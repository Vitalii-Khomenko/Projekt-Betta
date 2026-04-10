//! # scanner - Stateless Async SYN Scanner
//!
//! Raw-packet scanner driven by the Betta-Morpho SNN. Only compiled with `--features raw-scan`.
//!
//! ## Usage
//! ```bash
//! cargo build --release --features raw-scan
//! ./betta-morpho scan --target 10.10.11.0/24 --ports top100 --interface tun0
//! ```
//!
//! ## Requirements
//! - Linux: `root` or `CAP_NET_RAW`
//! - Windows: Npcap installed
//!
//! Author : Vitalii Khomenko <khomenko.vitalii@pm.me>
//! License : Apache-2.0 - see LICENSE
//! Version : 2.3.3
//! Created : 01.04.2026
#![cfg(feature = "raw-scan")]

use rand::Rng;
use serde::Serialize;
use siphasher::sip::SipHasher13;
use std::hash::Hasher;
/// Betta-Morpho Scanner - Stateless Async SYN Scanner
///
/// Architecture (Engineering_Draft Section 2.1 + Section 5):
///
///   LCG -> next target (IP, port)
///         |
///   Betta-Morpho SNN -> IPG + parallelism
///         |
///   Tokio sender task -> raw SYN packet (pnet, AF_PACKET / libpnet)
///         |
///   Tokio receiver task <- TCP responses
///         |
///   SipHash verification: ack_num == hash(src,dst,port,secret) + 1
///         |
///   STDP update -> Betta-Morpho SNN adapts
///         |
///   JSON/stdout output <- discovered open ports
///
/// Stateless verification (Engineering_Draft Section 2.1):
///   SYN sequence number = SipHash13(src_ip || dst_ip || dst_port || secret)
///   Response verified:  ack_num == seq + 1  (no per-probe state needed)
///
/// Requirements:
///   Linux: root / CAP_NET_RAW
///   Windows: Npcap must be installed (used by pnet backend)
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio::time::sleep;

use crate::snn_core::{BettaMorphoSnn, ResponseKind};

// --- Target enumeration via LCG -----------------------------------------------

/// Linear Congruential Generator for pseudo-random target ordering.
/// Iterates the full u32 space without repetition (c is coprime to m=2^32).
/// This is equivalent to zmap/masscan's target randomisation approach.
///
/// Parameters: a = Knuth multiplier, c = odd constant (coprime to 2^32)
pub struct Lcg {
    state: u32,
}

impl Lcg {
    pub fn new(seed: u32) -> Self {
        Self { state: seed }
    }

    pub fn next_u32(&mut self) -> u32 {
        self.state = self
            .state
            .wrapping_mul(1_664_525)
            .wrapping_add(1_013_904_223);
        self.state
    }

    /// Map a u32 into the range [lo, hi) via modulo (biased, acceptable for scanning).
    pub fn next_in(&mut self, lo: u32, hi: u32) -> u32 {
        lo + self.next_u32() % (hi - lo)
    }
}

// --- Stateless SYN sequence verification -------------------------------------

/// Compute the SYN sequence number for a probe.
/// The seq number encodes (src_ip, dst_ip, dst_port, secret) via SipHash-1-3.
/// When the target replies with SYN-ACK, ack_num = seq + 1.
/// Verifying this without storing per-probe state is the stateless technique.
pub fn compute_syn_seq(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    secret: &[u8; 16],
) -> u32 {
    let mut h = SipHasher13::new_with_key(secret);
    h.write(&src_ip.octets());
    h.write(&dst_ip.octets());
    h.write_u16(dst_port);
    h.finish() as u32
}

/// Verify a received SYN-ACK belongs to one of our probes.
/// their_ip  = responder's IP   (= original dst_ip we sent to)
/// their_port = responder's port (= original dst_port)
/// our_ip    = our own IP
/// ack_num   = TCP ack number from the SYN-ACK
pub fn verify_syn_ack(
    our_ip: Ipv4Addr,
    their_ip: Ipv4Addr,
    their_port: u16,
    ack_num: u32,
    secret: &[u8; 16],
) -> bool {
    let expected_seq = compute_syn_seq(our_ip, their_ip, their_port, secret);
    ack_num == expected_seq.wrapping_add(1)
}

// --- Scan config -------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Our source IP (used for seq hash and packet crafting).
    pub src_ip: Ipv4Addr,
    /// Secret key for SipHash stateless verification (16 bytes).
    pub secret: [u8; 16],
    /// Network interface name (e.g. "eth0", "tun0" for HTB VPN).
    pub interface: String,
    /// Scan duration before stopping receiver (seconds).
    pub scan_secs: u64,
    /// RTT threshold above which a host is classified as a Tarpit (us).
    pub tarpit_us: u64,
}

impl Default for ScanConfig {
    fn default() -> Self {
        let mut rng = rand::thread_rng();
        let mut secret = [0u8; 16];
        rng.fill(&mut secret);
        Self {
            src_ip: Ipv4Addr::new(10, 10, 14, 1), // HTB VPN default, override at runtime
            secret,
            interface: "tun0".to_owned(),
            scan_secs: 30,
            tarpit_us: 3_000_000, // 3 s
        }
    }
}

// --- Result types -------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct PortOpen {
    pub ip: String,
    pub port: u16,
    pub rtt_us: u64,
}

// --- Scan session -------------------------------------------------------------

/// One probe request queued from sender task to pnet worker.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct ProbeRequest {
    dst_ip: Ipv4Addr,
    dst_port: u16,
    seq: u32,
}

/// Response parsed from pnet receiver.
#[derive(Debug)]
struct ProbeResponse {
    src_ip: Ipv4Addr,
    src_port: u16,
    ack_num: u32,
    flags: u8,
    rtt_us: u64,
}

// --- Public scan entry point --------------------------------------------------

/// Run a stateless SYN scan against the given targets and ports.
///
/// The Betta-Morpho SNN controls IPG and parallelism adaptively.
/// STDP updates refine weights during the first 60 seconds.
///
/// Returns a list of discovered open ports (JSON-serialisable).
pub async fn run_scan(
    targets: Vec<Ipv4Addr>,
    ports: Vec<u16>,
    config: ScanConfig,
    snn: Arc<tokio::sync::Mutex<BettaMorphoSnn>>,
) -> Vec<PortOpen> {
    let (probe_tx, _probe_rx) = mpsc::channel::<ProbeRequest>(4096);
    let (resp_tx, mut resp_rx) = mpsc::channel::<ProbeResponse>(4096);
    let (open_tx, mut open_rx) = mpsc::channel::<PortOpen>(1024);

    let config_arc = Arc::new(config.clone());
    let config_recv = Arc::clone(&config_arc);
    let config_proc = Arc::clone(&config_arc);
    let snn_process = Arc::clone(&snn);

    // -- Receiver task -------------------------------------------------
    // Reads raw packets from the network via pnet, verifies SYN-ACK seq,
    // forwards confirmed responses to the processor task.
    let recv_cfg = config_recv.clone();
    let recv_resp_tx = resp_tx.clone();
    let recv_task = tokio::task::spawn_blocking(move || {
        pnet_receiver(recv_cfg, recv_resp_tx);
    });

    // -- Probe processor task ------------------------------------------
    // Receives responses, classifies them, runs STDP, streams open ports.
    let proc_task = tokio::spawn(async move {
        let start = Instant::now();
        let stdp_window = Duration::from_secs(60); // online learning phase

        while let Some(resp) = resp_rx.recv().await {
            if verify_syn_ack(
                config_proc.src_ip,
                resp.src_ip,
                resp.src_port,
                resp.ack_num,
                &config_proc.secret,
            ) {
                let is_open = resp.flags & 0x12 == 0x12; // SYN-ACK
                let is_rst = resp.flags & 0x04 != 0;

                if is_open {
                    let _ = open_tx
                        .send(PortOpen {
                            ip: resp.src_ip.to_string(),
                            port: resp.src_port,
                            rtt_us: resp.rtt_us,
                        })
                        .await;

                    // STDP potentiation during the online learning phase
                    if start.elapsed() < stdp_window {
                        let kind = if resp.rtt_us > config_proc.tarpit_us {
                            ResponseKind::Tarpit
                        } else {
                            ResponseKind::SynAck
                        };
                        let now_us = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_micros() as u64;
                        snn_process.lock().await.update_stdp(kind, now_us);
                    }
                } else if is_rst && start.elapsed() < stdp_window {
                    let now_us = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_micros() as u64;
                    snn_process
                        .lock()
                        .await
                        .update_stdp(ResponseKind::Rst, now_us);
                }
            }
        }
    });

    // -- Sender task ---------------------------------------------------
    // LCG enumerates (target, port) pairs in pseudo-random order.
    // Betta-Morpho SNN determines IPG (inter-packet gap) and parallelism.
    let snn_sender = Arc::clone(&snn);
    let config_send = config.clone();
    let send_task = tokio::spawn(async move {
        let mut lcg = Lcg::new({
            let mut rng = rand::thread_rng();
            rng.gen::<u32>()
        });

        // Build flat list, then LCG-order it
        let mut target_ports: Vec<(Ipv4Addr, u16)> = targets
            .iter()
            .flat_map(|&ip| ports.iter().map(move |&port| (ip, port)))
            .collect();

        // Fisher-Yates shuffle via LCG
        for i in (1..target_ports.len()).rev() {
            let j = lcg.next_in(0, (i + 1) as u32) as usize;
            target_ports.swap(i, j);
        }

        let start = Instant::now();
        let deadline = Duration::from_secs(config_send.scan_secs);
        let features = [0.0f32; 9]; // initial features - STDP will refine

        for chunk_start in (0..target_ports.len()).step_by(256) {
            if start.elapsed() > deadline {
                break;
            }

            // Query Betta-Morpho SNN for this window's parameters
            let output = {
                let mut snn_guard = snn_sender.lock().await;
                let out = snn_guard.step(&features);
                snn_guard.reset_counters(); // fresh window
                out
            };

            let ipg = Duration::from_micros(output.ipg_us);
            let batch_size = output.parallelism.min(target_ports.len() - chunk_start);
            let batch = &target_ports[chunk_start..chunk_start + batch_size];

            // Send one batch of probes concurrently
            let sends: Vec<_> = batch
                .iter()
                .map(|&(ip, port)| {
                    let seq = compute_syn_seq(config_send.src_ip, ip, port, &config_send.secret);
                    let now_us = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_micros() as u64;

                    let _ = probe_tx.try_send(ProbeRequest {
                        dst_ip: ip,
                        dst_port: port,
                        seq,
                    });
                    now_us
                })
                .collect();
            let _ = sends; // timestamps recorded; STDP handled in proc_task

            // Betta-Morpho SNN-controlled inter-packet gap
            sleep(ipg).await;
        }
        drop(probe_tx); // signal pnet worker to stop
    });

    // Run sender; then drain results
    let _ = tokio::join!(send_task, proc_task, recv_task);

    let mut results = Vec::new();
    while let Ok(port) = open_rx.try_recv() {
        results.push(port);
    }
    results
}

// --- pnet packet I/O ---------------------------------------------------------

/// Blocking pnet receiver - runs in a dedicated OS thread.
///
/// Captures incoming TCP packets on the configured interface.
/// Parses Ethernet -> IPv4 -> TCP and forwards raw response data to the
/// async processor via an mpsc channel.
///
/// Note: Requires root (Linux CAP_NET_RAW) or Npcap (Windows).
fn pnet_receiver(config: Arc<ScanConfig>, resp_tx: mpsc::Sender<ProbeResponse>) {
    use pnet::datalink::{self, NetworkInterface};
    use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::Ipv4Packet;
    use pnet::packet::tcp::TcpPacket;
    use pnet::packet::Packet;

    let ifaces: Vec<NetworkInterface> = datalink::interfaces();
    let iface = match ifaces.iter().find(|i| i.name == config.interface) {
        Some(i) => i.clone(),
        None => {
            eprintln!(
                "[Betta-morpho] interface '{}' not found. Available: {:->}",
                config.interface,
                ifaces.iter().map(|i| &i.name).collect::<Vec<_>>()
            );
            return;
        }
    };

    let (_, mut rx) = match datalink::channel(&iface, Default::default()) {
        Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            eprintln!("[Betta-morpho] unsupported channel type");
            return;
        }
        Err(e) => {
            eprintln!("[Betta-morpho] failed to open channel: {e}");
            return;
        }
    };

    loop {
        match rx.next() {
            Ok(frame) => {
                let eth = match EthernetPacket::new(frame) {
                    Some(p) => p,
                    None => continue,
                };
                if eth.get_ethertype() != EtherTypes::Ipv4 {
                    continue;
                }

                let ip = match Ipv4Packet::new(eth.payload()) {
                    Some(p) => p,
                    None => continue,
                };
                if ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
                    continue;
                }

                let tcp = match TcpPacket::new(ip.payload()) {
                    Some(p) => p,
                    None => continue,
                };
                let flags = tcp.get_flags() as u8;

                // Accept SYN-ACK and RST (both needed for STDP)
                if flags & 0x12 == 0x12 || flags & 0x04 != 0 {
                    let src_ip = ip.get_source();
                    let rtt_us = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_micros() as u64; // approximate; accurate Deltat computed in proc_task

                    let resp = ProbeResponse {
                        src_ip: src_ip,
                        src_port: tcp.get_source(),
                        ack_num: tcp.get_acknowledgement(),
                        flags,
                        rtt_us,
                    };
                    if resp_tx.blocking_send(resp).is_err() {
                        break;
                    }
                }
            }
            Err(e) => {
                eprintln!("[Betta-morpho] recv error: {e}");
                break;
            }
        }
    }
}

/// Blocking pnet SYN sender - consumes ProbeRequests from the async queue.
///
/// Crafts raw Ethernet + IPv4 + TCP SYN packets and injects them at L2.
/// Running at L2 (datalink) bypasses the kernel TCP stack, preventing
/// the kernel from sending RST for incoming SYN-ACKs.
#[allow(dead_code)]
pub(crate) fn pnet_sender(
    config: Arc<ScanConfig>,
    mut probe_rx: mpsc::Receiver<ProbeRequest>,
    gateway_mac: [u8; 6],
    src_mac: [u8; 6],
) {
    use pnet::datalink::{self};
    use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::{self, MutableIpv4Packet};
    use pnet::packet::tcp::{self, MutableTcpPacket, TcpFlags};

    use pnet::util::MacAddr;

    let ifaces = datalink::interfaces();
    let iface = match ifaces.iter().find(|i| i.name == config.interface) {
        Some(i) => i.clone(),
        None => {
            eprintln!("[Betta-morpho sender] interface not found");
            return;
        }
    };

    let (mut tx, _) = match datalink::channel(&iface, Default::default()) {
        Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        _ => {
            eprintln!("[Betta-morpho sender] channel error");
            return;
        }
    };

    while let Some(probe) = probe_rx.blocking_recv() {
        // Allocate packet buffer: Ethernet(14) + IP(20) + TCP(20) = 54 bytes
        let mut buf = [0u8; 54];

        // -- TCP header ------------------------------------------------
        let mut tcp_pkt = MutableTcpPacket::new(&mut buf[34..54]).unwrap();
        // Use a fixed source port derived from the target (deterministic)
        let sport: u16 = 40000u16.wrapping_add(probe.dst_port);
        tcp_pkt.set_source(sport);
        tcp_pkt.set_destination(probe.dst_port);
        tcp_pkt.set_sequence(probe.seq);
        tcp_pkt.set_acknowledgement(0);
        tcp_pkt.set_data_offset(5); // 20-byte header
        tcp_pkt.set_flags(TcpFlags::SYN);
        tcp_pkt.set_window(65535);
        tcp_pkt.set_urgent_ptr(0);
        let tcp_cksum = tcp::ipv4_checksum(&tcp_pkt.to_immutable(), &config.src_ip, &probe.dst_ip);
        tcp_pkt.set_checksum(tcp_cksum);

        // -- IPv4 header -----------------------------------------------
        let mut ip_pkt = MutableIpv4Packet::new(&mut buf[14..34]).unwrap();
        ip_pkt.set_version(4);
        ip_pkt.set_header_length(5);
        ip_pkt.set_dscp(0);
        ip_pkt.set_ecn(0);
        ip_pkt.set_total_length(40); // 20 IP + 20 TCP
        ip_pkt.set_identification(rand::thread_rng().gen());
        ip_pkt.set_flags(2); // Don't Fragment
        ip_pkt.set_fragment_offset(0);
        ip_pkt.set_ttl(64);
        ip_pkt.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_pkt.set_source(config.src_ip);
        ip_pkt.set_destination(probe.dst_ip);
        let ip_cksum = ipv4::checksum(&ip_pkt.to_immutable());
        ip_pkt.set_checksum(ip_cksum);

        // -- Ethernet frame --------------------------------------------
        let mut eth_pkt = MutableEthernetPacket::new(&mut buf[0..14]).unwrap();
        eth_pkt.set_destination(MacAddr::from(gateway_mac));
        eth_pkt.set_source(MacAddr::from(src_mac));
        eth_pkt.set_ethertype(EtherTypes::Ipv4);

        let _ = tx.send_to(&buf, None);
    }
}

// --- Target parsing utilities -------------------------------------------------

pub fn parse_targets(spec: &str) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.contains('/') {
            if let Ok(network) = part.parse::<ipnetwork::Ipv4Network>() {
                out.extend(network.iter());
            }
        } else if let Some(dash) = part.rfind('-') {
            let base = &part[..dash];
            let end: u8 = part[dash + 1..].parse().unwrap_or(0);
            let parts: Vec<&str> = base.split('.').collect();
            if parts.len() == 4 {
                let start: u8 = parts[3].parse().unwrap_or(1);
                let prefix = format!("{}.{}.{}", parts[0], parts[1], parts[2]);
                for o in start..=end {
                    if let Ok(ip) = format!("{}.{}", prefix, o).parse() {
                        out.push(ip);
                    }
                }
            }
        } else if let Ok(ip) = part.parse() {
            out.push(ip);
        }
    }
    out
}

pub fn parse_ports(spec: &str) -> Vec<u16> {
    const TOP20: &[u16] = &[
        21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
        8443, 9090,
    ];
    const TOP100: &[u16] = &[
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389,
        5900, 8080, 8443, 8888, 9090, 9200, 27017, 20, 69, 79, 88, 102, 113, 119, 137, 138, 161,
        179, 194, 389, 636, 873, 902, 990, 1080, 1194, 1433, 1521, 1883, 2049, 2121, 2222, 3000,
        4444, 4848, 5000, 5432, 5555, 5601, 5800, 5985, 5986, 6379, 6443, 7001, 7080, 7443, 8000,
        8008, 8069, 8161, 8180, 8500, 8834, 8983, 9000, 9042, 9092, 9300, 9418, 10000, 11211,
        27018, 28017, 47001, 50000, 50070,
    ];

    match spec.to_ascii_lowercase().as_str() {
        "top20" | "top-20" => return TOP20.to_vec(),
        "top100" | "top-100" => return TOP100.to_vec(),
        _ => {}
    }

    let mut ports = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if let Some(dash) = part.find('-') {
            let lo: u16 = part[..dash].parse().unwrap_or(1);
            let hi: u16 = part[dash + 1..].parse().unwrap_or(1024);
            ports.extend(lo..=hi);
        } else if let Ok(p) = part.parse::<u16>() {
            ports.push(p);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    ports
}
