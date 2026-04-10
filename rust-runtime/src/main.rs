//! # betta-morpho - Neuromorphic Adaptive Scanner
//!
//! Primary Rust runtime. Engineering_Draft Section 3: Rust is the primary language
//! for systems & inference.
//!
//! ## Subcommands
//! ```bash
//! betta-morpho scan   --target <IP/CIDR> --ports top100 --interface tun0
//! betta-morpho replay --model artifact.json --data telemetry.csv
//! ```
//!
//! ## Build variants
//! ```bash
//! cargo build --release                        # replay/classifier only
//! cargo build --release --features raw-scan   # full scanner (needs Npcap)
//! ```
//!
//! Author : Vitalii Khomenko <khomenko.vitalii@pm.me>
//! License : Apache-2.0 - see LICENSE
//! Version : 2.3.3
//! Created : 01.04.2026

use anyhow::Result;
#[cfg(not(feature = "raw-scan"))]
use betta_morpho::{infer, load_model, load_rows};
#[cfg(feature = "raw-scan")]
use betta_morpho::{infer, load_model, load_rows, snn_core::BettaMorphoSnn};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[cfg(feature = "raw-scan")]
use betta_morpho::{scanner, snn_core::BettaMorphoArtifact};
#[cfg(feature = "raw-scan")]
use std::sync::Arc;

#[derive(Debug, Parser)]
#[command(
    name = "betta-morpho",
    about = "Betta-Morpho - Neuromorphic Adaptive Scanner"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// SNN-driven stateless SYN scan.
    ///
    /// Requires: --features raw-scan + Npcap (Windows) or root (Linux).
    /// Build: cargo build --release --features raw-scan
    Scan {
        #[arg(long)]
        target: String,
        #[arg(long, default_value = "top100")]
        ports: String,
        #[arg(long, default_value = "normal")]
        profile: String,
        #[arg(long)]
        artifact: Option<PathBuf>,
        #[arg(long, default_value = "tun0")]
        interface: String,
        #[arg(long)]
        src_ip: Option<String>,
        #[arg(long, default_value_t = 30)]
        secs: u64,
        #[arg(long)]
        save_weights: Option<PathBuf>,
    },

    /// Classifier inference replay on telemetry CSV.
    Replay {
        #[arg(long)]
        model: PathBuf,
        #[arg(long)]
        data: PathBuf,
        #[arg(long, default_value_t = 10)]
        preview: usize,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Command::Scan {
            target,
            ports,
            profile,
            artifact,
            interface,
            src_ip,
            secs,
            save_weights,
        } => {
            #[cfg(not(feature = "raw-scan"))]
            {
                let _ = (
                    target,
                    ports,
                    profile,
                    artifact,
                    interface,
                    src_ip,
                    secs,
                    save_weights,
                );
                eprintln!("[Betta-morpho] raw scanner is not compiled in.");
                eprintln!("Install Npcap, then rebuild:");
                eprintln!("  cargo build --release --features raw-scan");
                eprintln!();
                eprintln!("Without Npcap, use the Python fallback:");
                eprintln!("  python launcher.py scan --target <IP> --ports top100");
                std::process::exit(1);
            }

            #[cfg(feature = "raw-scan")]
            {
                let snn = if let Some(path) = &artifact {
                    let raw = std::fs::read_to_string(path)?;
                    let art: BettaMorphoArtifact = serde_json::from_str(&raw)?;
                    println!("[Betta-morpho] loaded artifact: {}", path.display());
                    BettaMorphoSnn::from_artifact(&art)
                } else {
                    let (decay_shift, base_ipg_us, base_par) = profile_params(&profile);
                    println!("[Betta-morpho] default weights  profile={profile}  decay_shift={decay_shift}");
                    BettaMorphoSnn::new_default(decay_shift, 16, base_ipg_us, base_par)
                };
                let snn = Arc::new(tokio::sync::Mutex::new(snn));

                let src = src_ip
                    .as_deref()
                    .unwrap_or("10.10.14.1")
                    .parse()
                    .unwrap_or(std::net::Ipv4Addr::new(10, 10, 14, 1));

                let cfg = scanner::ScanConfig {
                    src_ip: src,
                    interface: interface.clone(),
                    scan_secs: secs,
                    ..Default::default()
                };

                let targets = scanner::parse_targets(&target);
                let port_list = scanner::parse_ports(&ports);
                println!(
                    "[Betta-morpho] targets={} ports={} iface={} profile={}",
                    targets.len(),
                    port_list.len(),
                    interface,
                    profile
                );

                let results = scanner::run_scan(targets, port_list, cfg, Arc::clone(&snn)).await;
                println!("\n[Betta-morpho] {} open port(s):", results.len());
                for r in &results {
                    println!("  {}:{}  rtt={}us", r.ip, r.port, r.rtt_us);
                }
                println!("\n{}", serde_json::to_string_pretty(&results)?);

                if let Some(out) = save_weights {
                    let snap = snn.lock().await.to_snapshot();
                    std::fs::write(&out, serde_json::to_string_pretty(&snap)?)?;
                    println!("[Betta-morpho] saved adapted weights: {}", out.display());
                }
            }
        }

        Command::Replay {
            model,
            data,
            preview,
        } => {
            let model = load_model(&model)?;
            let rows = load_rows(&data)?;
            let mut correct = 0_usize;
            let mut labeled = 0_usize;

            for (i, row) in rows.iter().enumerate() {
                let (pred_idx, logits) = infer(&model, row);
                let pred_label = &model.class_names[pred_idx];
                if i < preview {
                    println!(
                        "row={i}  ts={}  flag={}  pred={}  logits={:?}",
                        row.timestamp_us, row.protocol_flag, pred_label, logits
                    );
                }
                if let Some(label) = &row.label {
                    if !label.is_empty() {
                        labeled += 1;
                        if label.trim().eq_ignore_ascii_case(pred_label) {
                            correct += 1;
                        }
                    }
                }
            }

            if labeled > 0 {
                println!(
                    "samples={}  accuracy={:.3}",
                    labeled,
                    correct as f32 / labeled as f32
                );
            } else {
                println!("processed={}  (unlabeled)", rows.len());
            }
        }
    }
    Ok(())
}

#[cfg(feature = "raw-scan")]
fn profile_params(profile: &str) -> (u32, u64, usize) {
    match profile {
        "paranoid" => (0, 5_000_000, 1),
        "sneaky" => (1, 1_000_000, 1),
        "polite" => (2, 300_000, 2),
        "normal" => (3, 50_000, 8),
        "aggressive" => (4, 10_000, 50),
        _ => (3, 50_000, 8),
    }
}
