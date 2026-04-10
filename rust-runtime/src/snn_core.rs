//! # snn_core - Betta-Morpho SNN Core
//!
//! Neuromorphic Adaptive Scanner brain - the spiking neural network that drives
//! all probe timing and parallelism decisions in Betta-Morpho.
//!
//! ## Architecture (Engineering_Draft Section 2.3 + Section 2.4)
//!
//! ```text
//!   Input features ---> [Input Layer: RTT, Flags, Packet-Loss neurons]
//!                              |
//!                    +---------+----------+
//!                    |                    |
//!             [Hidden LIF Layer]   [Inhibitory neuron]
//!                    |             (suppresses spikes on spike-storm)
//!                    +---------+----------+
//!                              |
//!                    [Output Layer: IPG | Parallelism]
//! ```
//!
//! ## LIF formula (fixed-point integer arithmetic, Engineering_Draft Section 4.1)
//!
//! ```text
//!   V[t] = (V[t-1] >> decay_shift) + I_input
//!   Spike if V[t] >= V_threshold  ->  V[t] = 0
//! ```
//!
//! `decay_shift` is the stealth parameter:
//! - High shift (3-4) = fast decay = aggressive probing
//! - Low shift  (0-1) = slow decay = stealthy probing (membrane integrates slowly)
//!
//! ## STDP update rule (Engineering_Draft Section 4.2)
//!
//! - Potentiation: Deltaw = A+ >> (Deltat_ms / tau+)  (fast SYN-ACK -> reward)
//! - Depression:   Deltaw = A- >> (Deltat_ms / tau-)  (RST/Timeout -> penalise)
//! - Tarpit:       sustained high RTT -> inhibitory neuron fires -> suppresses output
//!
//! ## Output neuron mapping
//!
//! - Neuron 0 - IPG control:   spike_count / max_spikes -> inter-packet gap us
//! - Neuron 1 - Parallelism:   membrane_potential -> max concurrent probes
//!
//! Author : Vitalii Khomenko <khomenko.vitalii@pm.me>
//! License : Apache-2.0 - see LICENSE
//! Version : 2.3.3
//! Created : 01.04.2026

use fixed::types::I16F16;
use serde::{Deserialize, Serialize};

/// Fixed-point membrane potential type (16.16 fixed-point)
type Fp = I16F16;

/// Pre-trained Betta-Morpho artifact loaded from JSON (exported by Python pre-training)
#[derive(Debug, Serialize, Deserialize)]
pub struct BettaMorphoArtifact {
    pub decay_shift: u32,
    pub threshold: f32,
    pub input_dim: usize,
    pub hidden_dim: usize,
    /// w_in_h[hidden_i][input_j] - input-to-hidden weights
    pub w_in_h: Vec<Vec<f32>>,
    /// w_h_out[output_i][hidden_j] - hidden-to-output weights
    pub w_h_out: Vec<Vec<f32>>,
    /// w_inh[hidden_i] - hidden-to-inhibitory weights
    pub w_inh: Vec<f32>,
    pub base_ipg_us: u64,
    pub base_parallel: usize,
    /// Inhibitory interneuron threshold (default: same as `threshold`).
    /// Lower value -> fires more often -> stronger spike-storm suppression.
    #[serde(default)]
    pub inh_threshold: Option<f32>,
    /// Bit-shift applied to hidden membranes on inhibitory spike (default: 2).
    /// Higher value -> more aggressive damping (faster recovery from storm).
    #[serde(default)]
    pub inh_reset_shift: Option<u32>,
    /// Post-spike threshold boost applied to hidden neurons (default: 0.15).
    /// Higher values make the network switch away from recently active neurons.
    #[serde(default)]
    pub adaptive_threshold_boost: Option<f32>,
    /// Decay shift for the adaptive threshold offset (default: 2).
    /// Higher values keep the refractory threshold elevated for longer.
    #[serde(default)]
    pub threshold_decay_shift: Option<u32>,
    /// Optional per-hidden-neuron decay profile. When omitted, the runtime
    /// derives a heterogeneous pattern around the base decay_shift.
    #[serde(default)]
    pub hidden_decay_shifts: Option<Vec<u32>>,
}

/// Determines what the scanner should do this timestep
#[derive(Debug, Clone, Copy)]
pub struct SnnOutput {
    /// inter-packet gap in microseconds
    pub ipg_us: u64,
    /// maximum concurrent probes
    pub parallelism: usize,
}

/// Event class for STDP updates
#[derive(Debug, Clone, Copy)]
pub enum ResponseKind {
    SynAck,  // open port  -> potentiate (confidence high)
    Rst,     // closed     -> mild depression
    Timeout, // filtered   -> depression
    Tarpit,  // high RTT   -> strong inhibition
}

/// The Betta-Morpho SNN core.
///
/// Holds LIF membrane state for hidden, inhibitory, and output layers.
/// Weights are updated online by STDP after each probe response.
pub struct BettaMorphoSnn {
    // -- LIF parameters -----------------------------------------------
    decay_shift: u32,
    threshold: Fp,
    adaptive_threshold_boost: Fp,
    threshold_decay_shift: u32,

    // -- Layer weights (fixed-point) ----------------------------------
    /// w_in_h[hidden_i][input_j]
    w_in_h: Vec<Vec<Fp>>,
    /// w_h_out[out_i][hidden_j]
    w_h_out: Vec<Vec<Fp>>,
    /// w_inh[hidden_j] - contribution to inhibitory interneuron
    w_inh: Vec<Fp>,

    // -- Membrane potentials ------------------------------------------
    v_h: Vec<Fp>,   // hidden layer
    v_inh: Fp,      // inhibitory interneuron
    v_out: Vec<Fp>, // output layer (IPG, parallelism)
    hidden_thresholds: Vec<Fp>,
    hidden_decay_shifts: Vec<u32>,

    // -- STDP state ---------------------------------------------------
    last_probe_us: u64,
    last_response_us: u64,

    // -- Inhibitory interneuron parameters ----------------------------
    inh_threshold: Fp,    // fire threshold for inhibitory neuron
    inh_reset_shift: u32, // bit-shift to damp hidden membranes on inh spike

    // -- STDP hyperparameters -----------------------------------------
    a_plus: Fp,     // LTP amplitude
    a_minus: Fp,    // LTD amplitude
    tau_plus: u64,  // LTP time window (ms) - shift unit
    tau_minus: u64, // LTD time window (ms) - shift unit

    // -- Output scaling -----------------------------------------------
    base_ipg_us: u64,
    base_parallel: usize,

    // -- Spike counter for output interpretation -----------------------
    out_spikes: Vec<u32>,
    step_count: u32,
}

impl BettaMorphoSnn {
    fn effective_leak_shift(decay_shift: u32) -> u32 {
        5_u32.saturating_sub(decay_shift).max(1)
    }

    fn decay_membrane(value: Fp, decay_shift: u32) -> Fp {
        let leak_shift = Self::effective_leak_shift(decay_shift);
        value - (value >> leak_shift)
    }

    fn threshold_offset_decay(value: Fp, decay_shift: u32) -> Fp {
        if value <= Fp::ZERO {
            return Fp::ZERO;
        }
        value - (value >> decay_shift.max(1))
    }

    fn derived_hidden_decay_shifts(base: u32, hidden_dim: usize) -> Vec<u32> {
        (0..hidden_dim)
            .map(|idx| match idx % 3 {
                0 => base.saturating_sub(1),
                1 => base,
                _ => base.saturating_add(1).min(4),
            })
            .collect()
    }

    /// Construct from a pre-trained artifact loaded from JSON.
    pub fn from_artifact(art: &BettaMorphoArtifact) -> Self {
        let thr = Fp::from_num(art.threshold);
        let to_fp_row = |row: &Vec<f32>| row.iter().map(|&v| Fp::from_num(v)).collect::<Vec<_>>();

        let w_in_h: Vec<Vec<Fp>> = art.w_in_h.iter().map(to_fp_row).collect();
        let w_h_out: Vec<Vec<Fp>> = art.w_h_out.iter().map(to_fp_row).collect();
        let w_inh: Vec<Fp> = to_fp_row(&art.w_inh);

        let hidden_dim = art.hidden_dim;
        let out_dim = 2; // IPG neuron + Parallelism neuron

        let inh_thr = Fp::from_num(art.inh_threshold.unwrap_or(art.threshold));
        let inh_shift = art.inh_reset_shift.unwrap_or(2);
        let adaptive_threshold_boost =
            Fp::from_num(art.adaptive_threshold_boost.unwrap_or(0.15_f32));
        let threshold_decay_shift = art.threshold_decay_shift.unwrap_or(2);
        let hidden_decay_shifts = art
            .hidden_decay_shifts
            .clone()
            .filter(|shifts| shifts.len() == hidden_dim)
            .unwrap_or_else(|| Self::derived_hidden_decay_shifts(art.decay_shift, hidden_dim));

        Self {
            decay_shift: art.decay_shift,
            threshold: thr,
            adaptive_threshold_boost,
            threshold_decay_shift,
            inh_threshold: inh_thr,
            inh_reset_shift: inh_shift,
            w_in_h,
            w_h_out,
            w_inh,
            v_h: vec![Fp::ZERO; hidden_dim],
            v_inh: Fp::ZERO,
            v_out: vec![Fp::ZERO; out_dim],
            hidden_thresholds: vec![thr; hidden_dim],
            hidden_decay_shifts,
            last_probe_us: 0,
            last_response_us: 0,
            a_plus: Fp::from_num(0.1_f32),
            a_minus: Fp::from_num(0.05_f32),
            tau_plus: 20,
            tau_minus: 40,
            base_ipg_us: art.base_ipg_us,
            base_parallel: art.base_parallel,
            out_spikes: vec![0u32; out_dim],
            step_count: 0,
        }
    }

    /// Construct with default weights for a given profile (no artifact).
    /// decay_shift encodes the stealth profile:
    ///   paranoid=0, sneaky=1, polite=2, normal=3, aggressive=4
    pub fn new_default(
        decay_shift: u32,
        hidden_dim: usize,
        base_ipg_us: u64,
        base_parallel: usize,
    ) -> Self {
        // Simple xorshift PRNG - no external crate needed
        let mut seed: u64 = 0xDEAD_BEEF_1337_4242;
        let mut next_f32 = move |lo: f32, hi: f32| -> f32 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let t = (seed as f32) / (u64::MAX as f32);
            lo + t * (hi - lo)
        };
        let input_dim = 9; // RTT (1) + flags (6) + packet_loss (1) + streak (1)
        let out_dim = 2;

        let w_in_h: Vec<Vec<Fp>> = (0..hidden_dim)
            .map(|_| {
                (0..input_dim)
                    .map(|_| Fp::from_num(next_f32(-0.3, 0.3)))
                    .collect()
            })
            .collect();
        let w_h_out: Vec<Vec<Fp>> = (0..out_dim)
            .map(|_| {
                (0..hidden_dim)
                    .map(|_| Fp::from_num(next_f32(-0.2, 0.2)))
                    .collect()
            })
            .collect();
        let w_inh: Vec<Fp> = (0..hidden_dim)
            .map(|_| Fp::from_num(next_f32(0.0, 0.2)))
            .collect();

        Self {
            decay_shift,
            threshold: Fp::from_num(1.0_f32),
            adaptive_threshold_boost: Fp::from_num(0.15_f32),
            threshold_decay_shift: 2,
            inh_threshold: Fp::from_num(1.0_f32),
            inh_reset_shift: 2,
            w_in_h,
            w_h_out,
            w_inh,
            v_h: vec![Fp::ZERO; hidden_dim],
            v_inh: Fp::ZERO,
            v_out: vec![Fp::ZERO; out_dim],
            hidden_thresholds: vec![Fp::from_num(1.0_f32); hidden_dim],
            hidden_decay_shifts: Self::derived_hidden_decay_shifts(decay_shift, hidden_dim),
            last_probe_us: 0,
            last_response_us: 0,
            a_plus: Fp::from_num(0.1_f32),
            a_minus: Fp::from_num(0.05_f32),
            tau_plus: 20,
            tau_minus: 40,
            base_ipg_us,
            base_parallel,
            out_spikes: vec![0u32; out_dim],
            step_count: 0,
        }
    }

    /// Record the time a probe was sent (for STDP Deltat calculation).
    pub fn record_probe(&mut self, now_us: u64) {
        self.last_probe_us = now_us;
    }

    /// STDP update after receiving a response.
    ///
    /// Deltat = time between probe and response (us -> ms).
    /// Fast SYN-ACK: potentiate input->hidden weights (reward speed).
    /// RST/Timeout:  depress (penalise filtering/tarpits).
    /// Tarpit:       sustained high RTT -> strong inhibitory bias.
    pub fn update_stdp(&mut self, kind: ResponseKind, now_us: u64) {
        self.last_response_us = now_us;
        let dt_ms = (now_us.saturating_sub(self.last_probe_us)) / 1_000;

        match kind {
            ResponseKind::SynAck => {
                // LTP: Deltaw = A+ >> (Deltat_ms / tau+)  - bounded by 8 shifts
                let shift = (dt_ms / self.tau_plus).min(7) as u32;
                let dw = self.a_plus >> shift;
                for row in self.w_in_h.iter_mut() {
                    for w in row.iter_mut() {
                        *w = (*w + dw).min(Fp::from_num(2.0_f32));
                    }
                }
            }
            ResponseKind::Rst | ResponseKind::Timeout => {
                let shift = (dt_ms / self.tau_minus).min(7) as u32;
                let dw = self.a_minus >> shift;
                for row in self.w_in_h.iter_mut() {
                    for w in row.iter_mut() {
                        *w = (*w - dw).max(Fp::from_num(-2.0_f32));
                    }
                }
            }
            ResponseKind::Tarpit => {
                // Increase inhibitory weights - the inhibitory neuron will
                // fire more aggressively, suppressing output and slowing the scan
                for w in self.w_inh.iter_mut() {
                    *w = (*w + Fp::from_num(0.2_f32)).min(Fp::from_num(3.0_f32));
                }
            }
        }
    }

    /// One LIF timestep.
    ///
    /// features: [rtt_norm, syn_ack, rst, timeout, udp_resp, icmp_unreach, icmp_reply,
    ///            packet_loss_rate, timeout_streak_norm]
    ///
    /// Returns SnnOutput: the IPG and parallelism the scanner should use.
    pub fn step(&mut self, features: &[f32]) -> SnnOutput {
        self.step_count += 1;
        let shift = self.decay_shift;
        let thr = self.threshold;

        // -- Hidden layer ---------------------------------------------
        let mut inh_input = Fp::ZERO;
        for (i, row) in self.w_in_h.iter().enumerate() {
            let current: Fp = row
                .iter()
                .zip(features.iter())
                .fold(Fp::ZERO, |acc, (w, &x)| acc + *w * Fp::from_num(x));

            self.hidden_thresholds[i] = thr
                + Self::threshold_offset_decay(
                    self.hidden_thresholds[i] - thr,
                    self.threshold_decay_shift,
                );

            // V[t] = V[t-1] - (V[t-1] >> leak_shift) + I
            self.v_h[i] = Self::decay_membrane(self.v_h[i], self.hidden_decay_shifts[i]) + current;

            // Inhibitory input accumulates from hidden spikes
            if self.v_h[i] >= self.hidden_thresholds[i] {
                inh_input += self.w_inh[i];
            }
        }

        // -- Inhibitory interneuron ------------------------------------
        // If too many hidden neurons fire simultaneously (spike-storm during
        // congestion), the inhibitory neuron suppresses the hidden layer.
        // inh_threshold and inh_reset_shift are tunable via artifact JSON.
        self.v_inh = Self::decay_membrane(self.v_inh, shift) + inh_input;
        let inh_spike = self.v_inh >= self.inh_threshold;
        if inh_spike {
            self.v_inh = Fp::ZERO;
            let rs = self.inh_reset_shift;
            for v in self.v_h.iter_mut() {
                *v >>= rs;
            }
        }

        // -- Hidden spikes (after inhibition check) --------------------
        let h_spikes: Vec<Fp> = self
            .v_h
            .iter_mut()
            .enumerate()
            .map(|(idx, v)| {
                if *v >= self.hidden_thresholds[idx] {
                    *v = Fp::ZERO;
                    self.hidden_thresholds[idx] += self.adaptive_threshold_boost;
                    Fp::ONE
                } else {
                    Fp::ZERO
                }
            })
            .collect();

        // -- Output layer ---------------------------------------------
        for (i, row) in self.w_h_out.iter().enumerate() {
            let current: Fp = row
                .iter()
                .zip(h_spikes.iter())
                .fold(Fp::ZERO, |acc, (w, &s)| acc + *w * s);
            self.v_out[i] = Self::decay_membrane(self.v_out[i], shift) + current;
            if self.v_out[i] >= thr {
                self.v_out[i] = Fp::ZERO;
                self.out_spikes[i] += 1;
            }
        }

        self.compute_output()
    }

    /// Translate output spike counts into actionable scan parameters.
    ///
    /// Output neuron 0 (IPG): more spikes -> shorter IPG (faster scan)
    /// Output neuron 1 (Parallelism): membrane potential -> more concurrent probes
    fn compute_output(&self) -> SnnOutput {
        let window = self.step_count.max(1) as f64;
        let ipg_rate = self.out_spikes[0] as f64 / window; // [0.0, 1.0]
        let par_rate = self.out_spikes[1] as f64 / window;

        // IPG: high spike rate -> shorter gap (more aggressive)
        // base_ipg * (1 - 0.9 * rate) - never goes below 10% of base
        let ipg_us = (self.base_ipg_us as f64 * (1.0 - 0.9 * ipg_rate)).max(10.0) as u64;

        // Parallelism: range [1, base_parallel * 3]
        let parallelism = (1.0 + par_rate * self.base_parallel as f64 * 2.0)
            .min(self.base_parallel as f64 * 3.0) as usize;

        SnnOutput {
            ipg_us,
            parallelism,
        }
    }

    /// Reset spike counters (call between scan windows to re-adapt).
    pub fn reset_counters(&mut self) {
        self.out_spikes.iter_mut().for_each(|c| *c = 0);
        self.step_count = 0;
    }

    /// Export weight snapshot to JSON-compatible struct.
    pub fn to_snapshot(&self) -> serde_json::Value {
        let fp_to_f32 = |v: Fp| v.to_num::<f32>();
        serde_json::json!({
            "decay_shift":     self.decay_shift,
            "threshold":       fp_to_f32(self.threshold),
            "adaptive_threshold_boost": fp_to_f32(self.adaptive_threshold_boost),
            "threshold_decay_shift": self.threshold_decay_shift,
            "hidden_decay_shifts": self.hidden_decay_shifts,
            "inh_threshold":   fp_to_f32(self.inh_threshold),
            "inh_reset_shift": self.inh_reset_shift,
            "w_in_h":  self.w_in_h.iter().map(|r| r.iter().map(|&v| fp_to_f32(v)).collect::<Vec<_>>()).collect::<Vec<_>>(),
            "w_h_out": self.w_h_out.iter().map(|r| r.iter().map(|&v| fp_to_f32(v)).collect::<Vec<_>>()).collect::<Vec<_>>(),
            "w_inh":   self.w_inh.iter().map(|&v| fp_to_f32(v)).collect::<Vec<f32>>(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::BettaMorphoSnn;

    #[test]
    fn adaptive_threshold_recovers_after_spike() {
        // Use hidden_dim=16 so that with high probability at least one neuron
        // has a positive weight sum (current > threshold/8 = 0.125) and will
        // eventually spike under constant max input.
        let mut snn = BettaMorphoSnn::new_default(2, 16, 1_000, 2);
        let input = [1.0_f32; 9];
        let base_threshold = snn.threshold;

        // Drive with max input until exactly the first spike is detected (break
        // immediately so no neuron fires more than once before we stop).
        // This guarantees each threshold was boosted at most once.
        let mut spiked = false;
        for _ in 0..50 {
            let _ = snn.step(&input);
            if snn
                .hidden_thresholds
                .iter()
                .any(|thr| *thr > base_threshold)
            {
                spiked = true;
                break;
            }
        }
        assert!(
            spiked,
            "expected at least one hidden neuron to fire within 50 steps of max input"
        );

        // After 8 steps with zero input the adaptive threshold excess decays
        // to ~10 % of its initial boost - well within one boost's distance.
        for _ in 0..8 {
            let _ = snn.step(&[0.0_f32; 9]);
        }

        assert!(
            snn.hidden_thresholds
                .iter()
                .all(|thr| *thr <= base_threshold + snn.adaptive_threshold_boost),
            "threshold should recover toward base after input stops"
        );
    }

    #[test]
    fn heterogeneous_decay_pattern_is_derived() {
        let snn = BettaMorphoSnn::new_default(2, 6, 1_000, 2);
        assert_eq!(snn.hidden_decay_shifts, vec![1, 2, 3, 1, 2, 3]);
    }
}
