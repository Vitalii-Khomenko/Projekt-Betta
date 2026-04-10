//! # betta-morpho - library crate
//!
//! Core types and inference logic for Betta-Morpho (Neuromorphic Adaptive Scanner).
//! Provides model loading, feature encoding, TTFS encoding, and SNN inference.
//!
//! ## Usage
//! ```bash
//! cargo build --release                        # replay / classifier only
//! cargo build --release --features raw-scan   # full scanner (Npcap required)
//! ```
//!
//! Author : Vitalii Khomenko <khomenko.vitalii@pm.me>
//! License : Apache-2.0 - see LICENSE
//! Version : 2.3.3
//! Created : 01.04.2026

#[cfg(feature = "raw-scan")]
pub mod scanner;
pub mod snn_core;

use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct EventRow {
    pub timestamp_us: u64,
    #[serde(default)]
    pub asset_ip: String,
    #[serde(default)]
    pub target_port: u16,
    pub protocol_flag: String,
    pub inter_packet_time_us: f32,
    pub payload_size: f32,
    pub rtt_us: f32,
    pub label: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RangeSpec {
    pub min: f32,
    pub max: f32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LayerSpec {
    pub weight: Vec<Vec<f32>>,
    pub bias: Vec<f32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ModelArtifact {
    pub trainer: Option<String>,
    pub steps: usize,
    pub beta: f32,
    pub threshold: f32,
    pub class_names: Vec<String>,
    pub prototypes: Option<std::collections::BTreeMap<String, Vec<f32>>>,
    pub feature_ranges: std::collections::BTreeMap<String, RangeSpec>,
    pub input_layer: LayerSpec,
    pub output_layer: LayerSpec,
}

pub fn load_model(path: &Path) -> Result<ModelArtifact> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read model: {}", path.display()))?;
    let artifact = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse model: {}", path.display()))?;
    Ok(artifact)
}

pub fn load_rows(path: &Path) -> Result<Vec<EventRow>> {
    let mut reader = csv::Reader::from_path(path)
        .with_context(|| format!("failed to open csv: {}", path.display()))?;
    let mut rows = Vec::new();
    for record in reader.deserialize() {
        let row: EventRow =
            record.with_context(|| format!("failed to deserialize row in {}", path.display()))?;
        rows.push(row);
    }
    Ok(rows)
}

fn normalize(value: f32, range: &RangeSpec) -> f32 {
    let span = (range.max - range.min).max(1.0);
    ((value - range.min) / span).clamp(0.0, 1.0)
}

pub fn encode_features(model: &ModelArtifact, row: &EventRow) -> Vec<f32> {
    let flag = row.protocol_flag.trim().to_ascii_uppercase();
    let syn_ack = if flag == "SYN_ACK" { 1.0 } else { 0.0 };
    let rst = if flag == "RST" { 1.0 } else { 0.0 };
    let timeout = if flag == "TIMEOUT" { 1.0 } else { 0.0 };
    let udp_response = if flag == "UDP_RESPONSE" { 1.0 } else { 0.0 };
    let icmp_unreachable = if flag == "ICMP_UNREACHABLE" { 1.0 } else { 0.0 };
    let icmp_reply = if flag == "ICMP_REPLY" { 1.0 } else { 0.0 };

    let inter_packet = 1.0
        - normalize(
            row.inter_packet_time_us,
            model
                .feature_ranges
                .get("inter_packet_time_us")
                .expect("missing inter_packet_time_us range"),
        );
    let payload = normalize(
        row.payload_size,
        model
            .feature_ranges
            .get("payload_size")
            .expect("missing payload_size range"),
    );
    let rtt = 1.0
        - normalize(
            row.rtt_us,
            model
                .feature_ranges
                .get("rtt_us")
                .expect("missing rtt_us range"),
        );
    vec![
        syn_ack,
        rst,
        timeout,
        udp_response,
        icmp_unreachable,
        icmp_reply,
        inter_packet,
        payload,
        rtt,
    ]
}

pub fn ttfs_encode(features: &[f32], steps: usize) -> Vec<Vec<f32>> {
    let mut spikes = vec![vec![0.0; features.len()]; steps];
    for (feature_index, value) in features.iter().enumerate() {
        if *value <= 0.0 {
            continue;
        }
        let spike_step = (((1.0 - *value) * (steps.saturating_sub(1) as f32)).round() as usize)
            .min(steps.saturating_sub(1));
        spikes[spike_step][feature_index] = 1.0;
    }
    spikes
}

fn linear(input: &[f32], layer: &LayerSpec) -> Vec<f32> {
    layer
        .weight
        .iter()
        .zip(layer.bias.iter())
        .map(|(weights, bias)| {
            let dot = weights
                .iter()
                .zip(input.iter())
                .fold(0.0_f32, |acc, (weight, value)| acc + weight * value);
            dot + bias
        })
        .collect()
}

fn spike(values: &[f32], threshold: f32) -> Vec<f32> {
    values
        .iter()
        .map(|value| if *value > threshold { 1.0 } else { 0.0 })
        .collect()
}

pub fn infer(model: &ModelArtifact, row: &EventRow) -> (usize, Vec<f32>) {
    let features = encode_features(model, row);

    if model.trainer.as_deref() == Some("prototype") {
        if let Some(prototypes) = &model.prototypes {
            let logits: Vec<f32> = model
                .class_names
                .iter()
                .map(|class_name| {
                    let prototype = prototypes
                        .get(class_name)
                        .expect("missing prototype for class");
                    -features
                        .iter()
                        .zip(prototype.iter())
                        .fold(0.0_f32, |acc, (value, center)| {
                            acc + (value - center).powi(2)
                        })
                })
                .collect();
            let predicted = logits
                .iter()
                .enumerate()
                .max_by(|left, right| left.1.partial_cmp(right.1).unwrap())
                .map(|(index, _)| index)
                .unwrap_or(0);
            return (predicted, logits);
        }
    }

    let spikes = ttfs_encode(&features, model.steps);
    let hidden_dim = model.input_layer.bias.len();
    let output_dim = model.output_layer.bias.len();
    let mut hidden_membrane = vec![0.0_f32; hidden_dim];
    let mut output_membrane = vec![0.0_f32; output_dim];
    let mut output_spike_count = vec![0.0_f32; output_dim];

    for step_input in spikes {
        let input_current = linear(&step_input, &model.input_layer);
        for index in 0..hidden_dim {
            hidden_membrane[index] = hidden_membrane[index] * model.beta + input_current[index];
        }
        let hidden_spikes = spike(&hidden_membrane, model.threshold);
        for index in 0..hidden_dim {
            hidden_membrane[index] *= 1.0 - hidden_spikes[index];
        }

        let output_current = linear(&hidden_spikes, &model.output_layer);
        for index in 0..output_dim {
            output_membrane[index] = output_membrane[index] * model.beta + output_current[index];
        }
        let output_spikes = spike(&output_membrane, model.threshold);
        for index in 0..output_dim {
            output_membrane[index] *= 1.0 - output_spikes[index];
            output_spike_count[index] += output_spikes[index];
        }
    }

    let logits: Vec<f32> = output_spike_count
        .iter()
        .zip(output_membrane.iter())
        .map(|(spike_count, membrane)| spike_count + 0.01 * membrane)
        .collect();

    let predicted = logits
        .iter()
        .enumerate()
        .max_by(|left, right| left.1.partial_cmp(right.1).unwrap())
        .map(|(index, _)| index)
        .unwrap_or(0);
    (predicted, logits)
}
