//! Shared configuration for demo fuzz binaries via environment variables.
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

/// Probability of taking the vulnerable input path is `1 / DEMO_VULN_ROLL_DENOM` (default `10` → ~10%).
pub const ENV_VULN_ROLL_DENOM: &str = "DEMO_VULN_ROLL_DENOM";

/// Overrides Trident `fuzz(iterations, _)` when set (non-empty).
pub const ENV_FUZZ_ITERATIONS: &str = "DEMO_FUZZ_ITERATIONS";

/// Overrides Trident `fuzz(_, flow_calls_per_iteration)` when set (non-empty).
pub const ENV_FUZZ_FLOW_CALLS: &str = "DEMO_FUZZ_FLOW_CALLS";

/// Fuzzing mode: "demo" keeps guided vulnerable-path sampling, "paper" minimizes guidance.
pub const ENV_FUZZ_MODE: &str = "DEMO_FUZZ_MODE";

/// Enables per-flow path tracing when set to `1`, `true`, or `yes`.
pub const ENV_TRACE_PATHS: &str = "DEMO_TRACE_PATHS";

/// Enables JSONL artifact output for findings.
pub const ENV_WRITE_FINDINGS_JSON: &str = "DEMO_WRITE_FINDINGS_JSON";

/// Output directory for finding JSONL files.
pub const FINDINGS_DIR: &str = "results";

/// Parse `key` as `u64`; empty or missing `key` returns `default`.
pub fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

/// Min 1. Roll `1..=vuln_roll_denom() == 1` → chance `1/n`.
pub fn vuln_roll_denom() -> u64 {
    env_u64(ENV_VULN_ROLL_DENOM, 10).max(1)
}

/// True when harnesses should inject guided vulnerable-path attempts for demos.
pub fn guided_demo_mode() -> bool {
    std::env::var(ENV_FUZZ_MODE)
        .ok()
        .map(|s| s.to_ascii_lowercase() != "paper")
        .unwrap_or(true)
}

fn env_bool(key: &str, default: bool) -> bool {
    std::env::var(key)
        .ok()
        .map(|s| {
            let v = s.to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes" || v == "on"
        })
        .unwrap_or(default)
}

pub fn trace_paths_enabled() -> bool {
    env_bool(ENV_TRACE_PATHS, false)
}

pub fn write_findings_enabled() -> bool {
    env_bool(ENV_WRITE_FINDINGS_JSON, true)
}

fn fmt_fields(fields: &[(&str, String)]) -> String {
    fields
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn json_escape(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn now_epoch_ms() -> u128 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_millis(),
        Err(_) => 0,
    }
}

pub fn trace_path(target: &str, fields: &[(&str, String)]) {
    if trace_paths_enabled() {
        eprintln!("[TRACE][{target}] {}", fmt_fields(fields));
    }
}

pub fn record_finding(target: &str, finding: &str, fields: &[(&str, String)]) {
    if !write_findings_enabled() {
        return;
    }
    if create_dir_all(FINDINGS_DIR).is_err() {
        return;
    }
    let path = format!("{FINDINGS_DIR}/{target}.jsonl");
    let mut file = match OpenOptions::new().create(true).append(true).open(path) {
        Ok(f) => f,
        Err(_) => return,
    };
    let mode = if guided_demo_mode() { "demo" } else { "paper" };
    let fields_json = fields
        .iter()
        .map(|(k, v)| format!("\"{}\":\"{}\"", json_escape(k), json_escape(v)))
        .collect::<Vec<_>>()
        .join(",");
    let line = format!(
        "{{\"ts_ms\":{},\"target\":\"{}\",\"mode\":\"{}\",\"finding\":\"{}\",\"fields\":{{{}}}}}\n",
        now_epoch_ms(),
        json_escape(target),
        mode,
        json_escape(finding),
        fields_json
    );
    let _ = file.write_all(line.as_bytes());
}
