//! Shared configuration for demo fuzz binaries via environment variables.

/// Probability of taking the vulnerable input path is `1 / DEMO_VULN_ROLL_DENOM` (default `10` → ~10%).
pub const ENV_VULN_ROLL_DENOM: &str = "DEMO_VULN_ROLL_DENOM";

/// Overrides Trident `fuzz(iterations, _)` when set (non-empty).
pub const ENV_FUZZ_ITERATIONS: &str = "DEMO_FUZZ_ITERATIONS";

/// Overrides Trident `fuzz(_, flow_calls_per_iteration)` when set (non-empty).
pub const ENV_FUZZ_FLOW_CALLS: &str = "DEMO_FUZZ_FLOW_CALLS";

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
