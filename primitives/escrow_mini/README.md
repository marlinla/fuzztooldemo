# Escrow Mini Scaffold

Purpose: first extension primitive for the case study.

Status: scaffold only. Not yet integrated into `Cargo.toml` or Trident manifest.

## Files

- `program_lib.rs` - Anchor-style program skeleton with one intentionally vulnerable endpoint.
- `fuzz_escrow_mini.rs` - Trident flow skeleton with trace and finding hooks.

## Next Integration Steps

1. Move `program_lib.rs` into a new Anchor program crate under `programs/`.
2. Add program artifact mapping in `trident-tests/Trident.toml`.
3. Add `fuzz_escrow_mini` binary to `trident-tests`.
4. Fill `EVALUATION.md` extension row with real commands and artifacts.
