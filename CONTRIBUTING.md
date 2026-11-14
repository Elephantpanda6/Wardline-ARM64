# Contributing to Wardline (`win-arm64`)

Thank you for contributing to clean-room ARM64 agent sandboxing on Windows!

## Design & Coding Rules

1. **Preserve `#![forbid(unsafe_code)]`**: Keep `#![forbid(unsafe_code)]` intact across `wardline-core`, `wardline-policy`, `wardline-cert`, `wardline-approval`, `wardline-egress`, `wardline-mcp`, `wardline-verify`, `wardline-cli`, `wardline-vault/src/scrub.rs`, and `wardline-guard/src/{daemon,protocol}.rs`.
2. **Isolate Win32 & ISA Logic**: Keep ARM64 mitigation flags, Prism emulation checks (`evaluateArm64SpawnPolicy()`), and PAC/BTI probing inside `platforms/win-arm64/engine_arm64.zig` and `platforms/common/sandbox_core.zig`.
3. **Keep Cross-Compilation Zero-MinGW**: Changes affecting linker flags or sysroot behavior must continue linking cleanly through `tools/wl-arm64-cc.cmd` and `tools/wl-arm64-link.cmd`.

## Pre-PR Verification Checklist

On any Windows host (native ARM64 or x64 cross-compile):
```powershell
zig build
zig build test
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo build --release --bins
```

On native Windows on ARM64 hardware:
```powershell
cargo test --workspace -- --test-threads=1
```

## Licensing

Dual-licensed under **MIT OR Apache-2.0** ([LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE)).
