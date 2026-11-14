# Wardline (`win-arm64`) — Verification & Build Report

This document records the exact observed build, lint, cross-compilation, PE binary verification, and Zig test results for **`wardline-arm64`** (`aarch64-pc-windows-gnullvm` + Zig `0.17.1`), together with the native `windows-11-arm` CI suite scope.

---

## 1. Cross-Compilation Build & Verification Results (Observed on Windows 11 x64 Host)

Executed against [`build.zig`](../build.zig), [`.cargo/config.toml`](../.cargo/config.toml), and [`tools/wl-arm64-{cc,link}.cmd`](../tools/wl-arm64-link.cmd):

| Verification Step | Command | Result | Observed Details |
| :--- | :--- | :---: | :--- |
| **Zig ARM64 Static Engine Build** | `zig build` | **Exited `0`** | Builds `wardline_engine_arm64` (`aarch64-windows-gnu`). |
| **Zig Common & ARM64 Engine Tests** | `zig build test` | **Exited `0`** | Executes `common-host-tests` (including `classifyPeBytes` AMD64/ARM64/ARM64EC checks) on x64 host and cross-compiles `win-arm64-tests` (`engine_arm64.zig` Prism default-deny & ACG tests) cleanly; on native ARM64 hosts, `build.zig` runs both `common-arm64-tests` and `win-arm64-tests` directly. |
| **Rust Workspace Clippy** | `cargo clippy --workspace --all-targets -- -D warnings` | **Exited `0`** | Zero errors across all 12 workspace crates targeting `aarch64-pc-windows-gnullvm`. |
| **ARM64 Release Build** | `cargo build --release --bins` | **Exited `0`** | Built all 4 optimized release executables via `wl-arm64-link.py` + `zig cc`. |

---

## 2. Emitted PE COFF Machine Verification (`0xAA64`)

Inspected bytes at `e_lfanew + 4` of every compiled executable in `target\aarch64-pc-windows-gnullvm\release\`:

| Binary | PE Machine Value | Architecture Constant | Status |
| :--- | :---: | :--- | :---: |
| `wardline.exe` | **`0xAA64`** | `IMAGE_FILE_MACHINE_ARM64` | Verified |
| `wardline-guard.exe` | **`0xAA64`** | `IMAGE_FILE_MACHINE_ARM64` | Verified |
| `wardline-mcp.exe` | **`0xAA64`** | `IMAGE_FILE_MACHINE_ARM64` | Verified |
| `wardline-verify.exe` | **`0xAA64`** | `IMAGE_FILE_MACHINE_ARM64` | Verified |

---

## 3. Native ARM64 Execution Scope (`windows-11-arm`)

Because compiled `0xAA64` Windows executables cannot execute directly on an `AMD64` (`0x8664`) CPU without an ARM64 kernel, runtime execution of `wardline-arm64`'s Rust tests and hardware probes is explicitly wired into the `win-arm64-native` job of [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) on `windows-11-arm`:

```powershell
zig build test
cargo test --workspace
.\target\aarch64-pc-windows-gnullvm\debug\wardline.exe doctor --json
.\target\aarch64-pc-windows-gnullvm\debug\wardline-verify.exe --help
```

> [!NOTE]
> When running `cargo test --workspace` natively on `windows-11-arm`, pass `--test-threads=1` if you want deterministic single-instance ordering around `pipe_server::tests::hardened_pipe_roundtrip_serves_health_and_policy_denial`.
