# Changelog

All notable changes to **Wardline (Multi-OS ARM64)** are documented in this file.

## [0.2.0] — Multi-OS & Phase 2 Architecture Release (`win-arm64`, `linux-arm64`, `macos-arm64`, `freebsd-arm64`)

### Architecture & Workspace Restructuring
- Expanded the workspace to **14 Rust crates** plus the standalone **`wardline-client`** SDK crate:
  - **12 `#![forbid(unsafe_code)]` Rust crates**: `wardline-core`, `wardline-policy`, `wardline-secrets`, `wardline-audit`, `wardline-fs`, `wardline-egress`, `wardline-auth`, `wardline-sandbox`, `wardline-attest`, `wardline-mcp`, `wardline-cli`, and `wardline-guest-agent`.
  - **`wardline-platform`**: Quarantined OS FFI boundary (including Windows ARM64 DPAPI & ACL helpers, POSIX credential/filesystem checks, and emulation detection).
  - **`wardline-sandbox`**: Unified Zig `C-ABI v2` FFI shim dispatching cleanly across `aarch64` OS sandbox engines.
- Introduced **`assets/architecture-arm64.svg`** and **`assets/architecture-arm64.png`** (`3600x2400`) along with multi-OS documentation across `README.md` and `docs/*.md`.

### Multi-OS `aarch64` Zig `C-ABI v2` Engines & Isolation Tiers (`L0`–`L2`)
- **Windows on ARM64 (`win-arm64`)**: Native `0xAA64` binary gate, Prism cross-ABI emulation firewall, `AppContainer`, restricted Job Objects, DPAPI sealing, and `-OReleaseFast` + `ntdll` MSVC static linkage (`windows-11-arm`).
- **Linux ARM64 (`linux-arm64`)**: Unprivileged user namespaces with Ubuntu 24.04 AppArmor detection (`probeUsernsEnabled()`), Landlock LSM, 22-syscall / socket-family `seccomp-bpf` policy, QEMU user-mode emulation rejection, and `PAC`/`BTI`/`MTE` readiness.
- **macOS Apple Silicon (`macos-arm64`)**: Seatbelt (`sandbox-exec`) profile builder with `/private` symlink alias emission, Rosetta 2 cross-ABI rejection, and POSIX `rusage` peak memory accounting.
- **FreeBSD ARM64 (`freebsd-arm64`)**: `Capsicum` capability mode, `procdesc`, and `rctl` resource limits.
- **Fail-Closed Isolation Tiers**: Added `L0` (Direct Process Broker), `L1` (OS Kernel Sandbox via Zig `C-ABI v2`), `L1.5` (`gVisor`), and `L2` (MicroVM via `Firecracker` / `HCS` / `VZ` paired with `wardline-guest-agent`).

### Security, Policy, Egress & Audit Enhancements
- **Operator Governance**: Added `[operator_forbid]` non-overridable ceiling rules and two-phase `[session]` (`Setup -> Run`) execution lifecycles.
- **Deep Command Shielding**: Added 8-depth `argv_shield` wrapper and interpreter inspection to block chained shell/interpreter bypasses.
- **Delegation & Revocation**: Implemented `WardCert` hierarchical Ed25519 capability tokens (`MAX_CHAIN_DEPTH = 8`) with cascading subtree CRL revocation.
- **Host-Sealed Vault**: Added `--value-file` secret ingestion and live `rotate_master_key()` re-encryption across host-sealed stores.
- **Persistent Egress Accounting**: Added `redb`-backed egress `BudgetStore` tracking alongside pinned anti-SSRF DNS resolution.
- **Cryptographic Attestation**: Added `WLG1` `BLAKE3` Merkle inclusion proofs, signed Ed25519 checkpoints, and `.tainted` panic freeze protection.
- **MCP Broker & Auto-Learning**: Added `wardline-mcp` `serve`, `wrap`, `servers`, and `--learn` policy synthesis.
- **Verification & SDKs**: Expanded to **4 SDKs** (`Rust`, `Python`, `TypeScript`, `Go`), **7 formal security invariants (`I1`–`I7`)**, and **7 `cargo-fuzz` targets**, verified by multi-OS CI across Linux ARM64, macOS Apple Silicon, and Windows 11 ARM64.

## [0.1.0] — Initial Clean-Room Release (`win-arm64`)

### Added
- Clean-room 12-crate Rust control plane with `#![forbid(unsafe_code)]` across workspace logic crates.
- Native Zig `C-ABI v1` sandbox engine (`engine_arm64`) enforcing PE `0xAA64` native ARM64 checks, Prism emulation rejection, Job Objects, and `AppContainer` tokens.
- Host-sealed DPAPI vault (`wardline vault`), brokered NTFS access (`wardline fs`), DNS-pinned anti-SSRF HTTP proxy (`wardline egress`), Ed25519 capability tokens (`wardline-auth`), and hash-chained `BLAKE3` + Ed25519 audit logs (`wardline audit`).
- Python and TypeScript zero-dependency SDKs.
