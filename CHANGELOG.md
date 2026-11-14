# Changelog (`wardline-arm64`)

## `[0.1.0]` — Initial Clean-Room Release (`win-arm64`)

### Added
- **12-Crate Rust Control Plane** targeting `aarch64-pc-windows-gnullvm` with zero-MinGW Zig cross-build wrappers (`tools/wl-arm64-cc.cmd`, `tools/wl-arm64-link.cmd`).
- **Zig ARM64 Kernel Containment Engine (`wardline_engine_arm64`)**:
  - `evaluateArm64SpawnPolicy()` enforcing native `0xAA64`, opt-in `0xA641` ARM64EC, default-deny Prism `0x8664` (`WL_ERR_PRISM_BLOCKED`), and conditional ACG suppression under Prism emulation (`apply_acg = false`, `emulation_detected = 1`).
  - Hardware PAC/BTI probe (`checkArm64PacBti()`), DEP/ASLR/heap/font/extension-point mitigations, L0 (`CreateRestrictedToken` + `WinLowLabelSid`), L1 (`CreateAppContainerProfile` 0 network caps + `lpDesktop = ""` + `HANDLE_LIST` + `JobObject` + IOCP + deferred teardown), and staged fail-closed `L2` probe.
- **Hardened Named Pipe TCB Daemon (`wardline-guard.exe`)**:
  - `FILE_FLAG_FIRST_PIPE_INSTANCE | PIPE_REJECT_REMOTE_CLIENTS` + Protected User/`SYSTEM` SDDL + Process DACL protection.
  - Reparse-safe host NTFS File Broker (`FILE_FLAG_OPEN_REPARSE_POINT`, `GetFinalPathNameByHandleW(VOLUME_NAME_DOS)`).
  - DPAPI `CryptProtectData` + `ChaCha20Poly1305` vault + `VirtualLock` `SecretBytes` + cross-chunk `StreamingScrubber`.
  - Anti-SSRF DNS pinning + Windows Schannel TLS router (`wardline-egress`).
  - Ed25519 `WardCertChain` + `crl.redb` + `BLAKE3` single-use HITL `approvals.redb` + `WLG1` CBOR audit WAL verified offline by `wardline-verify.exe`.
- **Adapters & SDKs**: Zero-secret `wardline-mcp.exe` (`2024-11-05`) and Python/TypeScript `WardlineClient` SDKs.
- **Architecture & Documentation**: High-definition `4800×3200` PNG / `3600×2400` SVG architecture diagrams (`assets/architecture-arm64.{png,svg}`) plus full operator, architecture, threat-model, policy, and CLI/MCP guides (`docs/`).
