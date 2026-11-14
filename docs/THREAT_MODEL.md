# Wardline (`win-arm64`) — Threat Model & Security Analysis

This document details the security boundaries, ARM64-specific emulation threat vectors, Win32 mitigations, and explicit non-goals of **`wardline-arm64`**.

---

## 1. ARM64-Specific Threat Surface: Binary Translation & Mixed-ISA Confused Deputy

On Windows on ARM64, the OS transparently translates `0x8664` (x64) PE executables through the **Prism** emulator unless blocked by policy. Left unchecked, this creates two distinct risks:
1. **Unannounced JIT Memory Pages**: Prism emits writable/executable JIT caches at runtime. Enabling `MITIGATION_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON` (ACG) blindly crashes emulated x64 tools (`STATUS_DYNAMIC_CODE_BLOCKED`), often templating teams into disabling ACG globally.
2. **ISA Policy Bypass / Unaudited Third-Party x64 Binaries**: Agents could drop prebuilt x64 executables expecting silent Prism emulation.

**Wardline's Control (`engine_arm64.zig`)**:
- **`mode = "strict_native"` (default)** rejects all `0x8664` (`WL_ERR_PRISM_BLOCKED`) and `0xA641` (`WL_ERR_PE_DISALLOWED_ARCH`) executables prior to process launch.
- **`mode = "allow_prism_x64"`** opt-in **only relaxes ACG (`apply_acg = false`) for verified `emulation = true` children**, keeping strict ACG turned **ON** for every `0xAA64` and `0xA641` process while tagging `emulation_detected = 1` in `.wardline/audit.wlog`.

---

## 2. Shared Adversary Matrix

| Threat / Attack Vector | Wardline Defense (`win-arm64`) |
| :--- | :--- |
| **T1. LOLBin & Script Proxy Execution** | Blocks **25 LOLBins (50 patterns)** (`cmd`, `powershell`, `pwsh`, `wscript`, `cscript`, `mshta`, `rundll32`, `regsvr32`, `certutil`, `bitsadmin`, `wmic`, `msiexec`, `installutil`, `msbuild`, `bash`, `wsl`, …) + **19 script extensions** with trailing-dot & case normalization; `engine_arm64.zig` also drops non-PE scripts (`WL_ERR_PE_DISALLOWED_ARCH`). |
| **T2. Unwanted Prism / x86 / Foreign ISA** | `evaluateArm64SpawnPolicy()` rejects `0x014C` (x86) outright, rejects `0x8664` unless `allow_prism_x64 = true`, and rejects `0xA641` unless `allow_arm64ec = true`. |
| **T3. NTFS Junction / Reparse & ADS Escape** | `path.rs` denies `\\?\`, `\\.\`, `\??\`, UNC `\\`, and ADS `:`. `file_broker.rs` walks every path component with `FILE_FLAG_OPEN_REPARSE_POINT \| FILE_FLAG_BACKUP_SEMANTICS`, fails on `FILE_ATTRIBUTE_REPARSE_POINT`, and confirms `GetFinalPathNameByHandleW(VOLUME_NAME_DOS)` inside `--base-dir`. |
| **T4. Ambient Credential Harvest** | `build_child_env()` runs `env_clear()` + allowlist; vault keys stay sealed under Win32 DPAPI + `ChaCha20Poly1305` and locked RAM (`VirtualLock` + `Zeroize`). `L1 AppContainer` removes unconstrained filesystem visibility. |
| **T5. Cross-Chunk Secret Exfiltration** | `StreamingScrubber` scans child `stdout`/`stderr` and HTTP headers/bodies across arbitrary buffer splits, replacing granted secrets with `[WARDLINE_REDACTED:<grant_id>]`. |
| **T6. SSRF, Cloud IMDS & DNS Rebinding** | `ssrf.rs` + `client.rs` resolve DNS once (`resolve_and_pin_addresses`), block `localhost`, `.local`, `.internal`, `metadata.google.internal`, `127/8`, `169.254.0.0/16` IMDS, RFC1918, `100.64/10`, `::ffff:`, and IPv6 (default off), then dial via `connect_pinned` + Schannel TLS. `L1` child has 0 net capabilities. |
| **T7. Mutating Approval Replay / Swap** | `approvals.redb` binds each ticket to `BLAKE3("wardline.approval.v1\0" \|\| canonical_action)` and atomically transitions `Approved -> Consumed` on first use. |
| **T8. Delegation Escalation** | `WardCertChain` (`Ed25519` over CBOR `"wardline.cert.v1\0"`) validates strictly non-widening TTL, isolation, `arch = "arm64"`, depth, subset scopes, and durable `crl.redb` revocations. |
| **T9. Pipe Squatting & Memory Inspection** | `FILE_FLAG_FIRST_PIPE_INSTANCE \| PIPE_REJECT_REMOTE_CLIENTS` + Protected SDDL (`UserSID` + `SYSTEM`) + daemon `PROTECTED_DACL_SECURITY_INFORMATION`. |
| **T10. Audit Log Truncation / Tamper** | `WLG1` append-only log with Win32 `LockFileEx`, `FlushFileBuffers`, `BLAKE3` chain links, and `Ed25519` seals verified offline by `wardline-verify.exe`. |

---

## 3. Trust Assumptions & Staged Scope

1. **Non-Admin User Boundary**: Local Windows Administrators / `SYSTEM` sit outside user-mode container boundaries; run `wardline-guard.exe` as a non-elevated user.
2. **Host-Specific Hardware PAC/BTI**: `pac_bti_available` dynamically reflects Silicon + Windows OS pointer-auth capability in `wardline doctor --json`.
3. **Cross-Compiled Verification Limits**: Cross-compilation on x64 hosts validates Rust lint, `0xAA64` PE emission, and host common tests, while live Win32 AppContainer / IOCP / Prism probes execute on native Windows on ARM64 (`windows-11-arm`).
4. **`L2 MicroVM` Staged**: `hyperv_hcs_available` is probed, while `L2` spawn fails closed (`WL_ERR_NOT_SUPPORTED_ARCH`) until guest runner integration ships.
