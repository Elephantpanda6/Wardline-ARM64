# Wardline (`win-arm64`) — Operator & Developer Guide

This guide covers building, configuring, and operating **`wardline-arm64` (`aarch64-pc-windows-gnullvm`)** natively on Windows 11 on ARM64 or cross-compiling cleanly from Windows x64 hosts using Zig `0.17.1`.

---

## Table of Contents

1. [Toolchain Setup & Zig Cross-Build Wrappers](#1-toolchain-setup--zig-cross-build-wrappers)
2. [Probing ARM64 Hardware Capabilities (`doctor`)](#2-probing-arm64-hardware-capabilities-doctor)
3. [Selecting ARM64 / ARM64EC / Prism x64 Policy (`[architecture]`)](#3-selecting-arm64--arm64ec--prism-x64-policy-architecture)
4. [Authoring Policy & Running Sandboxed Tools](#4-authoring-policy--running-sandboxed-tools)
5. [Secret Vault Custody (`vault`) & SSRF-Pinned Fetch (`fetch`)](#5-secret-vault-custody-vault--ssrf-pinned-fetch-fetch)
6. [Asymmetric WardCert Delegation (`cert`)](#6-asymmetric-wardcert-delegation-cert)
7. [Human-in-the-Loop Approvals (`approve`)](#7-human-in-the-loop-approvals-approve)
8. [Operating `wardline-guard` + `wardline-mcp` & SDKs](#8-operating-wardline-guard--wardline-mcp--sdks)
9. [Offline Cryptographic Audit Verification (`audit`, `wardline-verify`)](#9-offline-cryptographic-audit-verification-audit-wardline-verify)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Toolchain Setup & Zig Cross-Build Wrappers

[`.cargo/config.toml`](../.cargo/config.toml) configures `aarch64-pc-windows-gnullvm` automatically using repository-local wrappers:
- `linker = "tools\\wl-arm64-link.cmd"` ([`wl-arm64-link.py`](../tools/wl-arm64-link.py))
- `CC_aarch64_pc_windows_gnullvm = "tools\\wl-arm64-cc.cmd"` ([`wl-arm64-cc.py`](../tools/wl-arm64-cc.py))

These wrappers locate `zig.exe` (on `PATH` or WinGet's `zig.zig*` package folder) and drive `zig cc -target aarch64-windows-gnu`, rewriting rustc GNU linker arguments (`-lmsvcrt` → `-lucrtbase`, `-lsynchronization` → `-lapi-ms-win-core-synch-l1-2-0`, `-lunwind`, static `-lwindows.*` archives) without needing a standalone MinGW/LLVM sysroot.

### Prerequisites
- Rust toolchain with target `aarch64-pc-windows-gnullvm` (`rustup target add aarch64-pc-windows-gnullvm`)
- Zig `0.17.1`
- Python 3 (on `PATH`)

### Build & Test Commands

```powershell
# Build Zig ARM64 engine static library (wardline_engine_arm64) & tests
zig build
zig build test

# Zero-warning lint & ARM64 (0xAA64) release binaries
cargo clippy --workspace --all-targets -- -D warnings
cargo build --release --bins

# Native Windows on ARM64 execution & integration verification
cargo test --workspace -- --test-threads=1
```

---

## 2. Probing ARM64 Hardware Capabilities (`doctor`)

Run on an ARM64 Windows host:

```powershell
.\target\aarch64-pc-windows-gnullvm\release\wardline.exe doctor --json
```

In `engine_arm64.zig`, `wl_probe_capabilities` reports:
- `capabilities.arch`: `2` (`WL_ARCH_ARM64`)
- `is_wow64_emulated`: from `IsWow64Process2` (`0` for native `aarch64` host execution)
- `pac_bti_available`: `1` when `IsProcessorFeaturePresent(PF_ARM_V83_JSCVT_INSTRUCTIONS_AVAILABLE)` or `GetProcessMitigationPolicy(..., ProcessUserPointerAuthPolicy)` indicates hardware Pointer Authentication support
- `cet_shadow_stack_supported`: `0` (x86/x64 CET feature flag not applicable on ARM64)
- `appcontainer_supported` / `job_object_iocp_supported` / `hyperv_hcs_available`: live OS & `computecore.dll` capability telemetry

---

## 3. Selecting ARM64 / ARM64EC / Prism x64 Policy (`[architecture]`)

Unlike `win-x64`, Windows on ARM64 hosts frequently encounter legacy x64 (`0x8664`) developer utilities or hybrid `ARM64EC` (`0xA641`) DLLs/executables. Wardline keeps **emulation disabled by default**:

- **`mode = "strict_native"` (default)**: Permits strictly **`0xAA64` (`ARM64`)** binaries. Rejects `0xA641` with `WL_ERR_PE_DISALLOWED_ARCH` and rejects `0x8664` with `WL_ERR_PRISM_BLOCKED`.
- **`mode = "allow_arm64ec"`**: Permits both **`0xAA64`** and **`0xA641`** (`ARM64EC`), keeping `PROHIBIT_DYNAMIC_CODE_ALWAYS_ON` (ACG) enabled.
- **`mode = "allow_prism_x64"`**: Explicitly opts into spawning **`0x8664` (`AMD64`)** tools via Windows Prism binary translation. Because Prism generates translated JIT code pages at runtime, `evaluateArm64SpawnPolicy()` sets `emulation = true` and **suppresses ACG (`apply_acg = false`)** for that emulated child so it does not crash with `STATUS_DYNAMIC_CODE_BLOCKED`, while recording `emulation_detected = 1` in the `audit.wlog` frame!

```powershell
# Check policy interpretation before deployment
.\target\aarch64-pc-windows-gnullvm\release\wardline.exe policy validate .\schemas\wardline.v1.toml --json
```

---

## 4. Authoring Policy & Running Sandboxed Tools

```powershell
$cli = ".\target\aarch64-pc-windows-gnullvm\release\wardline.exe"

# Dry-run checks
$cli policy eval-fs --policy .\schemas\wardline.v1.toml src\main.rs
$cli policy eval-net --policy .\schemas\wardline.v1.toml https://api.github.com/zen

# Execute a native 0xAA64 binary inside L1 AppContainer containment
$cli run --policy .\schemas\wardline.v1.toml --base-dir . --state-dir .\.wardline --json C:\Windows\System32\whoami.exe
```

Note that `deny_lolbins = true` still blocks all 25 Windows LOLBins (50 binary/bare patterns: `cmd`, `powershell`, `pwsh`, `wscript`, `mshta`, `rundll32`, `regsvr32`, `certutil`, `bitsadmin`, `wmic`, `bash`, `wsl`, …) and 19 script extensions (`.bat`, `.cmd`, `.ps1`, `.vbs`, `.hta`, …).

---

## 5. Secret Vault Custody (`vault`) & SSRF-Pinned Fetch (`fetch`)

Secrets are protected identically to the x64 edition using DPAPI `CryptProtectData` (`vault.key`) + `ChaCha20Poly1305` (`vault.enc`), pinned RAM (`VirtualLock` + `Zeroize`), and cross-chunk `StreamingScrubber` redaction:

```powershell
$cli = ".\target\aarch64-pc-windows-gnullvm\release\wardline.exe"
$env:GITHUB_TOKEN = "ghp_example_token"

$cli vault set --state-dir .\.wardline --grant-id gh_ro --host api.github.com --secret-env GITHUB_TOKEN
$cli vault list --state-dir .\.wardline --json
$cli fetch --policy .\schemas\wardline.v1.toml --grant gh_ro --json https://api.github.com/zen
```

---

## 6. Asymmetric WardCert Delegation (`cert`)

Lock delegated agent chains explicitly to ARM64 hosts using `--arch arm64`:

```powershell
$cli = ".\target\aarch64-pc-windows-gnullvm\release\wardline.exe"

$cli cert keygen --out-seed .\root.seed.hex --json
$cli cert keygen --out-seed .\arm_worker.seed.hex --json

$cli cert issue `
  --seed-file .\root.seed.hex `
  --holder-pubkey <WORKER_PUBKEY_HEX> `
  --subject "arm64-builder" `
  --ttl-secs 3600 `
  --isolation l1 `
  --arch arm64 `
  --depth 2 `
  --scope "fs-read:src" `
  --scope "net:api.github.com:/" `
  --out .\arm_worker.cert.json

$cli cert verify --root-pubkey <ROOT_PUBKEY_HEX> --cert .\arm_worker.cert.json --crl-db .\.wardline\crl.redb --json
```

---

## 7. Human-in-the-Loop Approvals (`approve`)

```powershell
$cli = ".\target\aarch64-pc-windows-gnullvm\release\wardline.exe"
$cli approve list --state-dir .\.wardline --json
$cli approve grant --state-dir .\.wardline --ticket <TICKET_UUID> --approver "operator"
$cli approve deny --state-dir .\.wardline --ticket <TICKET_UUID>
$cli approve sweep --state-dir .\.wardline
```

---

## 8. Operating `wardline-guard` + `wardline-mcp` & SDKs

Launch the ARM64 guard daemon and point MCP hosts to the `0xAA64` `wardline-mcp.exe` binary:

```powershell
.\target\aarch64-pc-windows-gnullvm\release\wardline-guard.exe `
  --policy .\schemas\wardline.v1.toml `
  --pipe \\.\pipe\wardline_guard `
  --base-dir . `
  --state-dir .\.wardline
```

```json
{
  "mcpServers": {
    "wardline-arm64": {
      "command": "C:\\path\\to\\wardline-arm64\\target\\aarch64-pc-windows-gnullvm\\release\\wardline-mcp.exe",
      "args": ["--pipe", "\\\\.\\pipe\\wardline_guard"]
    }
  }
}
```

Both Python ([`clients/python/wardline_client/__init__.py`](../clients/python/wardline_client/__init__.py)) and TypeScript ([`clients/ts/src/index.ts`](../clients/ts/src/index.ts)) `WardlineClient` SDKs work out-of-the-box against the ARM64 binaries and Named Pipe.

---

## 9. Offline Cryptographic Audit Verification (`audit`, `wardline-verify`)

```powershell
.\target\aarch64-pc-windows-gnullvm\release\wardline-verify.exe `
  --log .\.wardline\audit.wlog `
  --seal-pubkey <64_HEX_PUBKEY> `
  --json
```

---

## 10. Troubleshooting

| Symptom | Root Cause & Resolution |
| :--- | :--- |
| **`WL_ERR_PRISM_BLOCKED` (`status_code = 5`)** | Target binary has PE machine `0x8664` (x64) and `[architecture].mode` is `"strict_native"` or `"allow_arm64ec"`. Prefer an ARM64 build (`0xAA64`); only set `mode = "allow_prism_x64"` when legacy x64 tooling is unavoidable. |
| **`WL_ERR_PE_DISALLOWED_ARCH` (`status_code = 4`)** | Binary is `0xA641` (`ARM64EC`) without `mode = "allow_arm64ec"`, 32-bit `0x014C`, or a raw non-PE script. |
| **`wl-arm64-link.cmd` cannot find Zig** | Add `zig.exe` (`0.17.1`) to `PATH` or install Zig via WinGet so `%LOCALAPPDATA%\Microsoft\WinGet\Packages\zig.zig*` resolves automatically. |
| **`cargo test` skips running on an x64 dev box** | Cross-compiled `aarch64` Windows executables cannot execute directly on an x64 AMD64 CPU; run `cargo test --workspace -- --test-threads=1` on native Windows on ARM64 hardware (`windows-11-arm` CI runner). |
