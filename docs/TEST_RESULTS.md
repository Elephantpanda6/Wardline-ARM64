# Wardline ARM64 Verification & Test Matrix

All builds, static analyses, cross-OS Zig engine compilations, unit suites, and live containment checks recorded below were executed directly against the final tree.

## 1. Environment

- **Windows Host**: Windows 11 x64 (`Build 26300`), `rustc 1.100.0`, Zig `0.17.1`
- **WSL2 Linux Native**: Ubuntu (`6.18.33.2-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC x86_64`), `rustc 1.99.1`, OpenSSL/pkg-config toolchain

## 2. Zig Multi-OS ARM64 Kernel Engines (`zig build`)

Executed in `Wardline-ARM64`:

| Command | Result | Output Artifacts & Sizes |
|---|---|---|
| `zig build all-engines` | Passed (exit `0`) | `zig-out/win-arm64/wardline_engine_arm64.lib` (`5,100,554` bytes)<br>`zig-out/linux-arm64/libwardline_engine_arm64.a` (`4,277,028` bytes)<br>`zig-out/macos-arm64/libwardline_engine_arm64.a` (`3,268,064` bytes)<br>`zig-out/freebsd-arm64/libwardline_engine_arm64.a` (`4,073,468` bytes) |
| `zig build common-tests` | Passed (exit `0`) | Cross-OS binary format & ABI tests (`PE`, `ELF`, `Mach-O`, `MachOFat`) |
| `zig build test` | Passed (exit `0`) | Emits `zig-out/bin/win-arm64-tests.exe` (`2,251,776` bytes) + runs native host tests |

## 3. Windows ARM64 Cross-Build & Clippy (`aarch64-pc-windows-gnullvm`)

- `cargo clippy --target aarch64-pc-windows-gnullvm --workspace --all-targets -- -D warnings`: **Passed (0 warnings)** across all 12 workspace crates.
- `cargo build --target aarch64-pc-windows-gnullvm --release --bins`: **Passed (exit `0`)**.
- Verified PE Machine Headers (`0xAA64` / `IMAGE_FILE_MACHINE_ARM64`):
  - `wardline.exe`: `machine=0xAA64`, `3,205,120` bytes
  - `wardline-guard.exe`: `machine=0xAA64`, `2,554,368` bytes
  - `wardline-mcp.exe`: `machine=0xAA64`, `903,680` bytes
  - `wardline-verify.exe`: `machine=0xAA64`, `815,616` bytes

## 4. Host Unit & Live Kernel Containment Suites

### A. `Wardline-ARM64` Non-Sandbox Crates (`x86_64-pc-windows-msvc`)
`cargo test --target x86_64-pc-windows-msvc -p wardline-core -p wardline-policy -p wardline-cert -p wardline-approval -p wardline-log -p wardline-vault -p wardline-egress -p wardline-verify -- --test-threads=1`:
- **27 passed, 0 failed, 0 ignored**:
  - `wardline-core`: `12` passed (`platform`, `binary` PE/ELF/Mach-O, `lolbin`, `path`, `capability`)
  - `wardline-egress`: `4` passed (SSRF CIDR/IPv6/IMDS blocks, pinned lookup, cross-chunk HTTP scrub)
  - `wardline-cert`: `3` passed (monotonic attenuation, persistent `crl.redb`)
  - `wardline-policy`: `3` passed (schema, ARM64 Prism/ARM64EC gates, LOLBin/FS/egress rules)
  - `wardline-approval`: `2` passed (`approvals.redb` digest lock & non-replay)
  - `wardline-vault`: `2` passed (DPAPI master key persistence, cross-chunk `StreamingScrubber`)
  - `wardline-log`: `1` passed (concurrent `LockFileEx` WLG1 hash chain + tamper check)

### B. Full Shared Codebase Live Runs (`Wardline-x64` Windows Native & WSL2 Linux Native)
Because all 12 workspace crates and `platforms/common` + `platforms/{linux,macos,bsd}` are shared identically with `Wardline-x64`, full live execution of the shared crates and POSIX Linux containment engine ran on both:
- **Windows 11 x64 Native (`Wardline-x64`)**: `32` unit tests + `8` live Win32 AppContainer/JobObject/IOCP kernel assertions (`live_sandbox.rs`) = **40 passed, 0 failed, 0 ignored**.
- **WSL2 Ubuntu Linux (`6.18.33.2`)**: `32` unit tests + `8` live POSIX UserNS/NetNS/Landlock/seccomp kernel assertions (`live_sandbox.rs`) = **40 passed, 0 failed, 0 ignored**, plus live `wardline doctor --json`, validation of all 6 policy manifests, L1 `/usr/bin/id` (`exit=0`) and `/bin/echo` (`exit=0`), `/bin/sh -c` LOLBin denial, and offline `wardline-verify` (`11` frames, `valid: true`, exit `0`).
- **Not run live in this environment**: Native `windows-11-arm`, `linux-arm64`, `macos-arm64`, and `freebsd-arm64` hosts (cross-compiled and tested via Zig + CI workflows).
