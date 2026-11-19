# Wardline ARM64 Verification & Test Results

All Zig cross-engine builds, `aarch64-pc-windows-gnullvm` Clippy/release builds, and pure-Rust host unit tests below reflect runs executed against the finalized `Wardline-ARM64` codebase on the x64 Windows build host.

---

## 1. Zig ARM64 Engine Builds & C-ABI v2 Tests

- **Commands Executed**: `zig build all-engines`, `zig build common-tests`, `zig build test` — **Exited 0**.
- **Emitted 4 Static ARM64 Containment Archives**:
  - `zig-out/win-arm64/wardline_engine_arm64.lib` (`5,105,622` bytes) — `PE 0xAA64` / `AppContainer` + `JobObject` + `L1.5` Win32k/Non-MS-Binary mitigations + `C-ABI v2` bounds checks (`validateCapsPtr`, `validateSpawnReq`)
  - `zig-out/linux-arm64/libwardline_engine_arm64.a` (`4,284,940` bytes) — `EM_AARCH64`, PAC/BTI/MTE/SVE probes, fail-closed Landlock + `AUDIT_ARCH_AARCH64` 22-syscall `seccomp-bpf`
  - `zig-out/macos-arm64/libwardline_engine_arm64.a` (`3,272,632` bytes) — Apple Silicon `ARM64` Mach-O/Universal Fat + Seatbelt SBPL + `(deny process-fork)`
  - `zig-out/freebsd-arm64/libwardline_engine_arm64.a` (`4,078,116` bytes) — `EM_AARCH64` + Capsicum `cap_enter()` + `rlimit`

---

## 2. Windows ARM64 Cross-Compilation (`aarch64-pc-windows-gnullvm`)

- **Rust Clippy**: `cargo clippy --target aarch64-pc-windows-gnullvm --workspace -- -D warnings` — **Passed (0 warnings)**.
- **Release ARM64 PE Binaries** (`cargo build --target aarch64-pc-windows-gnullvm --release --bins`): All 5 binaries compiled cleanly with verified `PE 0xAA64` (`IMAGE_FILE_MACHINE_ARM64`) headers:
  - `target/aarch64-pc-windows-gnullvm/release/wardline.exe`: `4,013,568` bytes (`machine=0xAA64`)
  - `target/aarch64-pc-windows-gnullvm/release/wardline-guard.exe`: `2,944,512` bytes (`machine=0xAA64`)
  - `target/aarch64-pc-windows-gnullvm/release/wardline-mcp.exe`: `1,775,104` bytes (`machine=0xAA64`)
  - `target/aarch64-pc-windows-gnullvm/release/wardline-verify.exe`: `944,640` bytes (`machine=0xAA64`)
  - `target/aarch64-pc-windows-gnullvm/release/wardline-guest-agent.exe`: `445,952` bytes (`machine=0xAA64`)

---

## 3. Host Pure-Crate Verification & Scope Caveats

Because the build machine is `x86_64` Windows (not physical ARM64 hardware), the workspace test command excluded the Zig-linked binary/FFI crates for host x64 execution while all shared core/policy/crypto/vault/egress/log/guest-agent crates executed directly:

- **Command**:
  `cargo test --target x86_64-pc-windows-msvc --workspace --exclude wardline-sandbox --exclude wardline-guard --exclude wardline-mcp --exclude wardline-cli`
- **Result**: **37 passed, 0 failed, 0 ignored**:
  - `wardline-approval`: `2 passed`
  - `wardline-cert`: `4 passed` (`lineage` subtree revocation, `MAX_CHAIN_DEPTH`, monotonic attenuation, persistent CRL)
  - `wardline-core`: `12 passed` (`PE 0xAA64`/`0xA641`/`0x8664` Prism gates, `ELF64` ARM64/x64, `Mach-O`/`MachOFat`, LOLBins, path shield, `HostPlatformProfile`)
  - `wardline-egress`: `5 passed` (persistent `redb` `BudgetStore`, IMDS/SSRF blocking, credential grant binding, chunked scrub)
  - `wardline-guest-agent`: `2 passed`
  - `wardline-log`: `3 passed` (odd-leaf Merkle tree, concurrent writers WAL, `ActionIntent`/`ActionOutcome` & panic freeze)
  - `wardline-platform`: `0 tests` (low-level OS FFI wrapper crate)
  - `wardline-policy`: `7 passed` (`argv_shield`, ARM64 Prism/LOLBin enforcement, `[operator_forbid]`, egress/approval rules)
  - `wardline-vault`: `2 passed` (streaming scrubber, DPAPI master key persistence)
  - `wardline-verify`: `0 tests`

### Native Hardware & Parity Note
- **Not Executed Directly on Physical ARM64 Silicon**: Runtime execution of the `0xAA64` PE binaries on physical Windows on ARM (`windows-11-arm`), native `linux-arm64` kernel, `macos-arm64`, or `freebsd-arm64` hardware (and native ARM64 host execution of `wardline-sandbox`, `wardline-guard`, `wardline-mcp`, `wardline-cli`, and `invariants_i1_i7`) was not performed locally because this workstation is `x86_64` Windows.
- **Full Workspace & Live Kernel Verification on Shared Codebase**: Identical shared workspace crates (`cli`, `guard`, `mcp`, `sandbox`, `invariants_i1_i7`, plus live OS kernel containment) passed **62/62 unit/integration tests + 8/8 live kernel checks** on native Windows x64 and **62/62 + 8/8** on WSL2 Ubuntu Linux x64 in `Wardline-x64`.

---

## 4. `linux-arm64` User-Mode Emulation (`qemu-aarch64 10.2.1`)

Compiled standalone `ELF64 AArch64` (`aarch64-linux-musl`) Zig test binaries and executed them inside WSL2 Ubuntu via `qemu-aarch64 version 10.2.1 (Debian 1:10.2.1+ds-1ubuntu3.3)`:
- **`platforms/common/common.zig` (`AArch64` ELF)**: **3/3 passed** (`classifyPeBytes`, `classifyBinaryBytes`, `C-ABI v2 struct sizes match C contract`).
- **`platforms/linux/engine_linux.zig` (`AArch64` ELF)**: **1/1 passed** (`seccomp-bpf filter validates native arch, mount API blocks, and socket families`).
- **`wl_probe_capabilities` (`AArch64` ELF smoke binary)**: **Exited 0** (`rc=0 abi=2 size=48 os=2 arch=2 build=61833 page=4096 mask=5 landlock=0 cgroup_v2=1 ext_flags=30 flags=0x5e`; `landlock=0` expected under QEMU user-mode syscall interception).

---

## 5. Polyglot Client SDK Verification (Windows & WSL2 Ubuntu Linux)

| SDK | Windows x64 Status | WSL2 Ubuntu Linux x64 Status | Notes |
|---|---|---|---|
| **Rust SDK** (`clients/rust/wardline-client`) | **1/1 passed** (`cargo test --offline`) | **1/1 passed** (`cargo test --offline`) | `#![forbid(unsafe_code)]`; IPC framing & typed error mapping |
| **Python SDK** (`clients/python`) | **1/1 passed** (`unittest`) | **1/1 passed** (`unittest`) | `[u32 LE][JSON]` framing & exit-code `3` error classes |
| **TypeScript SDK** (`clients/ts`) | **1/1 passed** (`node v24.18.1 --experimental-strip-types --test`) | **1/1 passed** (`node v24.18.1 --experimental-strip-types --test`) | Verified Node v24 direct TypeScript execution on both OSes |
| **Go SDK** (`clients/go/wardline`) | **1/1 passed** (`go1.27.4 windows/amd64`) | **1/1 passed** (`go1.26.8 linux/amd64`) | `TestIPCFrameAndCheckedResponse` passed on both OSes |

---

## 6. Multi-OS ARM64 GitHub Actions CI & Supply-Chain Verification

- **Supply-Chain Audit (`supply-chain`: `cargo-deny` + `rustsec/audit-check`)**: **Passed** (`advisories ok`, `bans ok`, `licenses ok`, `sources ok`).
- **Native & Cross ARM64 Matrices (`Wardline ARM64 Multi-OS CI`)**: **Passed** across all 5 runners:
  - `Windows 11 ARM64 Native Test Suite` (`windows-11-arm`): native `PE 0xAA64` Zig + full live workspace + `live_sandbox` + `invariants_i1_i7`
  - `Linux ARM64 Native Build & Test` (`ubuntu-24.04-arm`): native `AArch64` ELF Zig + full workspace + `live_sandbox` + `invariants_i1_i7`
  - `macOS Apple Silicon Native Build & Test` (`macos-latest`): native Apple Silicon `ARM64` Seatbelt + `live_sandbox` + `invariants_i1_i7`
  - `Windows ARM64 Cross-Build & Clippy` (`windows-latest` -> `aarch64-pc-windows-msvc` / `aarch64-pc-windows-gnullvm`)
  - `Zig 4-OS ARM64 Engine Cross-Build` (`win-arm64`, `linux-arm64`, `macos-arm64`, `freebsd-arm64`)
