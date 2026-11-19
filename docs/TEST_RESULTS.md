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
- **Not Executed Directly on Physical ARM64 Silicon**: Runtime execution of the `0xAA64` PE binaries on Windows on ARM (`windows-11-arm`), `linux-arm64`, `macos-arm64`, or `freebsd-arm64` hardware (and ARM64 host execution of `wardline-sandbox`, `wardline-guard`, `wardline-mcp`, `wardline-cli`, and `invariants_i1_i7`) was not performed locally because this workstation is `x86_64` Windows.
- **Full Workspace & Live Kernel Verification on Shared Codebase**: Identical shared workspace crates (`cli`, `guard`, `mcp`, `sandbox`, `invariants_i1_i7`, plus live OS kernel containment and Python/TypeScript/Rust SDK tests) passed **62/62 unit/integration tests + 8/8 live kernel checks** on native Windows x64 and **62/62 + 8/8** on WSL2 Ubuntu Linux x64 in `Wardline-x64`.
