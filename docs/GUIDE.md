# Wardline Operator & Integration Guide

## 1. Prerequisites

- **Rust** toolchain (`1.85+` recommended; MSVC or GNU/LLVM on Windows, standard toolchain on Linux/macOS/FreeBSD)
- **Zig `0.17+`** (for compiling the OS kernel containment engines — or set `WARDLINE_PREBUILT_ENGINE_DIR` if linking prebuilt engine archives)
- For Windows ARM64 cross-compilation from Windows x64: LLVM/Clang-based MinGW sysroot tools configured via `tools/wl-arm64-{cc,link}.cmd` (or native Windows ARM64 MSVC toolchain)
- On Linux: C toolchain (`gcc`/`clang`), `pkg-config`, OpenSSL headers (`libssl-dev`) for `native-tls`

---

## 2. Building

### Build All 4 ARM64 OS Engines via Zig

```powershell
zig build all-engines
zig build common-tests
zig build test
```

Artifacts are emitted to target directories under `zig-out/`:
- `zig-out/win-arm64/wardline_engine_arm64.lib` (`win-arm64`)
- `zig-out/linux-arm64/libwardline_engine_arm64.a` (`linux-arm64`)
- `zig-out/macos-arm64/libwardline_engine_arm64.a` (`macos-arm64`)
- `zig-out/freebsd-arm64/libwardline_engine_arm64.a` (`freebsd-arm64`)

### Build Rust Binaries (ARM64 Windows Cross-Build from x64)

```powershell
# Run from the repository root so .cargo\config.toml configures the cross linker/CC
cargo clippy --target aarch64-pc-windows-gnullvm --workspace --all-targets -- -D warnings
cargo build --target aarch64-pc-windows-gnullvm --release --bins
```

### Build Natively on ARM64 Linux, macOS Apple Silicon, or FreeBSD

```bash
# If zig is installed natively on the host:
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace -- --test-threads=1
cargo build --release --bins

# If linking against a prebuilt Zig engine archive:
export WARDLINE_PREBUILT_ENGINE_DIR=/path/to/engine/dir
cargo build --release --bins
```

---

## 3. Core Operator Workflows

### Probe Hardware, OS & Containment Engine

```bash
wardline doctor --json
```

Inspects OS kind, ISA (`arm64` / `x64`), OS page size (`4096` vs `16384` / `65536`), device telemetry, and kernel containment primitives:
- Windows ARM64: `PAC/BTI`, `AppContainer`, `JobObject + IOCP`, `Hyper-V HCS`
- Linux ARM64: `PAC`, `BTI`, `MTE`, `SVE`, `SVE2`, `LARGE_PAGES`, UserNS, Landlock ABI, KVM
- macOS / FreeBSD: Seatbelt / Capsicum readiness and page size

### Validate Policy Profiles

```bash
wardline policy validate schemas/wardline.v1.toml --json
wardline policy validate schemas/profiles/arm64-laptop.toml --json
wardline policy validate schemas/profiles/arm64-server.toml --json
wardline policy validate schemas/profiles/arm64-edge-sbc.toml --json
```

### Execute Contained Tools

```bash
# Allowed native execution under L1 containment + audit trail
wardline run --policy schemas/profiles/arm64-server.toml --json /usr/bin/id

# LOLBin / shell invocation is denied fail-closed
wardline run --policy schemas/wardline.v1.toml --json cmd.exe /c echo blocked
```

### Secret Vault, Offline Verification, Checkpoints & Panic Freeze

```bash
# Store a secret in DPAPI / 0600 ChaCha20Poly1305 vault (locked in RAM on access; or --value-file)
wardline vault set --state-dir .wardline --grant-id github_api --host api.github.com --secret-env MY_TOKEN
wardline vault rotate --state-dir .wardline --json

# Offline WLG1 verification, Merkle inclusion proofs, and emergency panic freeze
wardline-verify --log .wardline/audit.wlog --proof-index 0 --json
wardline audit checkpoint --log .wardline/audit.wlog --out-dir .wardline --json
wardline panic --log .wardline/audit.wlog --reason "incident containment" --json
```

---

## 4. MCP, Supply Chain, Fuzzing & Thin Client SDKs

- **MCP Stdio Server**: Run `wardline-mcp serve --pipe ...` for `2024-11-05` MCP clients (`wardline_exec`, `wardline_fetch`, `wardline_fs_read`, `wardline_fs_write`, `wardline_learn`), or `wardline-mcp wrap --name tool --policy ... -- <COMMAND>` to sandbox third-party MCP servers.
- **Python Client**: [`clients/python/wardline_client/__init__.py`](../clients/python/wardline_client/__init__.py) — Win32 Named Pipes & Unix Domain Sockets + exit code `3` HITL errors.
- **TypeScript Client**: [`clients/ts/src/index.ts`](../clients/ts/src/index.ts) — Node.js client supporting `\\.\pipe\wardline_guard` and Unix domain sockets.
- **Go Client**: [`clients/go/wardline/client.go`](../clients/go/wardline/client.go) — Framed IPC + CLI wrapper (`ApprovalRequiredError` / `DeniedError`).
- **Rust Client**: [`clients/rust/wardline-client/src/lib.rs`](../clients/rust/wardline-client/src/lib.rs) — Standalone `#![forbid(unsafe_code)]` SDK crate.
- **Supply Chain & Fuzzing**: [`deny.toml`](../deny.toml), [`audit.toml`](../audit.toml), and 7 `cargo-fuzz` targets under [`fuzz/`](../fuzz/Cargo.toml).
