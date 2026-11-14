# Wardline (`win-arm64`) — CLI, MCP, Named Pipe IPC & SDK Reference

Complete command-line, MCP tool, Named Pipe IPC, and SDK reference for all four **`aarch64-pc-windows-gnullvm` (`0xAA64`)** binaries (`wardline.exe`, `wardline-guard.exe`, `wardline-mcp.exe`, `wardline-verify.exe`).

---

## 1. CLI Reference (`wardline.exe`)

| Subcommand | Description | Key Flags & Defaults |
| :--- | :--- | :--- |
| `doctor` | Probe ARM64 arch (`2`), PAC/BTI (`pac_bti_available`), WoW64 emulation status, AppContainer, IOCP, and HCS support | `--json` |
| `run` | Execute native `0xAA64` (or policy opt-in `0xA641`/`0x8664`) PE inside L0/L1 containment | `--policy <PATH>` (`schemas/wardline.v1.toml`), `--pipe`, `--base-dir`, `--state-dir`, `--ticket`, `--root-pubkey`, `--cert`, `--seal-key`, `--json`, `<EXECUTABLE> [ARGS]...` |
| `fetch` | SSRF-pinned HTTP(S) fetch with optional vault injection & scrubbing | `--policy`, `--pipe`, `--base-dir`, `--state-dir`, `--method <get\|head\|post\|put\|patch\|delete>` (`get`), `--grant`, `--header`, `--body`, `--ticket`, `--root-pubkey`, `--cert`, `--seal-key`, `--json`, `<URL>` |
| `policy validate` | Parse and validate TOML v1 manifest | `--json`, `<PATH>` |
| `policy eval-fs` | Dry-run filesystem read/write evaluation | `--policy <POLICY>`, `--base-dir`, `--write`, `<PATH>` |
| `policy eval-exec` | Dry-run executable path / PE architecture evaluation | `--policy <POLICY>`, `<EXECUTABLE>` |
| `policy eval-net` | Dry-run egress URL evaluation | `--policy <POLICY>`, `--method <METHOD>` (`get`), `--grant`, `<URL>` |
| `cert keygen` | Generate Ed25519 authority keypair | `--out-seed`, `--json` |
| `cert issue` | Issue root `WardCert` delegation chain | `--seed-file`, `--holder-pubkey`, `--subject`, `--ttl-secs` (`3600`), `--isolation <l0\|l1\|l2>` (`l1`), `--arch <any\|x64\|arm64>` (`any`), `--depth` (`2`), `--scope`, `--out` |
| `cert delegate` | Offline-attenuate existing `WardCert` chain | `--seed-file`, `--parent`, `--holder-pubkey`, `--subject`, `--ttl-secs` (`1800`), `--isolation` (`l1`), `--arch` (`any`), `--scope`, `--out` |
| `cert verify` | Verify signatures, expiry, attenuation & optional CRL | `--root-pubkey`, `--cert`, `--state-dir` (`.wardline`), `--crl-db`, `--json` |
| `cert revoke` | Revoke certificate UUID in durable `redb` CRL | `--state-dir` (`.wardline`), `--crl-db`, `--cert-id`, `--reason` (`"revoked by operator"`) |
| `vault set` | Seal DPAPI + ChaCha20Poly1305 destination-bound grant | `--state-dir` (`.wardline`), `--grant-id`, `--host`, `--path-prefix` (`/`), `--header` (`Authorization`), `--value-prefix` (`"Bearer "`), `--secret` \| `--secret-env` |
| `vault list` | List vault grant metadata (never decrypts secrets) | `--state-dir` (`.wardline`), `--json` |
| `approve list` | List pending unexpired approval tickets | `--state-dir` (`.wardline`), `--json` |
| `approve grant` | Approve pending action ticket | `--state-dir` (`.wardline`), `--ticket`, `--approver` (`operator`), `--ttl-secs` |
| `approve deny` | Deny pending action ticket | `--state-dir` (`.wardline`), `--ticket`, `--approver` (`operator`) |
| `approve sweep` | Expire stale pending/approved tickets | `--state-dir` (`.wardline`) |
| `audit verify` | Verify `BLAKE3` chain and optional `Ed25519` seals | `--log`, `--seal-pubkey`, `--json` |
| `audit checkpoint` | Append explicit signed checkpoint frame to `.wlog` | `--log`, `--seal-key` |
| `audit inspect` | Decode and display recorded audit frames from a `.wlog` file | `--log`, `--json` |
| `guard-serve` | Start hardened single-instance Named Pipe daemon | `--policy` (`schemas/wardline.v1.toml`), `--pipe` (`\\.\pipe\wardline_guard`), `--base-dir`, `--state-dir`, `--root-pubkey`, `--require-cert`, `--seal-key` |
| `mcp` | Run stateless stdio JSON-RPC `2024-11-05` MCP adapter | `--pipe` (`\\.\pipe\wardline_guard`) |

---

## 2. Standalone Daemon & Verifier Binaries

- **`wardline-guard.exe`**: `--policy`, `--pipe`, `--base-dir`, `--state-dir`, `--root-pubkey`, `--require-cert`, `--seal-key`.
- **`wardline-verify.exe`**: `--log <LOG>` `[--seal-pubkey <64_HEX>] [--json]`.

---

## 3. MCP (`2024-11-05`) & Named Pipe Protocol

`wardline-mcp.exe` (`#![forbid(unsafe_code)]`) exposes 5 tools over stdio newline-delimited JSON-RPC 2.0 and forwards frames to `\\.\pipe\wardline_guard` (`[u32 LE <= 16 MiB][UTF-8 JSON]`):
- `wardline_exec` → `GuardRequest::RunTool`
- `wardline_fetch` → `GuardRequest::HttpFetch`
- `wardline_fs_read` → `GuardRequest::BrokerFileRead`
- `wardline_fs_write` → `GuardRequest::BrokerFileWrite`
- `wardline_learn` → `GuardRequest::CapabilityLearn`

---

## 4. Thin Language SDKs

- **Python**: [`clients/python/wardline_client/__init__.py`](../clients/python/wardline_client/__init__.py) (`WardlineClient`)
- **TypeScript**: [`clients/ts/src/index.ts`](../clients/ts/src/index.ts) (`WardlineClient`, `DEFAULT_PIPE_NAME`, `GuardResponse`)
