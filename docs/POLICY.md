# Wardline (`win-arm64`) — Policy Manifest & WardCert Reference

Wardline enforces two authorization boundaries: the host's declarative TOML v1 manifest ([`schemas/wardline.v1.toml`](../schemas/wardline.v1.toml)) and dynamic **Ed25519 `WardCertChain`** capability tokens (`--arch arm64`).

---

## 1. Policy Manifest Schema (`v1`)

```toml
version = 1
name = "default-windows-sandbox"

[architecture]
# "strict_native"  — allow 0xAA64 (ARM64) only
# "allow_arm64ec"  — allow 0xAA64 + 0xA641 (ARM64EC)
# "allow_prism_x64"— allow 0x8664 under Prism emulation (suppresses ACG on emulated child)
mode = "strict_native"

[execution]
isolation = "L1"
working_dir = "."
inherit_env = false
allowed_env = ["PATH", "SystemRoot", "TEMP", "TMP"]
deny_scripts = true
deny_lolbins = true
timeout_ms = 30000
max_memory_mb = 512
max_processes = 16
cpu_rate_percent = 50
acg = true
cet_shadow_stack = true

[filesystem]
workspace_read = ["."]
workspace_write = []
denied_prefixes = [
    "C:\\Windows\\System32\\config",
    "\\\\?\\",
    "\\\\",
]

[network]
egress_mode = "proxy_only"
allow_ipv6 = false
allow_private_ips = false
allow_metadata_ips = false
allowed_destinations = [
    "https://api.github.com/**",
]

[credentials]
allowed_grants = []
max_bytes_per_request = 1048576

[approvals]
require_on_write = true
require_on_network_post = true
default_ttl_secs = 300

[audit]
log_path = ".wardline/audit.wlog"
lock_mode = "exclusive_blocking"
seal_interval_events = 64
```

### Key `win-arm64` Behavioral Notes

- **`[architecture].mode`**:
  - `"strict_native"` (recommended): rejects `ARM64EC` (`0xA641`, `WL_ERR_PE_DISALLOWED_ARCH`) and `AMD64` (`0x8664`, `WL_ERR_PRISM_BLOCKED`).
  - `"allow_arm64ec"`: permits `0xAA64` + `0xA641` with ACG still active.
  - `"allow_prism_x64"`: permits `0x8664` under Prism emulation while automatically suppressing ACG (`PROHIBIT_DYNAMIC_CODE_ALWAYS_ON`) on emulated child processes so Prism JIT code pages do not fault (`STATUS_DYNAMIC_CODE_BLOCKED`).
- **`[execution].cet_shadow_stack`**: Schema field shared across v1 manifests; ignored/reported as unsupported on ARM64 where `cet_shadow_stack_supported = 0`. Use `wardline doctor --json` to inspect `pac_bti_available` instead.
- **`[execution].deny_lolbins` & `deny_scripts`**: Blocks 25 Windows LOLBins (50 binary/bare patterns) and 19 script extensions regardless of host ISA.
- **`[filesystem]`, `[network]`, `[credentials]`, `[approvals]`, `[audit]`**: Enforced identically to `win-x64` inside `wardline-guard.exe`.

---

## 2. `WardCert` Capability Scopes & Monotonic Attenuation

Scopes use identical prefix syntax:
- `fs-read:<path>`
- `fs-write:<path>`
- `fs-delete:<path>`
- `exec:<binary>`
- `net:<host>[:/path]`
- `vault:<grant_id>`

When issuing or delegating certs for ARM64 hosts, pass `--arch arm64` so certificates cannot drift across processor architectures, and `validate_monotonic_attenuation()` guarantees child chains strictly narrow or preserve expiry, isolation tier (`l0`/`l1`/`l2`), arch constraint, depth, and scope sets.

---

## 3. Dry-Run Policy Evaluation Commands

```powershell
$cli = ".\target\aarch64-pc-windows-gnullvm\release\wardline.exe"

$cli policy validate .\schemas\wardline.v1.toml --json
$cli policy eval-fs --policy .\schemas\wardline.v1.toml src\main.rs
$cli policy eval-net --policy .\schemas\wardline.v1.toml https://api.github.com/zen
```
