# Wardline Policy Schema v1 Reference

Wardline policies are declarative TOML manifests compiled by `wardline-policy` (`schemas/wardline.v1.toml`). Anything not explicitly permitted is denied fail-closed.

## 1. Execution, Operator Guardrails & Isolation (`[operator_forbid]`, `[architecture]`, `[execution]`)

```toml
version = 1
name = "arm64-cloud-server"

# Immutable operator guardrails evaluated BEFORE allowlists or WardCert scopes
[operator_forbid]
binaries = ["sudo", "doas", "pkexec", "passwd", "mkfs"]
hosts = ["169.254.169.254", "metadata.google.internal"]
paths = ["~/.ssh/**", "~/.aws/**"]

[architecture]
mode = "strict_native"               # "strict_native" | "allow_arm64ec" | "allow_prism_x64"

[execution]
isolation = "L1"                     # "unisolated" | "L0" | "L1" | "L1.5" | "L2" (fail-closed; never downgrades)
working_dir = "."
inherit_env = false
allowed_env = ["PATH", "HOME", "LANG", "LC_ALL"]
deny_scripts = true                  # Blocks 19 Win + 14 Unix script extensions
deny_lolbins = true                  # Blocks 25 Win + 34 Unix LOLBins
allow_binaries = []                  # Optional strict executable basename/version-tolerant allowlist
allow_inline_shell = false           # Blocks -c / -e / -m / inline interpreter execution by default
timeout_ms = 60000
max_memory_mb = 2048
max_processes = 32
cpu_rate_percent = 80
acg = true
cet_shadow_stack = false
```

### Architecture Policies (`[architecture].mode`)
- **`strict_native`** (default):
  - Windows ARM64: allows `0xAA64` (`PE`) only.
  - Linux ARM64: allows native `AArch64` ELF only (rejects binfmt x64 translation and non-ELF images).
  - macOS Apple Silicon: allows `ARM64` native Mach-O or Universal Fat binary containing an `ARM64` slice.
  - FreeBSD ARM64: allows native `EM_AARCH64` ELF.
  - x64 hosts: allows native `0x8664` PE / `EM_X86_64` ELF / `X86_64` Mach-O only.
- **`allow_arm64ec`**: Windows ARM64 opt-in permitting `0xA641` ARM64EC binaries with native ACG enabled.
- **`allow_prism_x64`**: Opt-in permitting x64 emulation on ARM64 hosts (Prism on Windows with ACG automatically suppressed to avoid JIT `STATUS_DYNAMIC_CODE_BLOCKED`, Rosetta 2 on macOS, or qemu-user/binfmt on Linux).

### Isolation Tiers (`[execution].isolation`)
- **`unisolated`**: Explicit zero-kernel mode (opt-in only; refuses silent downgrade from higher tiers).
- **`L0`**: Restricted token + Low integrity (Windows) or `PR_SET_NO_NEW_PRIVS` + `PR_SET_DUMPABLE=0` + `rlimit` (POSIX).
- **`L1`** (default):
  - Windows ARM64: `AppContainer` (zero network capabilities) + Hardened `JobObject` + `CREATE_SUSPENDED` + `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` + Win32 process mitigations + IOCP reaper.
  - Linux ARM64: `UserNS` + `NetNS` + `IPC` + `UTS` + `PR_SET_NO_NEW_PRIVS` + fail-closed Landlock LSM (`abi >= 1`) + 22-syscall `AUDIT_ARCH_AARCH64` `seccomp-bpf` + `cgroup v2`.
  - macOS Apple Silicon: Seatbelt SBPL default-deny profile with network disabled.
  - FreeBSD ARM64: Capsicum `cap_enter()` capability mode + `fexecve()`.
- **`L1.5`**:
  - Windows ARM64: `L1` plus `MITIGATION_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON` & `MITIGATION_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON`.
  - Linux ARM64: Rootless zero-NIC `gVisor` `runsc` OCI containment.
  - macOS Apple Silicon: Seatbelt SBPL plus `(deny process-fork)`.
- **`L2`**: Hardware microVM (`Hyper-V HCS` / `Firecracker` / Apple `Virtualization.framework` / `bhyve`); fails closed when hypervisor or signed golden guest image is absent.

## 2. Filesystem, Egress Aliases, Sessions & HITL Approvals

```toml
[filesystem]
workspace_read = ["."]
workspace_write = ["./out"]
denied_prefixes = []
workspace_mode = "in_place"          # "in_place" | "session-copy"

[network]
egress_mode = "proxy_only"           # "blocked" | "proxy_only" | "direct_allowed"
allow_ipv6 = false
allow_private_ips = false
allow_metadata_ips = false
allowed_destinations = ["https://api.github.com/**"]

[[network.destinations]]
alias = "github_ro"
host = "api.github.com"
methods = ["GET", "HEAD"]
paths = ["/repos/**"]
bind_grant = "github_api"
max_bytes_total = 10485760
max_requests = 100

[approvals]
require_on_write = true
require_on_network_post = true
default_ttl_secs = 300

[[approvals.require_for]]
action = "exec"
binaries = ["git", "cargo"]
reason = "Require HITL approval for vcs/build operations"

[session.setup]
egress_mode = "proxy_only"
allow_binaries = ["cargo"]

[session.run]
egress_mode = "blocked"              # One-way Setup -> Run transition cannot reopen blocked egress
```

Device-class templates in [`schemas/profiles/`](../schemas/profiles/):
- `arm64-laptop.toml` — Copilot+ / Apple Silicon developer workstation profile
- `arm64-server.toml` — Neoverse / Graviton / Ampere / Grace cloud runner profile
- `arm64-edge-sbc.toml` — Tight memory/process-capped ARM64 SBC / robotics gateway profile
- `x64-workstation.toml` — Developer workstation x64 profile
- `x64-server.toml` — Hardened x64 Linux/Windows server runner profile

## 3. Built-In Anti-LOLBin, Wrapper Unwrapping & Path Shield

- **Recursive Wrapper Defense (`argv_shield.rs`)**: Unwraps nested `env`, `timeout`, `nice`, `nohup`, `stdbuf`, `sudo`, `doas`, and `busybox` invocations up to 8 layers deep, blocks `env -S` / `--split-string`, blocks inline `-c`/`-e`/`python -m`/`awk` execution (`allow_inline_shell = false`), enforces RFC 9110 HTTP method/target validation, and matches binary names version-tolerantly (`python3.12` matches `python3` without prefix confusion).

- **Windows LOLBins blocked (25 executables / 50 patterns)**: `cmd`, `powershell`, `pwsh`, `wscript`, `cscript`, `mshta`, `rundll32`, `regsvr32`, `certutil`, `bitsadmin`, `wmic`, `msiexec`, `installutil`, `msbuild`, `wsl`, `bash`, `reg`, `sc`, `schtasks`, `forfiles`, `pcalua`, `syncappvpublishingserver`, `control`, `cmstp`, `odbcconf` (and native `.exe` / System32/SysWOW64/Sysnative variants).
- **Windows script extensions blocked (19)**: `.bat`, `.cmd`, `.ps1`, `.psm1`, `.psd1`, `.vbs`, `.vbe`, `.js`, `.jse`, `.wsf`, `.wsh`, `.hta`, `.sct`, `.scr`, `.pif`, `.lnk`, `.inf`, `.reg`, `.msc`.
- **Unix LOLBins blocked (34)**: `sh`, `dash`, `bash`, `zsh`, `ksh`, `csh`, `tcsh`, `fish`, `ash`, `busybox`, `curl`, `wget`, `fetch`, `nc`, `ncat`, `netcat`, `socat`, `telnet`, `ssh`, `scp`, `sftp`, `rsync`, `python`, `python2`, `python3`, `perl`, `ruby`, `php`, `lua`, `awk`, `gawk`, `nawk`, `mawk`, `osascript`.
- **Unix script extensions blocked (14)**: `.sh`, `.bash`, `.zsh`, `.ksh`, `.csh`, `.fish`, `.command`, `.py`, `.pl`, `.rb`, `.php`, `.lua`, `.scpt`, `.applescript`.
- **Path normalization (`path.rs`)**: Rejects `..` parent escapes, NUL bytes, NT device prefixes (`\\?\`, `\\.\`, `\??\`), UNC shares, and NTFS Alternate Data Streams (`:`).
