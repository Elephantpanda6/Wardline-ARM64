# Wardline Threat Model

## 1. Security Objective

Ensure that untrusted AI agents, generated tool invocations, third-party plugins, and fetched remote content cannot execute arbitrary host binaries, escape their workspace, exfiltrate host credentials, pivot into loopback/cloud metadata/LAN endpoints, or tamper undetected with the audit trail — across Windows, Linux, macOS, and FreeBSD on both ARM64 and x64.

## 2. Adversary Capabilities Assumed

1. **Prompt-injected or compromised AI caller**: Sends malicious arguments to MCP tools, SDKs, or IPC framing (`..` path traversal, NT device paths `\\?\`, symlinks/junctions, LOLBins like `powershell`/`bash`/`curl`, oversized frames, or unauthorized capability certs).
2. **Hostile child process inside sandbox**: Attempts socket dials (IPv4/IPv6/raw/Netlink), credential environment inspection, file descriptor inheritance reuse, privilege escalation (`setuid`/`sudo`/`ptrace`), or echoing secrets across stdout/stderr chunk boundaries.
3. **Hostile remote HTTP server**: Attempts DNS rebinding (`1.2.3.4` -> `127.0.0.1` or `169.254.169.254`), HTTP redirect pivoting, response-body credential reflection, or oversized response DoS.
4. **Cross-architecture evasion (ARM64 hosts)**: Attempts to spawn x64 JIT-emulated code (`0x8664` Prism / Rosetta / QEMU) to evade native PAC/BTI or ACG mitigations.
5. **Post-incident log tampering**: Edits, truncates, or reorders `.wardline/audit.wlog` frames.

## 3. Structural Defenses

| Threat Vector | Mitigation & Code Location |
|---|---|
| Ambient secret exposure in child RAM/env | Secrets live only inside `wardline-vault` (`VirtualLock`/`mlock` + zeroize-on-drop `SecretBytes`, DPAPI or `0600 WLV1`, owner-ACL `--value-file` input, atomic `rotate_master_key`); spawned children & MCP servers receive `env_clear()` + safe allowlist only; stdout/stderr and HTTP responses pass through cross-chunk `StreamingScrubber`. |
| Shell / interpreter / nested wrapper evasion | `wardline-core/src/lolbin.rs` blocks 25 Windows + 34 Unix LOLBins and 19 Win + 14 Unix script extensions; `wardline-policy/src/argv_shield.rs` recursively unwraps nested wrappers (depth 8), blocks `env -S` & inline flags, and enforces `[operator_forbid]` rules ahead of policy/cert allowlists. |
| Symlink / NTFS junction / ADS escape | `wardline-core/src/path.rs` rejects raw prefixes & `:`; `wardline-guard/src/file_broker.rs` (via `wardline-platform/src/fs_safe.rs`) walks every path segment from `base_dir` checking `FILE_ATTRIBUTE_REPARSE_POINT` (Win) or `O_NOFOLLOW` (Unix). |
| Sandbox downgrade or kernel escape | `wardline-sandbox/src/driver.rs` (`select_backend_for_tier`) fails closed on `unisolated`/`L0`/`L1`/`L1.5`/`L2`; Linux `L1` fails closed without Landlock ABI >= 1 + 22-syscall `seccomp-bpf`; Windows `L1.5` enforces Win32k & Non-MS-Binary blocks; macOS `L1.5` denies `process-fork`. |
| Sandbox network escape & SSRF | `L1` child runs with `0` AppContainer network capabilities (Windows), empty `CLONE_NEWNET` + BPF socket family filter (Linux), or Seatbelt `(deny network*)` (macOS); all egress goes through `wardline-egress` single-lookup DNS pinning, RFC 9110 validation, and durable `redb` transfer budgets. |
| Delegated cert chain replay / parent compromise | `wardline-cert` binds Ed25519 certs with embedded `lineage: Vec<Uuid>` (`MAX_CHAIN_DEPTH = 8`), rejecting any descendant cert whose root or intermediate ancestor is revoked in `CrlStore` or JSON `RevocationList`. |
| IPC hijacking & frame DoS | Windows `\\.\pipe\wardline_guard` requires `FIRST_PIPE_INSTANCE`, `REJECT_REMOTE_CLIENTS`, and user+SYSTEM SDDL; Unix UDS enforces `0600` file mode and `SO_PEERCRED`/`LOCAL_PEERCRED` peer UID equality; frames capped at `16 MiB` (IPC) / `1 MiB` (MCP JSON-RPC). |
| Cross-ISA bypass on ARM64 | `binary.rs` + Zig `engine_arm64.zig` / `engine_linux.zig` / `engine_macos.zig` enforce `StrictNative` by default and block foreign ISAs fail-closed unless explicitly opted in. |
| Audit tampering & partial execution logging | `wardline-log` locks via `LockFileEx`/`flock`, fsyncs `ActionIntent` before dispatch, guarantees `ActionOutcome` on every exit path, signs Ed25519 checkpoints, proves leaves via BLAKE3 Merkle trees, and locks down permanently via `.tainted` panic freeze (`wardline panic`). |

## 4. Verified Invariants (`I1`–`I7`, `crates/wardline-guard/tests/invariants_i1_i7.rs`)

- **I1**: Zero secret custody in child/MCP processes, cross-chunk HTTP/stream redaction, and atomic `rotate_master_key()`.
- **I2**: Fail-closed isolation tiers (`L2`/`L1.5`/`L1`/`L0`) never silently downgrade when requested.
- **I3**: 240+ adversarial bypass inputs (`cmd`/`bash`/wrappers/`env -S`/ADS/UNC/`..`/IMDS/IPv6-mapped v4/RFC 9110 smuggling) denied fail-closed.
- **I4**: Ed25519 `WardCert` depth cap (`8`) and automatic ancestor `lineage` subtree revocation across CRL stores.
- **I5**: Intent-before-dispatch ordering, `ActionOutcome` completeness on early denials, Ed25519 Merkle checkpoint verification, and irreversible `.tainted` panic freeze.
- **I6**: Sub-millisecond policy evaluation throughput + persistent `redb` egress byte/request cap enforcement across restart.
- **I7**: Monotonic session transitions (`Setup -> Run` irreversible), single-use replay-resistant HITL approvals, and IPC/`MCP` frame size caps.

## 5. Explicit Out-of-Scope / Trust Boundaries

- **Compromised host OS kernel or elevated Administrator/`root` attacker**: Wardline protects host integrity *against* sandboxed agents and untrusted inputs; it does not isolate a compromised host kernel from itself (for hostile untrusted kernels/multi-tenant workloads, `L2` hardware MicroVMs are required and fail closed today).
- **Authorized destructive actions within policy**: An action permitted by both policy and capability cert (or explicitly approved via HITL ticket) can modify permitted resources within `--base-dir`. Use HITL approvals (`require_approval = true`) and narrow capability scopes for high-risk mutations.
