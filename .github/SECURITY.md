# Security Policy (`wardline-arm64`)

## Supported Versions

| Version | Target Architecture | Supported |
| :--- | :--- | :--- |
| `0.1.x` | Windows on ARM64 (`0xAA64`) | Yes (active) |

## Security Boundaries in Scope

- **Sandbox Escape (`L0` / `L1`)**: Breakout from `AppContainer`, `JobObject`, restricted tokens (`WinLowLabelSid`), handle inheritance leaks, or desktop isolation bypasses.
- **Prism / Multi-ISA Policy Bypasses**: Any ability to spawn `0x8664` (x64) or `0xA641` (ARM64EC) binaries when `[architecture].mode = "strict_native"`, or failure to log `emulation_detected = 1`.
- **Host NTFS Broker Escape**: Symlink/junction/hardlink/ADS/canonical-path bypasses in `file_broker.rs` or bypassing `approvals.redb` write digest checks.
- **Secret Custody, SSRF & Pipe Auth**: DPAPI/ChaCha20Poly1305 vault exposure, `StreamingScrubber` bypass, SSRF/DNS rebinding, `WardCert` Ed25519 escalation, pipe squatting, or `WLG1` audit tampering.

## Out of Scope

- Attacks requiring pre-existing local Windows Administrator / `SYSTEM` (`SeDebugPrivilege`) privileges.
- `L2 MicroVM` execution (currently intentionally **fails closed** with `WL_ERR_NOT_SUPPORTED_ARCH`).

## Reporting a Vulnerability

Do **not** open public GitHub issues for unpatched vulnerabilities. Report privately via GitHub Security Advisories on [`Elephantpanda6/wardline-arm64`](https://github.com/Elephantpanda6/wardline-arm64) with reproduction steps and target PE details.
