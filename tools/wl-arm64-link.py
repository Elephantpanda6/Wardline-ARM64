import glob
import os
import shutil
import subprocess
import sys

def find_zig() -> str:
    zig = shutil.which("zig")
    if zig:
        return zig
    local_app = os.environ.get("LOCALAPPDATA", "")
    if local_app:
        pattern = os.path.join(
            local_app,
            "Microsoft",
            "WinGet",
            "Packages",
            "zig.zig*",
            "zig-*",
            "zig.exe",
        )
        matches = sorted(glob.glob(pattern))
        if matches:
            return matches[-1]
    raise FileNotFoundError("zig.exe not found on PATH or WinGet packages directory")

def transform_tokens(tokens: list[str], state: dict[str, bool]) -> list[str]:
    out: list[str] = []
    for raw in tokens:
        tok = raw.strip().strip('"').strip("'")
        if not tok or tok in ("-nolibc", "-nostartfiles", "-Wl,-O1"):
            continue
        if tok == "-Wl,-Bdynamic" and not state["inserted_unwind"]:
            out.append("-lunwind")
            state["inserted_unwind"] = True
        if tok.startswith("-Wl,") and tok.lower().endswith(".def"):
            out.append(tok[4:])
            continue
        if tok == "-lmsvcrt":
            out.append("-lucrtbase")
        elif tok == "-lsynchronization":
            out.append("-lapi-ms-win-core-synch-l1-2-0")
        elif tok.startswith("-lwindows."):
            out.extend(["-Wl,-Bstatic", tok, "-Wl,-Bdynamic"])
        else:
            out.append(tok)
    return out

def main() -> int:
    zig_exe = find_zig()
    state = {"inserted_unwind": False}
    args: list[str] = []
    for arg in sys.argv[1:]:
        if arg.startswith("@"):
            rsp_path = arg[1:]
            with open(rsp_path, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
            rewritten = transform_tokens(lines, state)
            with open(rsp_path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(rewritten) + "\n")
            args.append(arg)
        else:
            args.extend(transform_tokens([arg], state))
    cmd = [
        zig_exe,
        "cc",
        "-target",
        "aarch64-windows-gnu",
        "-Wl,--dynamicbase",
        "-Wl,--nxcompat",
        "-Wl,--high-entropy-va",
    ] + args
    return subprocess.call(cmd)

if __name__ == "__main__":
    raise SystemExit(main())
