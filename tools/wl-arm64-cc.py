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
        matches = sorted(
            glob.glob(
                os.path.join(
                    local_app,
                    "Microsoft",
                    "WinGet",
                    "Packages",
                    "zig.zig*",
                    "zig-*",
                    "zig.exe",
                )
            )
        )
        if matches:
            return matches[-1]
    raise FileNotFoundError("zig.exe not found on PATH or WinGet packages directory")

def main() -> int:
    zig_exe = find_zig()
    cmd = [zig_exe, "cc", "-target", "aarch64-windows-gnu"] + sys.argv[1:]
    return subprocess.call(cmd)

if __name__ == "__main__":
    raise SystemExit(main())
