#!/usr/bin/env python3
"""Exercise the Windows console UI through ConPTY.

This catches the two regressions users hit on Windows: arrow keys terminating
the prompt, and provider menus with more than nine entries.
"""
import glob
import sys
import time

from winpty import PtyProcess


def find_exe():
    matches = glob.glob("**/emerag-full-windows-x86_64.exe", recursive=True)
    if not matches:
        raise SystemExit("emerag-full-windows-x86_64.exe not found")
    return matches[0]


def drain(proc, rounds=4):
    out = []
    for _ in range(rounds):
        try:
            chunk = proc.read(4096)
        except EOFError:
            break
        if not chunk:
            break
        out.append(chunk)
    return "".join(out)


def main():
    exe = find_exe()
    proc = PtyProcess.spawn(
        [exe, "--base-url", "http://127.0.0.1:1/v1", "--model", "x", "--no-write"],
        dimensions=(30, 100),
    )
    time.sleep(2)
    proc.write("\x1b[A")
    time.sleep(0.3)
    proc.write("\x1b[B")
    time.sleep(0.5)
    if not proc.isalive():
        print("FAIL: arrow keys terminated the prompt")
        proc.terminate(force=True)
        return 1
    proc.write("/quit\r")
    time.sleep(0.5)
    proc.terminate(force=True)

    proc = PtyProcess.spawn([exe, "--wizard", "--no-write"], dimensions=(40, 120))
    time.sleep(2)
    initial = drain(proc)
    proc.write("\x1b[B")
    time.sleep(0.5)
    after = drain(proc)
    if "> 2." not in (initial + after):
        print("FAIL: Down arrow did not move the provider selection")
        print((initial + after)[-1000:])
        proc.terminate(force=True)
        return 1
    proc.write("11\r")
    time.sleep(1)
    selected = drain(proc)
    if "Provider name" not in selected:
        print("FAIL: typing 11 + Enter did not select Custom")
        print(selected[-1000:])
        proc.terminate(force=True)
        return 1
    proc.terminate(force=True)
    print("ok: Windows arrows and two-digit provider selection")
    return 0


if __name__ == "__main__":
    sys.exit(main())
