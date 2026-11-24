#!/usr/bin/env python3
"""Exercise the Windows console UI through ConPTY.

This checks that arrow input does not terminate the prompt, that arrows
actually move a menu selection (a console in VT input mode used to deliver
them as Esc plus literal "[A"), and that the two-digit provider selection
works when arrows are unavailable.
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


def drain(proc):
    try:
        return proc.read(65536, blocking=False)
    except TypeError:
        import threading
        result = []
        t = threading.Thread(target=lambda: result.append(proc.read(65536)), daemon=True)
        t.start()
        t.join(1.0)
        return result[0] if result else ""
    except EOFError:
        return ""


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
    drain(proc)
    # Home, Down, Enter must pick provider 2 (DeepSeek account), whose
    # endpoint step prints a line no other provider prints. ConPTY only
    # repaints changed cells, so the menu text itself cannot be checked.
    for seq in ("\x1b[H", "\x1b[B", "\r"):
        proc.write(seq)
        time.sleep(0.5)
    output = drain(proc)
    if "fixed for DeepSeek account" not in output:
        print("FAIL: Home, Down, Enter did not select provider 2")
        print(output[-1500:])
        proc.terminate(force=True)
        return 1
    proc.terminate(force=True)

    proc = PtyProcess.spawn([exe, "--wizard", "--no-write"], dimensions=(40, 120))
    time.sleep(2)
    proc.write("11\r")
    time.sleep(1)
    output = drain(proc)
    if "Provider name" not in output:
        print("FAIL: typing 11 + Enter did not select Custom")
        print(output[-1000:])
        proc.terminate(force=True)
        return 1
    proc.terminate(force=True)
    print("ok: arrows survive and move the selection; 11 selected Custom")
    return 0


if __name__ == "__main__":
    sys.exit(main())
