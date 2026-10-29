#!/usr/bin/env bash
# Report the minimum OS/kernel a built binary can run on.
# - static ELF: no interpreter, no DT_NEEDED, no glibc symbols
# - PE: imported kernel32 APIs newer than a given Windows version
# Usage: ./scripts/compat-report.sh [dist/*]
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Windows APIs introduced after Windows 2000 / XP / Vista / 7.
NEWER_THAN_XP="GetFileInformationByHandleEx|SetFileInformationByHandle|QueryFullProcessImageNameW|GetTickCount64|CreateSymbolicLinkW|InitializeConditionVariable|WakeConditionVariable|SleepConditionVariableCS|InitializeSRWLock|AcquireSRWLockExclusive|CreateThreadpoolWork|GetSystemTimePreciseAsFileTime|SetThreadDescription|GetActiveProcessorCount|GetLogicalProcessorInformationEx|CancelIoEx|GetFinalPathNameByHandleW|SetDefaultDllDirectories|AddDllDirectory|GetCurrentThreadStackLimits|CompareObjectHandles|GetPackageFamilyName|CreatePseudoConsole"
NEWER_THAN_7="GetSystemCpuSetInformation|SetThreadDescription|GetMachineTypeAttributes|RtlGetVersion|CreateFile2|GetOverlappedResultEx|WaitOnAddress|WakeByAddressSingle|PrefetchVirtualMemory|DiscardVirtualMemory"

report_elf() {
  bin="$1"
  echo "--- $bin"
  file "$bin" || true
  echo "size: $(wc -c < "$bin") bytes"
  if command -v readelf >/dev/null 2>&1; then
    interp=$(readelf -l "$bin" 2>/dev/null | grep -c 'INTERP' || true)
    echo "PT_INTERP segments: $interp (0 = static)"
    needed=$(readelf -d "$bin" 2>/dev/null | grep -c NEEDED || true)
    echo "DT_NEEDED: $needed (0 = no shared libs)"
  fi
  if command -v objdump >/dev/null 2>&1; then
    n=$(objdump -T "$bin" 2>/dev/null | grep -c 'GLIBC_' || true)
    echo "GLIBC_ symbol references: $n (0 = not glibc)"
  fi
}

report_pe() {
  bin="$1"
  echo "--- $bin"
  file "$bin" || true
  echo "size: $(wc -c < "$bin") bytes"
  if command -v objdump >/dev/null 2>&1; then
    imports=$(objdump -p "$bin" 2>/dev/null | sed -n 's/^\s*DLL Name: //p' | tr '\n' ' ')
    echo "DLL imports: $imports"
    hits=$(objdump -p "$bin" 2>/dev/null | grep -Eo "$NEWER_THAN_XP" | sort -u | tr '\n' ' ')
    echo "APIs newer than XP: ${hits:-none}"
    hits7=$(objdump -p "$bin" 2>/dev/null | grep -Eo "$NEWER_THAN_7" | sort -u | tr '\n' ' ')
    echo "APIs newer than Windows 7: ${hits7:-none}"
  fi
}

shopt -s nullglob
files=("$@")
if [ ${#files[@]} -eq 0 ]; then
  files=("$ROOT"/dist/*)
fi
for f in "${files[@]}"; do
  case "$f" in
    *.exe) report_pe "$f" ;;
    *linux*|*musl*) report_elf "$f" ;;
    *) report_elf "$f" 2>/dev/null || true ;;
  esac
done
