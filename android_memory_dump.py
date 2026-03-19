#!/usr/bin/env python3
"""
android_memory_dump.py
======================
Forensic memory acquisition from a rooted Android device over ADB.

Acquisition methods (tried in order of completeness):
  1. LiME (Linux Memory Extractor) – full physical RAM via kernel module
  2. /proc/kcore                    – full kernel address-space view
  3. /proc/<pid>/mem                – per-process virtual memory
  4. /dev/mem                       – physical memory (legacy, often restricted)

Requirements (workstation):
  pip install tqdm

Requirements (device):
  - ADB accessible (USB or TCP)
  - Root shell (adb root, Magisk su, or equivalent)
  - Optional: LiME .ko for the device kernel (enables full RAM dump)

Usage:
  # Full RAM dump via LiME
  python android_memory_dump.py --method lime --lime-ko lime.ko --output /cases/ram.lime

  # Kernel address space via /proc/kcore
  python android_memory_dump.py --method kcore --output /cases/kcore.bin

  # All processes named "signal"
  python android_memory_dump.py --method process --proc signal --output /cases/signal/

  # Specific PID
  python android_memory_dump.py --method process --pid 1234 --output /cases/pid1234/

  # Dump process + parse for SQLCipher / AES keys in output
  python android_memory_dump.py --method process --proc chrome --output /cases/ --search-keys
"""

import argparse
import os
import re
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    print("[!] tqdm not found – install with 'pip install tqdm' for progress bars")

# ─── ADB wrapper ─────────────────────────────────────────────────────────────

class ADB:
    def __init__(self, serial: Optional[str] = None):
        self.serial = serial
        self._prefix = ["adb"] + (["-s", serial] if serial else [])

    def _run(self, args: list, timeout=30, check=True) -> subprocess.CompletedProcess:
        cmd = self._prefix + args
        return subprocess.run(cmd, capture_output=True, timeout=timeout, check=check)

    def shell(self, cmd: str, timeout=60, su=True) -> bytes:
        """Run a shell command as root. Returns stdout bytes."""
        if su:
            cmd = f"su -c '{cmd}'"
        result = self._run(["shell", cmd], timeout=timeout, check=False)
        return result.stdout

    def shell_str(self, cmd: str, **kw) -> str:
        return self.shell(cmd, **kw).decode("utf-8", errors="replace").strip()

    def pull(self, remote: str, local: str, timeout=600):
        self._run(["pull", remote, local], timeout=timeout)

    def push(self, local: str, remote: str, timeout=120):
        self._run(["push", local, remote], timeout=timeout)

    def devices(self) -> list[str]:
        out = subprocess.check_output(["adb", "devices"]).decode()
        lines = out.strip().splitlines()[1:]
        return [l.split()[0] for l in lines if "device" in l]

    def ensure_root(self) -> bool:
        """Try adb root; fall back to checking su availability."""
        try:
            self._run(["root"], timeout=10)
            time.sleep(1)
        except Exception:
            pass
        whoami = self.shell_str("whoami", su=False)
        if "root" in whoami:
            return True
        # Try via su
        whoami = self.shell_str("id", su=True)
        return "uid=0" in whoami

    def get_device_info(self) -> dict:
        props = {}
        for prop in ["ro.product.model", "ro.build.version.release",
                     "ro.product.manufacturer", "ro.build.fingerprint",
                     "ro.product.cpu.abi"]:
            props[prop] = self.shell_str(f"getprop {prop}", su=False)
        return props

    def total_ram_kb(self) -> int:
        line = self.shell_str("cat /proc/meminfo | grep MemTotal", su=False)
        m = re.search(r"(\d+)", line)
        return int(m.group(1)) if m else 0

    def stream_pull(self, remote_cmd: str, local_path: str,
                    total_bytes: int = 0, label: str = ""):
        """
        Execute remote_cmd on device and pipe stdout directly to local_path.
        Uses 'adb exec-out' for raw binary streaming (no base64 overhead).
        """
        cmd = self._prefix + ["exec-out", f"su -c '{remote_cmd}'"]
        with open(local_path, "wb") as out_f:
            proc = subprocess.Popen(cmd, stdout=out_f, stderr=subprocess.DEVNULL)
            if HAS_TQDM and total_bytes:
                with tqdm(total=total_bytes, unit="B", unit_scale=True,
                          desc=label, dynamic_ncols=True) as bar:
                    while proc.poll() is None:
                        try:
                            written = out_f.tell()
                            bar.n = written
                            bar.refresh()
                        except Exception:
                            pass
                        time.sleep(0.5)
                    bar.n = out_f.tell()
                    bar.refresh()
            else:
                proc.wait()
        return proc.returncode

# ─── Memory map parser ────────────────────────────────────────────────────────

@dataclass
class MemRegion:
    start:  int
    end:    int
    perms:  str
    offset: int
    dev:    str
    inode:  int
    name:   str = ""

    @property
    def size(self) -> int:
        return self.end - self.start

    @property
    def readable(self) -> bool:
        return "r" in self.perms

    def __str__(self):
        name = self.name or "[anonymous]"
        return (f"  {self.start:016x}-{self.end:016x}  {self.perms}  "
                f"{self.size // 1024:>8} KB  {name}")


def parse_maps(maps_text: str) -> list[MemRegion]:
    regions = []
    for line in maps_text.splitlines():
        # Format: addr_range perms offset dev inode [name]
        m = re.match(
            r"([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+([0-9a-f]+)\s+(\S+)\s+(\d+)\s*(.*)",
            line.strip()
        )
        if m:
            regions.append(MemRegion(
                start=int(m.group(1), 16),
                end=int(m.group(2), 16),
                perms=m.group(3),
                offset=int(m.group(4), 16),
                dev=m.group(5),
                inode=int(m.group(6)),
                name=m.group(7).strip(),
            ))
    return regions

# ─── Key-pattern scanner ──────────────────────────────────────────────────────

# Patterns for interesting forensic artefacts in raw memory
KEY_PATTERNS = {
    "AES-256 key candidate (32 bytes, high entropy)": None,   # entropy-based
    "SQLCipher hex passphrase (64 hex chars)": rb"[0-9a-fA-F]{64}",
    "SQLCipher passphrase quote":               rb"PRAGMA key\s*=\s*['\"][^'\"]{8,}['\"]",
    "v10/v11 Chrome blob":                      rb"v1[01].{12}",    # prefix + 12-byte nonce
    "AES-GCM nonce candidate":                  None,
    "JWT token":                                rb"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}",
    "Private key PEM":                          rb"-----BEGIN (RSA |EC |)PRIVATE KEY-----",
    "Signal identity key (base64, 44 chars)":   rb"[A-Za-z0-9+/]{43}=",
}

COMPILED = {k: re.compile(v, re.DOTALL) for k, v in KEY_PATTERNS.items() if v}


def scan_buffer(buf: bytes, region: MemRegion) -> list[dict]:
    hits = []
    for label, pat in COMPILED.items():
        for m in pat.finditer(buf):
            hits.append({
                "label":  label,
                "offset": region.start + m.start(),
                "value":  m.group(0)[:256],
            })
    # High-entropy 32-byte blocks (AES key heuristic)
    for i in range(0, len(buf) - 32, 4):
        chunk = buf[i:i+32]
        entropy = _shannon(chunk)
        if entropy > 7.5:
            hits.append({
                "label":  "High-entropy 32-byte block (AES key?)",
                "offset": region.start + i,
                "value":  chunk,
            })
    return hits


def _shannon(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    import math
    return -sum((f / n) * math.log2(f / n) for f in freq if f)


def print_hit(hit: dict):
    val = hit["value"]
    if isinstance(val, bytes):
        display = val.hex() if all(b < 32 or b > 126 for b in val) else val.decode("latin-1")
    else:
        display = str(val)
    print(f"    [{hit['label']}]  @ 0x{hit['offset']:016x}")
    print(f"      {display[:120]}")

# ─── Acquisition methods ──────────────────────────────────────────────────────

class MemoryDumper:
    def __init__(self, adb: ADB, output_dir: str):
        self.adb = adb
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ── Method 1: LiME ───────────────────────────────────────────────────────

    def dump_lime(self, lime_ko: str, format: str = "lime") -> Optional[str]:
        """
        Load LiME kernel module and acquire full physical RAM.

        LiME formats: lime (with ELF-style segment headers) or raw (plain binary).

        Produces a .lime file compatible with Volatility / rekall.
        """
        info = self.adb.get_device_info()
        ram_kb = self.adb.total_ram_kb()
        print(f"\n[LiME] Device : {info.get('ro.product.model', '?')}")
        print(f"[LiME] Android: {info.get('ro.build.version.release', '?')}")
        print(f"[LiME] RAM    : {ram_kb // 1024} MB")
        print(f"[LiME] ABI    : {info.get('ro.product.cpu.abi', '?')}")

        if not os.path.isfile(lime_ko):
            print(f"[-] LiME module not found: {lime_ko}")
            print("    Build LiME for the target kernel:")
            print("    https://github.com/504ensicsLabs/LiME")
            return None

        remote_ko = "/data/local/tmp/lime.ko"
        print(f"\n[LiME] Pushing module to device…")
        self.adb.push(lime_ko, remote_ko)
        self.adb.shell(f"chmod 644 {remote_ko}")

        remote_dump = "/data/local/tmp/ram.lime"
        out_local = str(self.output_dir / "ram.lime")

        print(f"[LiME] Loading module and dumping RAM to {remote_dump}…")
        print(f"       (this may take several minutes for large RAM)")

        # insmod with path= pointing to on-device file, format=lime|raw
        load_cmd = f"insmod {remote_ko} 'path={remote_dump} format={format}'"
        self.adb.shell(load_cmd, timeout=600)

        # Wait for dump to complete
        print("[LiME] Waiting for dump to finish…")
        for _ in range(120):
            time.sleep(2)
            size = self.adb.shell_str(f"stat -c %s {remote_dump} 2>/dev/null")
            if size.isdigit() and int(size) > 1024 * 1024:
                # Check if insmod has finished (module unloaded automatically)
                lsmod = self.adb.shell_str("lsmod | grep lime")
                if not lsmod:
                    break
            print(".", end="", flush=True)
        print()

        print(f"[LiME] Pulling dump to {out_local}…")
        self.adb.stream_pull(f"cat {remote_dump}", out_local,
                             total_bytes=ram_kb * 1024, label="RAM dump")

        # Cleanup
        self.adb.shell(f"rm -f {remote_ko} {remote_dump}")
        print(f"[LiME] Done: {out_local}")
        self._print_lime_stats(out_local)
        return out_local

    def _print_lime_stats(self, path: str):
        """Parse LiME header to show segment info."""
        LIME_MAGIC = 0x4C694D45   # 'LiME'
        size = os.path.getsize(path)
        print(f"\n[LiME] File size: {size // (1024*1024)} MB  ({size} bytes)")
        try:
            with open(path, "rb") as f:
                seg = 0
                total = 0
                while True:
                    hdr = f.read(32)
                    if len(hdr) < 32:
                        break
                    magic, ver, s_start, s_end, reserved = struct.unpack("<IQQQQ", hdr[:36][:32])
                    # LiME v1 header: magic(4) ver(4) s_start(8) s_end(8) reserved(8)
                    magic, ver, s_start, s_end = struct.unpack("<IIQQ", hdr[:24])
                    if magic != LIME_MAGIC:
                        break
                    seg_size = s_end - s_start + 1
                    print(f"  Segment {seg}: 0x{s_start:016x} – 0x{s_end:016x}  "
                          f"({seg_size // (1024*1024)} MB)")
                    f.seek(seg_size, 1)
                    total += seg_size
                    seg += 1
                print(f"  Total physical RAM captured: {total // (1024*1024)} MB across {seg} segments")
        except Exception as e:
            print(f"  (could not parse LiME headers: {e})")

    # ── Method 2: /proc/kcore ─────────────────────────────────────────────────

    def dump_kcore(self, max_gb: int = 8) -> Optional[str]:
        """
        Acquire memory via /proc/kcore (ELF core dump of kernel address space).
        Requires root.  On modern kernels CONFIG_PROC_KCORE must be enabled.
        """
        print("\n[kcore] Checking /proc/kcore availability…")
        size_str = self.adb.shell_str("ls -la /proc/kcore")
        print(f"  {size_str}")

        readable = self.adb.shell_str("dd if=/proc/kcore bs=4096 count=1 2>/dev/null | wc -c")
        if readable.strip() == "0":
            print("[-] /proc/kcore is not readable (CONFIG_PROC_KCORE disabled or permission denied)")
            return None

        out_local = str(self.output_dir / "kcore.bin")
        max_bytes = max_gb * 1024 * 1024 * 1024
        ram_kb = self.adb.total_ram_kb()

        print(f"[kcore] Streaming /proc/kcore (capped at {max_gb} GB)…")
        # dd with bs=4M for speed, skip unreadable blocks with conv=noerror,sync
        cmd = f"dd if=/proc/kcore bs=4M count={max_bytes // (4*1024*1024)} conv=noerror,sync 2>/dev/null"
        self.adb.stream_pull(cmd, out_local,
                             total_bytes=ram_kb * 1024, label="kcore")
        print(f"[kcore] Done: {out_local}  ({os.path.getsize(out_local) // (1024*1024)} MB)")
        return out_local

    # ── Method 3: /proc/<pid>/mem ─────────────────────────────────────────────

    def list_processes(self, name_filter: str = "") -> list[dict]:
        """Return [{pid, name, cmdline}, …] optionally filtered by name."""
        ps = self.adb.shell_str("ps -A -o PID,NAME,CMD 2>/dev/null || ps 2>/dev/null")
        procs = []
        for line in ps.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 2:
                continue
            pid_s, *rest = parts
            pname = rest[0] if rest else ""
            cmdline = " ".join(rest)
            if not pid_s.isdigit():
                continue
            if name_filter and name_filter.lower() not in cmdline.lower():
                continue
            procs.append({"pid": int(pid_s), "name": pname, "cmdline": cmdline})
        return procs

    def dump_process(self, pid: int, search_keys: bool = False) -> Optional[str]:
        """
        Dump all readable virtual memory regions of a process via /proc/<pid>/mem.
        Writes one file per region + a maps file.
        """
        proc_dir = self.output_dir / f"pid_{pid}"
        proc_dir.mkdir(exist_ok=True)

        # Fetch process name
        pname = self.adb.shell_str(f"cat /proc/{pid}/cmdline 2>/dev/null").replace("\x00", " ").strip()
        if not pname:
            pname = self.adb.shell_str(f"cat /proc/{pid}/comm 2>/dev/null").strip()
        print(f"\n[proc] PID {pid} – {pname or '?'}")

        # Read memory map
        maps_raw = self.adb.shell_str(f"cat /proc/{pid}/maps")
        if not maps_raw:
            print(f"  [-] Cannot read /proc/{pid}/maps (permission denied?)")
            return None

        maps_file = proc_dir / "maps.txt"
        maps_file.write_text(maps_raw)
        regions = parse_maps(maps_raw)
        readable = [r for r in regions if r.readable and r.size > 0]

        print(f"  Total regions : {len(regions)}")
        print(f"  Readable      : {len(readable)}")
        total_sz = sum(r.size for r in readable)
        print(f"  Total size    : {total_sz // (1024*1024)} MB")
        print(f"  Output dir    : {proc_dir}")

        if search_keys:
            print(f"\n  [scan] Key pattern search enabled")

        all_hits = []

        for r in readable:
            label = (r.name or "anon").replace("/", "_").replace(" ", "_")[:60]
            out_file = proc_dir / f"{r.start:016x}-{r.end:016x}_{label}.bin"

            # Use dd to read the exact region from /proc/<pid>/mem
            skip = r.start // 512    # dd skip in blocks of 512
            count = r.size // 512 + 1
            cmd = (f"dd if=/proc/{pid}/mem bs=512 "
                   f"skip={skip} count={count} 2>/dev/null")

            self.adb.stream_pull(cmd, str(out_file), label=label)

            written = out_file.stat().st_size
            if written == 0:
                out_file.unlink(missing_ok=True)
                continue

            if search_keys:
                try:
                    data = out_file.read_bytes()
                    hits = scan_buffer(data, r)
                    if hits:
                        print(f"\n  [!] {len(hits)} hit(s) in {r.name or 'anon'} "
                              f"(0x{r.start:x}–0x{r.end:x}):")
                        for h in hits[:20]:   # cap noisy output
                            print_hit(h)
                        all_hits.extend(hits)
                except Exception:
                    pass

        if search_keys and all_hits:
            hits_file = proc_dir / "key_hits.txt"
            with open(hits_file, "w") as f:
                for h in all_hits:
                    val = h["value"]
                    if isinstance(val, bytes):
                        val = val.hex()
                    f.write(f"0x{h['offset']:016x}  [{h['label']}]  {val[:256]}\n")
            print(f"\n  [scan] {len(all_hits)} total hits written to {hits_file}")

        print(f"\n[proc] PID {pid} dump complete.")
        return str(proc_dir)

    # ── Method 4: /dev/mem ────────────────────────────────────────────────────

    def dump_devmem(self, start: int = 0, length_mb: int = 512) -> Optional[str]:
        """
        Dump physical memory via /dev/mem.
        Restricted on kernels with CONFIG_STRICT_DEVMEM (most Android kernels ≥ 4.x).
        """
        print("\n[devmem] Checking /dev/mem…")
        check = self.adb.shell_str("ls -la /dev/mem")
        if "No such" in check or not check:
            print("  [-] /dev/mem not present on this device")
            return None

        # Try reading first 4 KB
        test = self.adb.shell_str("dd if=/dev/mem bs=4096 count=1 2>&1 | wc -c")
        if test.strip() in ("0", ""):
            print("  [-] /dev/mem read blocked (CONFIG_STRICT_DEVMEM active)")
            return None

        out_local = str(self.output_dir / "devmem.bin")
        count = (length_mb * 1024 * 1024) // 4096
        cmd = f"dd if=/dev/mem bs=4096 count={count} skip={start // 4096} conv=noerror,sync 2>/dev/null"
        print(f"[devmem] Reading {length_mb} MB from offset 0x{start:x}…")
        self.adb.stream_pull(cmd, out_local,
                             total_bytes=length_mb * 1024 * 1024, label="/dev/mem")
        print(f"[devmem] Done: {out_local}")
        return out_local


# ─── Report ───────────────────────────────────────────────────────────────────

def write_report(output_dir: str, info: dict, method: str, dump_path: str):
    report = Path(output_dir) / "acquisition_report.txt"
    with open(report, "w") as f:
        f.write("Android Memory Acquisition Report\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Timestamp  : {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n")
        f.write(f"Method     : {method}\n")
        f.write(f"Output     : {dump_path}\n\n")
        f.write("Device Info\n" + "-" * 40 + "\n")
        for k, v in info.items():
            f.write(f"  {k:<35} {v}\n")
    print(f"\n[*] Report written to: {report}")


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Forensic memory acquisition from a rooted Android device.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--serial", "-s", help="ADB device serial (omit for single device)")
    parser.add_argument("--output", "-o", required=True, help="Output directory or file path")
    parser.add_argument("--method", "-m",
                        choices=["lime", "kcore", "process", "devmem", "auto"],
                        default="auto",
                        help="Acquisition method (default: auto)")

    # LiME options
    parser.add_argument("--lime-ko", metavar="FILE",
                        help="Path to LiME .ko module compiled for device kernel")
    parser.add_argument("--lime-format", choices=["lime", "raw"], default="lime",
                        help="LiME output format (default: lime)")

    # Process options
    parser.add_argument("--proc", metavar="NAME",
                        help="Process name filter (substring match)")
    parser.add_argument("--pid", type=int, metavar="PID",
                        help="Specific process PID to dump")
    parser.add_argument("--list-procs", action="store_true",
                        help="List running processes and exit")
    parser.add_argument("--all-procs", action="store_true",
                        help="Dump all running processes")

    # /dev/mem options
    parser.add_argument("--devmem-offset", type=lambda x: int(x, 0), default=0,
                        help="Physical offset for /dev/mem dump (default: 0)")
    parser.add_argument("--devmem-size", type=int, default=512,
                        help="Size in MB for /dev/mem dump (default: 512)")

    # /proc/kcore options
    parser.add_argument("--kcore-max-gb", type=int, default=8,
                        help="Max GB to read from /proc/kcore (default: 8)")

    # Scanner
    parser.add_argument("--search-keys", action="store_true",
                        help="Scan dumped memory for SQLCipher keys, AES keys, etc.")

    args = parser.parse_args()

    # ── Connect ──────────────────────────────────────────────────────────────
    adb = ADB(serial=args.serial)
    devices = adb.devices()
    if not devices:
        print("[-] No ADB devices found. Check USB connection and 'adb devices'.")
        sys.exit(1)
    print(f"[*] Connected: {devices}")

    if not adb.ensure_root():
        print("[-] Cannot obtain root shell. Ensure the device is rooted and")
        print("    'adb root' works or Magisk is installed.")
        sys.exit(1)
    print("[+] Root shell confirmed")

    info = adb.get_device_info()
    for k, v in info.items():
        print(f"    {k}: {v}")

    dumper = MemoryDumper(adb, args.output)

    # ── List processes ────────────────────────────────────────────────────────
    if args.list_procs:
        procs = dumper.list_processes()
        print(f"\n{'PID':>7}  {'NAME':<30}  CMDLINE")
        print("-" * 80)
        for p in procs:
            print(f"{p['pid']:>7}  {p['name'][:30]:<30}  {p['cmdline'][:60]}")
        return

    # ── Dispatch ──────────────────────────────────────────────────────────────
    method  = args.method
    result  = None

    if method == "auto":
        # Try LiME first, fall back to kcore, then per-process
        if args.lime_ko and os.path.isfile(args.lime_ko):
            method = "lime"
        else:
            print("[auto] No LiME module supplied – checking /proc/kcore…")
            check = adb.shell_str("dd if=/proc/kcore bs=4096 count=1 2>/dev/null | wc -c")
            method = "kcore" if check.strip() not in ("0", "") else "process"
            print(f"[auto] Selected method: {method}")

    if method == "lime":
        if not args.lime_ko:
            print("[-] --lime-ko required for LiME method")
            sys.exit(1)
        result = dumper.dump_lime(args.lime_ko, args.lime_format)

    elif method == "kcore":
        result = dumper.dump_kcore(args.kcore_max_gb)

    elif method == "devmem":
        result = dumper.dump_devmem(args.devmem_offset, args.devmem_size)

    elif method == "process":
        if args.pid:
            result = dumper.dump_process(args.pid, search_keys=args.search_keys)
        elif args.proc:
            procs = dumper.list_processes(args.proc)
            if not procs:
                print(f"[-] No processes matching '{args.proc}'")
                sys.exit(1)
            for p in procs:
                print(f"\n[*] Dumping PID {p['pid']} ({p['cmdline'][:60]})")
                dumper.dump_process(p["pid"], search_keys=args.search_keys)
        elif args.all_procs:
            procs = dumper.list_processes()
            for p in procs:
                try:
                    dumper.dump_process(p["pid"], search_keys=args.search_keys)
                except Exception as e:
                    print(f"  [!] PID {p['pid']}: {e}")
        else:
            print("[-] Specify --pid, --proc, or --all-procs for process method")
            sys.exit(1)
        result = args.output

    if result:
        write_report(args.output, info, method, result)
        print(f"\n[✓] Acquisition complete: {result}")
    else:
        print("\n[-] Acquisition failed – see messages above")
        sys.exit(1)


if __name__ == "__main__":
    main()
