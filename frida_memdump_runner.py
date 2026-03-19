#!/usr/bin/env python3
"""
frida_memdump_runner.py
=======================
Python host-side runner for frida_memdump.js.
Coordinates memory acquisition from an Android process via Frida RPC,
writes binary segment files, and produces a key-hit report.

This is the kernel-module-free alternative to LiME.

Requirements:
  pip install frida frida-tools tqdm

Usage:
  # Dump a specific package (spawn mode – best coverage)
  python frida_memdump_runner.py -f org.thoughtcrime.securesms --output /cases/signal/

  # Attach to a running PID
  python frida_memdump_runner.py -p 1234 --output /cases/

  # Dump with artefact scanning
  python frida_memdump_runner.py -f com.android.chrome --output /cases/ --scan-keys

  # Dump only heap + stack (skip mapped files)
  python frida_memdump_runner.py -f <pkg> --output /cases/ --anon-only

  # Specify ADB serial for multi-device setups
  python frida_memdump_runner.py -f <pkg> --serial <serial> --output /cases/
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

try:
    import frida
except ImportError:
    print("[-] pip install frida frida-tools")
    sys.exit(1)

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

# Path to the companion JS script
SCRIPT_PATH = Path(__file__).parent / "frida_memdump.js"

CHUNK_SIZE = 4 * 1024 * 1024   # 4 MB per RPC call


# ─── Frida helpers ────────────────────────────────────────────────────────────

def get_device(serial: str | None) -> frida.core.Device:
    if serial:
        return frida.get_device(serial)
    # Prefer USB device
    dm = frida.get_device_manager()
    for dev in dm.enumerate_devices():
        if dev.type == "usb":
            return dev
    return frida.get_usb_device(timeout=10)


def load_script(session: frida.core.Session) -> frida.core.Script:
    js = SCRIPT_PATH.read_text(encoding="utf-8")
    script = session.create_script(js)
    script.on("message", lambda msg, data: _on_message(msg, data))
    script.load()
    return script


def _on_message(msg, data):
    if msg.get("type") == "error":
        print(f"[script error] {msg.get('description', msg)}")


# ─── Acquisition ──────────────────────────────────────────────────────────────

def acquire(script, output_dir: Path, scan_keys: bool,
            anon_only: bool, max_region_mb: int):
    api = script.exports_sync

    # Configure JS side
    cfg = {
        "scanKeys":       scan_keys,
        "maxRegionMB":    max_region_mb,
        "chunkSize":      CHUNK_SIZE,
    }
    api.configure(cfg)

    proc_info = api.process_info()
    print(f"\n[*] Process  PID={proc_info['pid']}  arch={proc_info['arch']}")

    ranges = api.list_ranges()
    if anon_only:
        ranges = [r for r in ranges if r["file"] is None]
    print(f"[*] Readable regions: {len(ranges)}")
    total_bytes = sum(r["size"] for r in ranges)
    print(f"[*] Total data      : {total_bytes / (1024*1024):.1f} MB")

    output_dir.mkdir(parents=True, exist_ok=True)

    # Save metadata
    meta_path = output_dir / "memory_map.json"
    with open(meta_path, "w") as f:
        json.dump({
            "process":  proc_info,
            "acquired": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "regions":  ranges,
        }, f, indent=2)
    print(f"[*] Memory map saved: {meta_path}")

    all_hits = []
    written_bytes = 0

    outer = tqdm(total=total_bytes, unit="B", unit_scale=True,
                 desc="Dumping", dynamic_ncols=True) if HAS_TQDM else None

    for region in ranges:
        base = region["base"]
        size = region["size"]
        prot = region["prot"]
        fname = (region["file"] or "").split("/")[-1] or "anon"
        label = f"{base}_{fname}"[:80].replace("/", "_").replace(" ", "_")

        seg_path = output_dir / f"{label}.bin"

        offset = 0
        seg_hits = []

        with open(seg_path, "wb") as seg_f:
            while offset < size:
                chunk_len = min(CHUNK_SIZE, size - offset)
                try:
                    result = api.read_chunk(base, offset, chunk_len)
                except Exception as e:
                    print(f"\n  [!] RPC error reading {base}+{offset}: {e}")
                    break

                if "error" in result:
                    # Unreadable page – write zeros to preserve offsets
                    seg_f.write(b"\x00" * chunk_len)
                    offset += chunk_len
                    if outer:
                        outer.update(chunk_len)
                    continue

                data = bytes(result["data"]) if result["data"] else b""
                seg_f.write(data)
                written_bytes += len(data)

                if scan_keys and result.get("hits"):
                    seg_hits.extend(result["hits"])

                offset += chunk_len
                if outer:
                    outer.update(len(data))

        if not seg_path.stat().st_size:
            seg_path.unlink(missing_ok=True)
            continue

        if seg_hits:
            all_hits.extend(seg_hits)
            print(f"\n  [!] {len(seg_hits)} artefact(s) in {label}:")
            for h in seg_hits[:10]:
                val = str(h.get("value", ""))[:100]
                print(f"      [{h['type']}] @ 0x{h['offset']:016x}  {val}")
            if len(seg_hits) > 10:
                print(f"      … and {len(seg_hits)-10} more")

    if outer:
        outer.close()

    print(f"\n[*] Written: {written_bytes/(1024*1024):.1f} MB")

    # ── Write key-hit report ──────────────────────────────────────────────────
    if scan_keys:
        hits_path = output_dir / "key_hits.json"
        with open(hits_path, "w") as f:
            json.dump(all_hits, f, indent=2)
        print(f"[*] {len(all_hits)} total artefact(s) → {hits_path}")

        # Human-readable summary
        report_path = output_dir / "key_hits_report.txt"
        with open(report_path, "w") as f:
            f.write(f"Artefact scan report\n{'='*60}\n")
            f.write(f"Process : PID {proc_info['pid']}\n")
            f.write(f"Time    : {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n\n")
            by_type: dict[str, list] = {}
            for h in all_hits:
                by_type.setdefault(h["type"], []).append(h)
            for typ, items in sorted(by_type.items()):
                f.write(f"\n[{typ}] – {len(items)} hit(s)\n")
                for item in items[:50]:
                    val = str(item.get("value", ""))[:120]
                    f.write(f"  0x{item['offset']:016x}  {val}\n")
        print(f"[*] Human-readable report → {report_path}")

    return all_hits


# ─── Entry point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Frida-based process memory dumper (kernel-module-free).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("-f", "--spawn", metavar="PKG",
                        help="Spawn and instrument a package (best coverage)")
    target.add_argument("-p", "--pid",   type=int,
                        help="Attach to a running PID")
    target.add_argument("-n", "--name",  metavar="NAME",
                        help="Attach by process name")

    parser.add_argument("--serial",  "-s", help="ADB device serial")
    parser.add_argument("--output",  "-o", required=True, help="Output directory")
    parser.add_argument("--scan-keys",     action="store_true",
                        help="Scan memory for AES keys, SQLCipher passphrases, etc.")
    parser.add_argument("--anon-only",     action="store_true",
                        help="Dump only anonymous (heap/stack) regions; skip mapped files")
    parser.add_argument("--max-region-mb", type=int, default=256,
                        help="Skip anonymous regions larger than this (MB, default 256)")
    parser.add_argument("--realm",         default="usb",
                        choices=["usb", "remote", "local"],
                        help="Frida transport (default: usb)")
    parser.add_argument("--host",          default="127.0.0.1:27042",
                        help="Frida remote host:port (if --realm=remote)")
    args = parser.parse_args()

    if not SCRIPT_PATH.exists():
        print(f"[-] JS script not found: {SCRIPT_PATH}")
        sys.exit(1)

    # ── Connect ──────────────────────────────────────────────────────────────
    if args.realm == "remote":
        device = frida.get_device_manager().add_remote_device(args.host)
    elif args.realm == "local":
        device = frida.get_local_device()
    else:
        device = get_device(args.serial)

    print(f"[*] Device : {device.name}  ({device.id})")

    session = None
    try:
        if args.spawn:
            print(f"[*] Spawning {args.spawn}…")
            pid = device.spawn([args.spawn])
            session = device.attach(pid)
            script  = load_script(session)
            device.resume(pid)
            time.sleep(2)   # let the app initialise
        elif args.pid:
            print(f"[*] Attaching to PID {args.pid}…")
            session = device.attach(args.pid)
            script  = load_script(session)
        else:
            print(f"[*] Attaching to '{args.name}'…")
            session = device.attach(args.name)
            script  = load_script(session)

        output_dir = Path(args.output)
        label = args.spawn or str(args.pid or args.name)
        run_dir = output_dir / label.replace(".", "_") / time.strftime("%Y%m%d_%H%M%S")

        acquire(script, run_dir,
                scan_keys=args.scan_keys,
                anon_only=args.anon_only,
                max_region_mb=args.max_region_mb)

        print(f"\n[✓] Dump complete: {run_dir}")

    except frida.ProcessNotFoundError:
        print(f"[-] Process not found.")
        sys.exit(1)
    except frida.NotSupportedError as e:
        print(f"[-] Frida error: {e}")
        print("    Ensure frida-server is running on the device as root.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
    finally:
        if session:
            try:
                session.detach()
            except Exception:
                pass


if __name__ == "__main__":
    main()
