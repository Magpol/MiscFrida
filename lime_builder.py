#!/usr/bin/env python3
"""
lime_builder.py
===============
Automated LiME (Linux Memory Extractor) kernel module builder.

Workflow:
  1. Connect to device over ADB and fingerprint the exact kernel build
  2. Resolve the correct kernel source repository for the OEM/device
  3. Download kernel source + matching cross-compiler toolchain
  4. Compile LiME against those sources (Docker preferred; native Linux fallback)
  5. Cache the built .ko by kernel version for reuse
  6. Optionally load the module and stream a full RAM dump immediately

Supported OEMs / kernel sources:
  - Google Pixel     (android.googlesource.com)
  - Samsung          (opensource.samsung.com)
  - OnePlus          (github.com/OnePlusOSS)
  - Xiaomi           (github.com/MiCode)
  - Generic AOSP     (android.googlesource.com/kernel/common)
  - kernel.org       (last resort, vanilla mainline)

Requirements (workstation):
  pip install requests tqdm
  docker  OR  gcc-aarch64-linux-gnu / gcc-arm-linux-gnueabihf (apt/brew)

Usage:
  # Auto-detect everything, build, and load on device
  python lime_builder.py --serial <adb-serial> --output /cases/

  # Build only, do not load
  python lime_builder.py --build-only --output /cases/

  # Use a cached .ko (skip build)
  python lime_builder.py --use-cached --output /cases/

  # Force a specific kernel source URL
  python lime_builder.py --kernel-src https://github.com/... --output /cases/
"""

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("[-] pip install requests tqdm")
    sys.exit(1)

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

# ─── Configuration ────────────────────────────────────────────────────────────

LIME_REPO        = "https://github.com/504ensicsLabs/LiME"
CACHE_DIR        = Path.home() / ".cache" / "lime_builder"
TOOLCHAIN_CACHE  = CACHE_DIR / "toolchains"
MODULE_CACHE     = CACHE_DIR / "modules"

# Android NDK r26 – used for cross-compilation when no system toolchain is found
NDK_URLS = {
    "linux":   "https://dl.google.com/android/repository/android-ndk-r26d-linux.zip",
    "darwin":  "https://dl.google.com/android/repository/android-ndk-r26d-darwin.zip",
    "windows": "https://dl.google.com/android/repository/android-ndk-r26d-windows.zip",
}

# ─── OEM kernel source database ───────────────────────────────────────────────

# Each entry: { "match": regex against ro.product.manufacturer or fingerprint,
#               "src_type": "git"|"tarball_index",
#               "url": base URL or template (use {version}, {model}, {build}) }

OEM_SOURCES = [
    # ── Google Pixel ──────────────────────────────────────────────────────────
    {
        "name":     "Google Pixel",
        "match":    re.compile(r"google|pixel", re.I),
        "src_type": "git",
        # Google publishes per-device branches; we try the common kernel first
        "urls": [
            "https://android.googlesource.com/kernel/msm",
            "https://android.googlesource.com/kernel/gs",          # Pixel 6+
            "https://android.googlesource.com/kernel/common",
        ],
        # Branch naming: android{api}-{device}-{version}
        "branch_pattern": "android{api}-5.{minor}",
    },

    # ── Samsung ───────────────────────────────────────────────────────────────
    {
        "name":     "Samsung",
        "match":    re.compile(r"samsung", re.I),
        "src_type": "tarball_index",
        # Samsung OSS portal – search by model + build ID
        "search_url": "https://opensource.samsung.com/uploadSearch?searchValue={model}",
        # Direct tarball pattern (many Samsung devices):
        "direct_url": "https://opensource.samsung.com/uploadFile/{model}_Kernel.tar.gz",
    },

    # ── OnePlus ───────────────────────────────────────────────────────────────
    {
        "name":     "OnePlus",
        "match":    re.compile(r"oneplus", re.I),
        "src_type": "git",
        "urls": ["https://github.com/OnePlusOSS/android_kernel_oneplus_{model}"],
        "branch_pattern": "oneplus/{version}",
    },

    # ── Xiaomi ────────────────────────────────────────────────────────────────
    {
        "name":     "Xiaomi",
        "match":    re.compile(r"xiaomi|redmi|poco", re.I),
        "src_type": "git",
        "urls": [
            "https://github.com/MiCode/Xiaomi_Kernel_OpenSource",
            "https://github.com/MiCode/Mi-kernel-opensource-{model}",
        ],
        "branch_pattern": "{codename}-s-oss",
    },

    # ── Generic AOSP fallback ─────────────────────────────────────────────────
    {
        "name":     "AOSP common kernel",
        "match":    re.compile(r".*"),
        "src_type": "git",
        "urls": [
            "https://android.googlesource.com/kernel/common",
        ],
        "branch_pattern": "android{api}-{minor}",
    },
]

# ─── HTTP session ─────────────────────────────────────────────────────────────

def make_session() -> requests.Session:
    s = requests.Session()
    retry = Retry(total=5, backoff_factor=1,
                  status_forcelist=[429, 500, 502, 503, 504])
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.mount("http://",  HTTPAdapter(max_retries=retry))
    return s

SESSION = make_session()

def download(url: str, dest: Path, label: str = "") -> Path:
    """Download url to dest with optional progress bar."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    r = SESSION.get(url, stream=True, timeout=60)
    r.raise_for_status()
    total = int(r.headers.get("content-length", 0))
    label = label or dest.name

    if tqdm and total:
        bar = tqdm(total=total, unit="B", unit_scale=True, desc=label)
    else:
        bar = None

    with open(dest, "wb") as f:
        for chunk in r.iter_content(chunk_size=65536):
            f.write(chunk)
            if bar:
                bar.update(len(chunk))
    if bar:
        bar.close()
    return dest

# ─── ADB helpers (minimal, no external dep) ──────────────────────────────────

def adb(serial: Optional[str], *args, su=True, timeout=30) -> str:
    prefix = ["adb"] + (["-s", serial] if serial else [])
    cmd = list(args)
    if args[0] == "shell" and su:
        cmd = ["shell", f"su -c '{' '.join(args[1:])}'"]
    try:
        r = subprocess.run(prefix + cmd, capture_output=True,
                           timeout=timeout, check=False)
        return r.stdout.decode("utf-8", errors="replace").strip()
    except subprocess.TimeoutExpired:
        return ""

def get_device_info(serial: Optional[str]) -> dict:
    props = [
        "ro.product.manufacturer",
        "ro.product.model",
        "ro.product.device",       # codename (e.g. "oriole")
        "ro.build.version.release",
        "ro.build.fingerprint",
        "ro.product.cpu.abi",
        "ro.build.id",
    ]
    info = {}
    for p in props:
        info[p] = adb(serial, "shell", f"getprop {p}", su=False)
    info["uname_r"]   = adb(serial, "shell", "uname -r", su=False)
    info["uname_m"]   = adb(serial, "shell", "uname -m", su=False)
    info["kconfig"]   = adb(serial, "shell", "cat /proc/config.gz 2>/dev/null | gzip -d 2>/dev/null | head -5", su=False)
    return info

# ─── Toolchain resolution ─────────────────────────────────────────────────────

def find_system_cross_compiler(arch: str) -> Optional[str]:
    """
    Look for an installed cross-compiler for the given Android ABI arch string.
    Returns the CROSS_COMPILE prefix (e.g. 'aarch64-linux-gnu-') or None.
    """
    candidates = {
        "arm64-v8a":   ["aarch64-linux-gnu-", "aarch64-linux-android-"],
        "armeabi-v7a": ["arm-linux-gnueabihf-", "arm-linux-androideabi-"],
        "x86_64":      ["x86_64-linux-gnu-", "x86_64-linux-android-"],
        "x86":         ["i686-linux-gnu-",  "i686-linux-android-"],
    }
    for prefix in candidates.get(arch, []):
        if shutil.which(f"{prefix}gcc"):
            return prefix
    return None


def install_ndk_toolchain(arch: str) -> str:
    """
    Download Android NDK and return the CROSS_COMPILE prefix path.
    Caches the NDK under TOOLCHAIN_CACHE.
    """
    host = platform.system().lower()
    ndk_url = NDK_URLS.get(host)
    if not ndk_url:
        raise RuntimeError(f"No NDK URL for host platform: {host}")

    ndk_zip = TOOLCHAIN_CACHE / "ndk.zip"
    ndk_dir = TOOLCHAIN_CACHE / "android-ndk"

    if not ndk_dir.exists():
        print(f"[toolchain] Downloading Android NDK from {ndk_url}…")
        download(ndk_url, ndk_zip, label="Android NDK")
        print("[toolchain] Extracting…")
        with zipfile.ZipFile(ndk_zip) as zf:
            zf.extractall(TOOLCHAIN_CACHE)
        # NDK extracts to android-ndk-r26d/
        extracted = next(TOOLCHAIN_CACHE.glob("android-ndk-r*"), None)
        if extracted:
            extracted.rename(ndk_dir)
        ndk_zip.unlink(missing_ok=True)

    # Locate the prebuilt toolchain
    arch_map = {
        "arm64-v8a":   ("aarch64-linux-android", "aarch64-linux-android26-clang"),
        "armeabi-v7a": ("armv7a-linux-androideabi", "armv7a-linux-androideabi26-clang"),
        "x86_64":      ("x86_64-linux-android", "x86_64-linux-android26-clang"),
    }
    tc_arch, _ = arch_map.get(arch, ("aarch64-linux-android", ""))
    # NDK standalone toolchains
    tc_bin = ndk_dir / "toolchains" / "llvm" / "prebuilt"
    host_tc = next(tc_bin.glob(f"{host}*"), None)
    if host_tc:
        cross_prefix = str(host_tc / "bin" / tc_arch) + "-"
        return cross_prefix

    raise RuntimeError("Could not locate NDK toolchain binaries")


def resolve_toolchain(arch: str) -> tuple[str, str]:
    """
    Returns (CROSS_COMPILE_prefix, ARCH_flag) for kernel Makefile.
    """
    arch_flag = {
        "arm64-v8a":   "arm64",
        "armeabi-v7a": "arm",
        "x86_64":      "x86_64",
        "x86":         "x86",
    }.get(arch, "arm64")

    prefix = find_system_cross_compiler(arch)
    if prefix:
        print(f"[toolchain] Using system cross-compiler: {prefix}gcc")
        return prefix, arch_flag

    print(f"[toolchain] No system cross-compiler for {arch}, downloading NDK…")
    prefix = install_ndk_toolchain(arch)
    print(f"[toolchain] NDK toolchain: {prefix}")
    return prefix, arch_flag

# ─── Kernel source resolution ─────────────────────────────────────────────────

def resolve_oem(info: dict) -> dict:
    manufacturer = info.get("ro.product.manufacturer", "").lower()
    fingerprint  = info.get("ro.build.fingerprint", "").lower()
    for oem in OEM_SOURCES:
        if oem["match"].search(manufacturer) or oem["match"].search(fingerprint):
            return oem
    return OEM_SOURCES[-1]   # AOSP fallback


def kernel_version_parts(uname_r: str) -> dict:
    """Parse '5.15.104-android13-8-00001-g...' into components."""
    m = re.match(
        r"(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)"
        r"(?:-android(?P<api>\d+))?",
        uname_r
    )
    if not m:
        return {}
    return {
        "major": int(m.group("major")),
        "minor": int(m.group("minor")),
        "patch": int(m.group("patch")),
        "api":   m.group("api") or "13",
        "full":  uname_r,
    }


def resolve_kernel_git_branch(oem: dict, info: dict, kver: dict) -> tuple[str, str]:
    """
    Return (repo_url, branch) best matching the device's kernel.
    Tries multiple heuristics.
    """
    api    = kver.get("api", "13")
    minor  = kver.get("minor", "15")
    model  = re.sub(r"\s+", "_", info.get("ro.product.model", "")).lower()
    codename = info.get("ro.product.device", model).lower()

    urls = oem.get("urls", [])
    branch_tpl = oem.get("branch_pattern", "android{api}-{minor}")

    branch = (branch_tpl
              .replace("{api}", str(api))
              .replace("{minor}", str(minor))
              .replace("{model}", model)
              .replace("{codename}", codename)
              .replace("{version}", f"{kver.get('major', 5)}.{minor}"))

    for url_tpl in urls:
        url = (url_tpl
               .replace("{model}", model)
               .replace("{codename}", codename))
        # Quick HEAD check to see if repo/branch exists
        try:
            r = SESSION.head(url, timeout=10, allow_redirects=True)
            if r.status_code < 400:
                return url, branch
        except Exception:
            continue

    # Fall back to first URL regardless
    return urls[0] if urls else "", branch


def clone_kernel_source(repo_url: str, branch: str, dest: Path,
                        depth: int = 1) -> bool:
    """Shallow-clone the kernel source. Returns True on success."""
    if dest.exists() and (dest / "Makefile").exists():
        print(f"[kernel] Reusing cached source: {dest}")
        return True

    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"[kernel] Cloning {repo_url}  branch={branch}  (shallow, depth={depth})…")
    print(f"         This may take several minutes for large kernel repos.")
    cmd = [
        "git", "clone", "--depth", str(depth),
        "--branch", branch,
        "--single-branch",
        repo_url, str(dest)
    ]
    result = subprocess.run(cmd, timeout=1800)
    if result.returncode != 0:
        # Try without branch (let git pick default) then checkout
        print(f"[kernel] Branch {branch!r} not found; cloning default branch…")
        cmd2 = ["git", "clone", "--depth", str(depth), repo_url, str(dest)]
        r2 = subprocess.run(cmd2, timeout=1800)
        return r2.returncode == 0
    return True


def download_samsung_tarball(info: dict, dest: Path) -> bool:
    """
    Attempt to download a Samsung kernel tarball from opensource.samsung.com.
    Returns True if a tarball was found and extracted.
    """
    model = info.get("ro.product.model", "").replace(" ", "").upper()
    build = info.get("ro.build.id", "").upper()

    # Common Samsung tarball URL patterns
    attempts = [
        f"https://opensource.samsung.com/uploadFile/{model}_{build}_Opensource.zip",
        f"https://opensource.samsung.com/uploadFile/{model}_Kernel.tar.gz",
        f"https://opensource.samsung.com/uploadFile/{model}_OS14_Kernel.tar.gz",
    ]

    dest.mkdir(parents=True, exist_ok=True)
    for url in attempts:
        print(f"[samsung] Trying {url}…")
        try:
            r = SESSION.head(url, timeout=10, allow_redirects=True)
            if r.status_code == 200:
                archive = dest / Path(urlparse(url).path).name
                download(url, archive, label="Samsung kernel source")
                if archive.suffix == ".zip":
                    with zipfile.ZipFile(archive) as zf:
                        zf.extractall(dest)
                else:
                    with tarfile.open(archive) as tf:
                        tf.extractall(dest)
                archive.unlink(missing_ok=True)
                return True
        except Exception:
            continue

    print("[samsung] Could not auto-download Samsung kernel source.")
    print(f"          Visit https://opensource.samsung.com and search for model {model}")
    print(f"          Extract the kernel tarball to: {dest}")
    return False

# ─── LiME compilation ─────────────────────────────────────────────────────────

def clone_lime(dest: Path) -> bool:
    if dest.exists() and (dest / "src" / "Makefile").exists():
        print(f"[LiME] Using cached source: {dest}")
        # Pull latest
        subprocess.run(["git", "-C", str(dest), "pull", "--ff-only"],
                       capture_output=True)
        return True
    print(f"[LiME] Cloning LiME from {LIME_REPO}…")
    r = subprocess.run(["git", "clone", "--depth", "1", LIME_REPO, str(dest)],
                       timeout=120)
    return r.returncode == 0


def _ko_cache_key(uname_r: str) -> str:
    return hashlib.sha256(uname_r.encode()).hexdigest()[:16]


def find_cached_module(uname_r: str) -> Optional[Path]:
    key = _ko_cache_key(uname_r)
    candidates = list(MODULE_CACHE.glob(f"{key}*.ko"))
    if candidates:
        return candidates[0]
    return None


def cache_module(uname_r: str, ko_path: Path) -> Path:
    MODULE_CACHE.mkdir(parents=True, exist_ok=True)
    key = _ko_cache_key(uname_r)
    dest = MODULE_CACHE / f"{key}_{uname_r.replace('/', '-')}_lime.ko"
    shutil.copy2(ko_path, dest)
    print(f"[cache] Module cached: {dest}")
    return dest


def build_lime_native(lime_src: Path, kernel_src: Path,
                      cross_prefix: str, arch_flag: str,
                      uname_r: str, build_dir: Path) -> Optional[Path]:
    """
    Build LiME .ko natively using make.
    Returns path to the built .ko or None on failure.
    """
    lime_src_dir = lime_src / "src"
    if not lime_src_dir.exists():
        print(f"[-] LiME src directory not found: {lime_src_dir}")
        return None

    # Prepare out-of-tree build directory
    build_dir.mkdir(parents=True, exist_ok=True)
    # Copy LiME sources into build dir so we don't pollute the cache
    for f in lime_src_dir.glob("*"):
        if f.is_file():
            shutil.copy2(f, build_dir / f.name)

    # Patch the Makefile to point at the right kernel
    makefile = build_dir / "Makefile"
    original = makefile.read_text()
    patched = re.sub(
        r"KDIR\s*:?=.*",
        f"KDIR := {kernel_src}",
        original
    )
    if patched == original:
        # Makefile doesn't have KDIR; prepend it
        patched = f"KDIR := {kernel_src}\n" + original
    makefile.write_text(patched)

    env = os.environ.copy()
    env["CROSS_COMPILE"] = cross_prefix
    env["ARCH"]           = arch_flag

    print(f"[build] Running make in {build_dir}…")
    print(f"        ARCH={arch_flag}  CROSS_COMPILE={cross_prefix}")
    result = subprocess.run(
        ["make", "-j", str(os.cpu_count() or 4),
         f"ARCH={arch_flag}",
         f"CROSS_COMPILE={cross_prefix}",
         f"KDIR={kernel_src}"],
        cwd=str(build_dir),
        env=env,
        timeout=600,
    )

    if result.returncode != 0:
        print("[-] make failed. Common fixes:")
        print("    • Ensure kernel source version matches device exactly (uname -r)")
        print("    • Run: make -C <kernel_src> scripts prepare modules_prepare")
        print("    • Check cross-compiler version compatibility")
        return None

    ko = next(build_dir.glob("lime.ko"), None) or next(build_dir.glob("*.ko"), None)
    if ko:
        print(f"[build] Built: {ko}")
        cache_module(uname_r, ko)
        return ko
    return None


def build_lime_docker(lime_src: Path, kernel_src: Path,
                      arch_flag: str, uname_r: str) -> Optional[Path]:
    """
    Build LiME inside a Docker container (Ubuntu 22.04 + cross-compiler).
    This avoids host toolchain issues entirely.
    """
    if not shutil.which("docker"):
        return None

    print("[docker] Building LiME inside Docker container…")

    # Cross-compiler package per architecture
    pkg_map = {
        "arm64": "gcc-aarch64-linux-gnu",
        "arm":   "gcc-arm-linux-gnueabihf",
        "x86_64":"gcc",
        "x86":   "gcc",
    }
    cross_map = {
        "arm64": "aarch64-linux-gnu-",
        "arm":   "arm-linux-gnueabihf-",
        "x86_64":"",
        "x86":   "",
    }
    pkg    = pkg_map.get(arch_flag, "gcc-aarch64-linux-gnu")
    cross  = cross_map.get(arch_flag, "aarch64-linux-gnu-")

    dockerfile = f"""
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \\
    make {pkg} bc flex bison libssl-dev libelf-dev kmod git \\
    python3 python3-pip && rm -rf /var/lib/apt/lists/*
WORKDIR /build
"""
    df_path = lime_src / "Dockerfile.lime_builder"
    df_path.write_text(dockerfile)

    img_tag = "lime_builder:latest"
    # Build image
    r = subprocess.run(["docker", "build", "-f", str(df_path),
                        "-t", img_tag, str(lime_src)],
                       capture_output=True)
    if r.returncode != 0:
        print(f"[-] Docker image build failed:\n{r.stderr.decode()}")
        return None

    # Determine output path inside container
    out_dir = lime_src / "build_out"
    out_dir.mkdir(exist_ok=True)

    # Run container with both sources mounted
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{lime_src}:/lime:ro",
        "-v", f"{kernel_src}:/kernel:ro",
        "-v", f"{out_dir}:/out",
        img_tag,
        "bash", "-c",
        (
            "cp -r /lime/src /tmp/lime_src && "
            f"make -C /tmp/lime_src -j$(nproc) "
            f"ARCH={arch_flag} CROSS_COMPILE={cross} KDIR=/kernel && "
            "cp /tmp/lime_src/lime.ko /out/"
        )
    ]
    r2 = subprocess.run(cmd, timeout=900)
    if r2.returncode != 0:
        print("[-] Docker build run failed")
        return None

    ko = out_dir / "lime.ko"
    if ko.exists():
        print(f"[docker] Built: {ko}")
        cache_module(uname_r, ko)
        return ko
    return None

# ─── Kernel source preparation ────────────────────────────────────────────────

def prepare_kernel_headers(kernel_src: Path, cross_prefix: str, arch_flag: str):
    """
    Run 'make scripts prepare modules_prepare' so LiME can find Module.symvers
    and the kernel headers are fully prepared for out-of-tree module builds.
    """
    print("[kernel] Preparing kernel headers (scripts + modules_prepare)…")
    env = os.environ.copy()
    env["CROSS_COMPILE"] = cross_prefix
    env["ARCH"]           = arch_flag

    for target in ["scripts", "prepare", "modules_prepare"]:
        r = subprocess.run(
            ["make", target, f"ARCH={arch_flag}",
             f"CROSS_COMPILE={cross_prefix}",
             "-j", str(os.cpu_count() or 4)],
            cwd=str(kernel_src), env=env,
            capture_output=True, timeout=600
        )
        if r.returncode != 0:
            # Not fatal; some targets may not exist depending on kernel version
            print(f"  [!] make {target} returned {r.returncode} (may be harmless)")

    # Apply a default config if no .config present
    config = kernel_src / ".config"
    if not config.exists():
        print("[kernel] No .config found – applying defconfig…")
        subprocess.run(
            ["make", "defconfig", f"ARCH={arch_flag}",
             f"CROSS_COMPILE={cross_prefix}"],
            cwd=str(kernel_src), env=env, capture_output=True, timeout=300
        )

# ─── Device loading ───────────────────────────────────────────────────────────

def load_and_dump(serial: Optional[str], ko_path: Path, output_dir: Path,
                  lime_format: str = "lime") -> Optional[Path]:
    """Push LiME .ko to device, insmod, and stream RAM dump back."""
    remote_ko   = "/data/local/tmp/lime.ko"
    remote_dump = "/data/local/tmp/ram.lime"
    local_dump  = output_dir / "ram.lime"
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n[device] Pushing {ko_path.name} to device…")
    subprocess.run(["adb"] + (["-s", serial] if serial else []) +
                   ["push", str(ko_path), remote_ko], check=True)
    adb(serial, "shell", f"chmod 644 {remote_ko}")

    print(f"[device] Loading LiME and dumping RAM to {remote_dump}…")
    adb(serial, "shell",
        f"insmod {remote_ko} 'path={remote_dump} format={lime_format}'",
        timeout=30)

    # Poll until module is gone (LiME unloads itself after dump)
    print("[device] Waiting for LiME to finish dumping…", end="", flush=True)
    for _ in range(180):
        time.sleep(2)
        lsmod = adb(serial, "shell", "lsmod 2>/dev/null | grep lime", su=False)
        if not lsmod:
            break
        print(".", end="", flush=True)
    print()

    print(f"[device] Pulling dump → {local_dump}")
    prefix = ["adb"] + (["-s", serial] if serial else [])
    ram_kb = int(adb(serial, "shell", "grep MemTotal /proc/meminfo | awk '{print $2}'",
                     su=False) or "0")

    cmd = prefix + ["exec-out", f"su -c 'cat {remote_dump}'"]
    with open(local_dump, "wb") as out_f:
        proc = subprocess.Popen(cmd, stdout=out_f, stderr=subprocess.DEVNULL)
        if tqdm and ram_kb:
            with tqdm(total=ram_kb * 1024, unit="B", unit_scale=True,
                      desc="RAM dump", dynamic_ncols=True) as bar:
                while proc.poll() is None:
                    try:
                        bar.n = out_f.tell()
                        bar.refresh()
                    except Exception:
                        pass
                    time.sleep(0.5)
                bar.n = out_f.tell()
                bar.refresh()
        else:
            proc.wait()

    # Cleanup
    adb(serial, "shell", f"rm -f {remote_ko} {remote_dump}")
    size_mb = local_dump.stat().st_size // (1024 * 1024)
    print(f"[device] Done. Dump size: {size_mb} MB  →  {local_dump}")
    return local_dump

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Automated LiME builder for Android forensics.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--serial", "-s", help="ADB device serial")
    parser.add_argument("--output", "-o", required=True,
                        help="Output directory for .ko and RAM dump")
    parser.add_argument("--build-only", action="store_true",
                        help="Build the .ko but do not load it on the device")
    parser.add_argument("--use-cached", action="store_true",
                        help="Use a previously built .ko from cache if available")
    parser.add_argument("--kernel-src", metavar="URL_OR_PATH",
                        help="Override kernel source URL or local path")
    parser.add_argument("--lime-format", choices=["lime", "raw"], default="lime",
                        help="LiME output format (default: lime)")
    parser.add_argument("--no-docker", action="store_true",
                        help="Disable Docker build; use native toolchain only")
    parser.add_argument("--info-only", action="store_true",
                        help="Print device info and resolved kernel source, then exit")
    parser.add_argument("--cache-dir", default=str(CACHE_DIR),
                        help=f"Override cache directory (default: {CACHE_DIR})")
    args = parser.parse_args()

    global CACHE_DIR, TOOLCHAIN_CACHE, MODULE_CACHE
    CACHE_DIR       = Path(args.cache_dir)
    TOOLCHAIN_CACHE = CACHE_DIR / "toolchains"
    MODULE_CACHE    = CACHE_DIR / "modules"

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── 1. Fingerprint device ────────────────────────────────────────────────
    print("\n[*] Collecting device information…")
    info = get_device_info(args.serial)
    for k, v in info.items():
        if k != "kconfig":
            print(f"    {k:<35} {v}")

    uname_r = info.get("uname_r", "")
    if not uname_r:
        print("[-] Could not determine kernel version (uname -r failed).")
        sys.exit(1)

    kver = kernel_version_parts(uname_r)
    arch = info.get("ro.product.cpu.abi", "arm64-v8a")
    print(f"\n[*] Kernel  : {uname_r}")
    print(f"[*] ABI     : {arch}")
    print(f"[*] Version : {kver}")

    # ── 2. Check cache ───────────────────────────────────────────────────────
    if args.use_cached:
        cached = find_cached_module(uname_r)
        if cached:
            print(f"\n[cache] Found cached module: {cached}")
            if not args.build_only:
                load_and_dump(args.serial, cached, output_dir, args.lime_format)
            return
        print("[cache] No cached module found, proceeding with build.")

    # ── 3. Resolve kernel source ─────────────────────────────────────────────
    oem = resolve_oem(info)
    print(f"\n[*] OEM profile: {oem['name']}")

    kernel_src_dir = CACHE_DIR / "kernel_src" / _ko_cache_key(uname_r)

    if args.kernel_src:
        ks = args.kernel_src
        if os.path.isdir(ks):
            kernel_src_dir = Path(ks)
            print(f"[kernel] Using local source: {kernel_src_dir}")
        else:
            print(f"[kernel] Using provided URL: {ks}")
            clone_kernel_source(ks, "HEAD", kernel_src_dir)
    else:
        if oem["src_type"] == "tarball_index" and "samsung" in oem["name"].lower():
            if not download_samsung_tarball(info, kernel_src_dir):
                print("[!] Falling back to AOSP common kernel…")
                oem = OEM_SOURCES[-1]  # AOSP fallback
                repo_url, branch = resolve_kernel_git_branch(oem, info, kver)
                clone_kernel_source(repo_url, branch, kernel_src_dir)
        else:
            repo_url, branch = resolve_kernel_git_branch(oem, info, kver)
            print(f"[kernel] Repository : {repo_url}")
            print(f"[kernel] Branch     : {branch}")
            if args.info_only:
                return
            clone_kernel_source(repo_url, branch, kernel_src_dir)

    if args.info_only:
        return

    if not kernel_src_dir.exists():
        print(f"[-] Kernel source not found at {kernel_src_dir}")
        sys.exit(1)

    # ── 4. Toolchain ─────────────────────────────────────────────────────────
    cross_prefix, arch_flag = resolve_toolchain(arch)

    # ── 5. Prepare kernel headers ─────────────────────────────────────────────
    prepare_kernel_headers(kernel_src_dir, cross_prefix, arch_flag)

    # ── 6. Clone LiME ────────────────────────────────────────────────────────
    lime_src_dir = CACHE_DIR / "lime_src"
    if not clone_lime(lime_src_dir):
        print("[-] Failed to clone LiME repository")
        sys.exit(1)

    # ── 7. Build ─────────────────────────────────────────────────────────────
    build_tmp = output_dir / "lime_build"
    ko_path: Optional[Path] = None

    if not args.no_docker:
        ko_path = build_lime_docker(lime_src_dir, kernel_src_dir, arch_flag, uname_r)

    if ko_path is None:
        print("[build] Docker build unavailable or failed; trying native build…")
        ko_path = build_lime_native(
            lime_src_dir, kernel_src_dir,
            cross_prefix, arch_flag, uname_r, build_tmp
        )

    if ko_path is None:
        print("\n[-] LiME build failed.")
        print("    Manual steps:")
        print(f"      git clone {LIME_REPO}")
        print(f"      make -C LiME/src KDIR={kernel_src_dir} ARCH={arch_flag} CROSS_COMPILE={cross_prefix}")
        sys.exit(1)

    # Copy .ko to output dir
    final_ko = output_dir / f"lime_{uname_r.replace('/', '-')}.ko"
    shutil.copy2(ko_path, final_ko)
    print(f"\n[✓] LiME module ready: {final_ko}")

    # ── 8. Load and dump (unless --build-only) ───────────────────────────────
    if not args.build_only:
        load_and_dump(args.serial, final_ko, output_dir, args.lime_format)


if __name__ == "__main__":
    main()
