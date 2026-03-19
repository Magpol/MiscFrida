/**
 * frida_memdump.js
 * ================
 * Kernel-module-free memory acquisition via Frida.
 * Replaces LiME when a compiled .ko is unavailable.
 *
 * Capabilities:
 *   - Enumerate and dump all readable virtual memory ranges of the target process
 *   - Optionally dump every process accessible on the device (requires root spawn)
 *   - Export dumps as raw binary segments (one per memory range)
 *   - Built-in scanner for forensic artefacts: AES keys, SQLCipher passphrases,
 *     Chrome v10/v11 blobs, JWTs, PEM headers, high-entropy blocks
 *   - Transfer output over Frida RPC (collected by the Python runner below)
 *
 * Usage (standalone – dumps self):
 *   frida -U -f <package> --no-pause -l frida_memdump.js
 *
 * Usage (with Python runner for file output):
 *   python frida_memdump_runner.py --pkg org.thoughtcrime.securesms --output /cases/
 *
 * Architecture:
 *   JS side  – memory enumeration, reading, scanning (runs inside target process)
 *   Python   – RPC transport, file writing, progress display (frida_memdump_runner.py)
 */

"use strict";

// ─── Configuration (overridable via rpc.exports.configure) ───────────────────

const CONFIG = {
    // Memory protection filters – include ranges matching any of these
    protections: ["r--", "rw-", "r-x", "rwx"],

    // Skip very large anonymous mappings (e.g. graphics heaps) above this size
    maxRegionMB: 256,

    // Enable artefact scanner
    scanKeys: true,

    // Minimum entropy for high-entropy block detection (0–8)
    entropyThreshold: 7.4,

    // Chunk size for reading large regions (avoids OOM)
    chunkSize: 4 * 1024 * 1024,   // 4 MB

    // Skip known noise regions
    skipPatterns: [
        /\/dev\/ashmem/,
        /\/dev\/kgsl/,      // Qualcomm GPU
        /\/dev\/ion/,       // ION allocator
        /gralloc/i,
    ],
};

// ─── Utilities ────────────────────────────────────────────────────────────────

function hexOf(buf) {
    return Array.from(new Uint8Array(buf))
        .map(b => b.toString(16).padStart(2, "0")).join("");
}

function entropy(buf) {
    const freq = new Uint32Array(256);
    const u8   = new Uint8Array(buf);
    for (const b of u8) freq[b]++;
    let h = 0;
    const n = u8.length;
    for (const f of freq) {
        if (f === 0) continue;
        const p = f / n;
        h -= p * Math.log2(p);
    }
    return h;
}

function tryString(buf, maxLen) {
    try {
        const u8 = new Uint8Array(buf, 0, Math.min(buf.byteLength, maxLen || 256));
        let s = "";
        for (const b of u8) {
            if (b === 0) break;
            if (b < 0x20 || b > 0x7e) return null;
            s += String.fromCharCode(b);
        }
        return s.length > 3 ? s : null;
    } catch (_) { return null; }
}

// ─── Artefact patterns ────────────────────────────────────────────────────────

const PATTERNS = {
    // SQLCipher 64-char hex passphrase
    sqlcipherHex:  /[0-9a-f]{64}/gi,

    // PRAGMA key statement
    pragmaKey:     /PRAGMA\s+key\s*=\s*['"][^'"]{8,}['"]/gi,

    // Chrome v10/v11 AES-GCM blob prefix + 12-byte nonce
    chromev10v11:  /v1[01][\s\S]{12}/g,

    // JWT
    jwt:           /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,

    // PEM private key
    pem:           /-----BEGIN (?:RSA |EC |)PRIVATE KEY-----/g,

    // Signal identity key pattern (32-byte base64 = 44 chars)
    signalKey:     /[A-Za-z0-9+/]{43}=/g,

    // Generic base64 secret-like fields
    secretB64:     /(?:key|secret|password|token|passphrase)["']?\s*[:=]\s*["']([A-Za-z0-9+/=]{16,})/gi,
};

function scanBuffer(buf, regionStart) {
    const hits = [];
    let text;
    try {
        text = new TextDecoder("utf-8", { fatal: false }).decode(buf);
    } catch (_) {
        return hits;
    }

    for (const [label, pat] of Object.entries(PATTERNS)) {
        pat.lastIndex = 0;
        let m;
        while ((m = pat.exec(text)) !== null) {
            hits.push({
                type:   label,
                offset: regionStart + m.index,
                value:  m[0].substring(0, 256),
            });
        }
    }

    // High-entropy 32-byte sliding window (AES key heuristic)
    const u8 = new Uint8Array(buf);
    for (let i = 0; i + 32 <= u8.length; i += 4) {
        const chunk = buf.slice(i, i + 32);
        if (entropy(chunk) > CONFIG.entropyThreshold) {
            hits.push({
                type:   "high_entropy_32b",
                offset: regionStart + i,
                value:  hexOf(chunk),
            });
        }
    }

    return hits;
}

// ─── Memory enumeration ───────────────────────────────────────────────────────

function enumerateReadableRanges() {
    const ranges = [];
    for (const prot of CONFIG.protections) {
        try {
            const result = Process.enumerateRanges(prot);
            for (const r of result) {
                // Skip noise patterns
                if (CONFIG.skipPatterns.some(p => p.test(r.file ? r.file.path : "")))
                    continue;
                // Skip oversized anonymous regions
                if (!r.file && r.size > CONFIG.maxRegionMB * 1024 * 1024)
                    continue;
                ranges.push(r);
            }
        } catch (_) {}
    }
    // Deduplicate by base address
    const seen = new Set();
    return ranges.filter(r => {
        const k = r.base.toString();
        if (seen.has(k)) return false;
        seen.add(k);
        return true;
    });
}

// ─── RPC exports (called from Python runner) ──────────────────────────────────

rpc.exports = {

    /** Return process info */
    processInfo() {
        return {
            pid:    Process.id,
            arch:   Process.arch,
            ptrSize: Process.pointerSize,
            pageSize: Process.pageSize,
        };
    },

    /** Update config fields */
    configure(overrides) {
        Object.assign(CONFIG, overrides);
    },

    /** Return list of readable memory ranges (metadata only, no data) */
    listRanges() {
        const ranges = enumerateReadableRanges();
        return ranges.map(r => ({
            base:  r.base.toString(),
            size:  r.size,
            prot:  r.protection,
            file:  r.file ? r.file.path : null,
        }));
    },

    /**
     * Read one chunk of a memory range.
     * Returns { data: ArrayBuffer, hits: [...] } or { error: string }.
     *
     * Chunked design avoids transferring huge buffers in one RPC call.
     */
    readChunk(baseStr, offset, length) {
        try {
            const ptr  = ptr(baseStr).add(offset);
            const size = Math.min(length, CONFIG.chunkSize);
            const buf  = ptr.readByteArray(size);
            const regionStart = parseInt(baseStr, 16) + offset;

            const hits = CONFIG.scanKeys ? scanBuffer(buf, regionStart) : [];

            return { data: buf, hits };
        } catch (e) {
            return { error: e.message };
        }
    },

    /** Convenience: read a full region in one call (for small regions < chunkSize) */
    readRegion(baseStr, size) {
        try {
            const buf  = ptr(baseStr).readByteArray(size);
            const hits = CONFIG.scanKeys ? scanBuffer(buf, parseInt(baseStr, 16)) : [];
            return { data: buf, hits };
        } catch (e) {
            return { error: e.message };
        }
    },

    /** Scan already-dumped data (pass raw ArrayBuffer from a previous readChunk) */
    scanBuffer(data, regionStartStr) {
        const hits = scanBuffer(data, parseInt(regionStartStr, 16));
        return hits;
    },
};

// ─── Standalone mode (no Python runner) ──────────────────────────────────────
// When loaded directly with frida -l, prints a summary to the console.

(function standaloneSummary() {
    console.log("\n[frida_memdump] Enumerating memory ranges…");
    const ranges = enumerateReadableRanges();
    let totalMB  = 0;
    const allHits = [];

    console.log(`\n${"BASE":>20}  ${"SIZE":>10}  PROT  FILE`);
    console.log("─".repeat(70));

    for (const r of ranges) {
        const mb = r.size / (1024 * 1024);
        totalMB += mb;
        const fname = r.file ? r.file.path.split("/").pop() : "[anon]";
        console.log(
            `  ${r.base.toString().padStart(18)}  ${(mb.toFixed(1) + " MB").padStart(9)}` +
            `  ${r.protection}  ${fname}`
        );
    }

    console.log(`\n  Total readable: ${totalMB.toFixed(1)} MB across ${ranges.length} regions`);
    console.log("\n[frida_memdump] Use frida_memdump_runner.py to dump to files.");
    console.log("[frida_memdump] RPC exports ready: listRanges, readChunk, readRegion");
})();
