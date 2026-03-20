/**
 * frida_crypto_hooks.js  (fixed)
 * ================================
 * Fixes applied vs original:
 *   1. hookAllInstances: use m.findExportByName(sym) instead of
 *      Module.findExportByName(m.name, sym) — avoids "not a function" on
 *      newer Frida runtimes where the static form is unreliable per-module.
 *   2. Cipher.init overloads: replace `this.init(m, k)` / `this.init(m, k, p)`
 *      with the explicit overload call to avoid recursive "not a function"
 *      errors inside Java.perform hooked methods.
 *   3. Mac.init, SKF.generateSecret, MD.update/digest, KA.doPhase: same fix —
 *      always call the overload explicitly, never `this.method(args)` bare.
 *   4. KeyAgreement.doPhase inner generateSecret call wrapped in try/catch to
 *      prevent uncaught crash if the method isn't available on this phase.
 */

"use strict";

// ─── Configuration ─────────────────────────────────────────────────────────────

const CONFIG = {
    SHOW_STACK:     false,
    SHOW_HEX:       true,
    MIN_KEY_BYTES:  4,
    FILTER_PKG:     "",
    COLOUR:         true,
    NATIVE_SCAN:    true,
    JAVA_HOOKS:     true,
    DEDUP_WINDOW:   500,
};

// ─── Output helpers ────────────────────────────────────────────────────────────

const C = CONFIG.COLOUR ? {
    reset:  "\x1b[0m",
    bold:   "\x1b[1m",
    dim:    "\x1b[2m",
    red:    "\x1b[31m",
    green:  "\x1b[32m",
    yellow: "\x1b[33m",
    blue:   "\x1b[34m",
    cyan:   "\x1b[36m",
    white:  "\x1b[37m",
    magenta:"\x1b[35m",
} : Object.fromEntries(
    ["reset","bold","dim","red","green","yellow","blue","cyan","white","magenta"]
    .map(k => [k, ""])
);

const CATEGORY_COLOR = {
    KEY:        C.green,
    IV:         C.cyan,
    NONCE:      C.cyan,
    HMAC_KEY:   C.yellow,
    PASSPHRASE: C.red + C.bold,
    DERIVED:    C.magenta,
    HASH_IN:    C.dim,
    HASH_OUT:   C.blue,
    AEAD_KEY:   C.green + C.bold,
    DH_SECRET:  C.red,
    GENERIC:    C.white,
};

function categoryColor(cat) { return CATEGORY_COLOR[cat] || C.white; }

const _dedupCache = new Map();
function isDuplicate(key) {
    const now = Date.now();
    const last = _dedupCache.get(key);
    if (last && (now - last) < CONFIG.DEDUP_WINDOW) return true;
    _dedupCache.set(key, now);
    if (_dedupCache.size > 512) _dedupCache.delete(_dedupCache.keys().next().value);
    return false;
}

function report(fn, cat, value, extra) {
    if (!value) return;
    const dedupKey = `${fn}:${cat}:${JSON.stringify(value)}`;
    if (isDuplicate(dedupKey)) return;

    const cc = categoryColor(cat);
    let line = `${C.bold}[${cat}]${C.reset} ${cc}${fn}${C.reset}`;

    if (value.label)          line += `  ${C.dim}(${value.label})${C.reset}`;
    if (value.int !== undefined) line += `  int=${value.int}`;
    if (value.str)            line += `  str=${C.yellow}"${value.str}"${C.reset}`;
    if (value.hex)            line += `  hex=${C.green}${value.hex}${C.reset}`;
    if (value.bytes)          line += `  len=${value.bytes}`;

    if (extra) {
        for (const [k, v] of Object.entries(extra))
            if (v !== null && v !== undefined)
                line += `  ${k}=${C.cyan}${v}${C.reset}`;
    }

    if (CONFIG.SHOW_STACK) {
        try {
            const stack = Java.use("java.lang.Thread")
                .currentThread().getStackTrace();
            const frames = Array.from(stack)
                .map(f => `    ${f.getClassName()}.${f.getMethodName()}(${f.getFileName()}:${f.getLineNumber()})`)
                .filter(f => !f.includes("java.lang.Thread") && !f.includes("art."))
                .slice(0, 8).join("\n");
            line += `\n${C.dim}${frames}${C.reset}`;
        } catch (_) {}
    }
    console.log(line);
}

// ─── Buffer helpers ────────────────────────────────────────────────────────────

function bytesToHex(arr) {
    // FIX: indexed access with Number() coercion — safe for all array types.
    if (!arr || arr.length === 0) return "";
    const out = [];
    for (let i = 0; i < arr.length; i++)
        out.push((Number(arr[i]) & 0xff).toString(16).padStart(2, "0"));
    return out.join(" ");
}

function tryString(arr) {
    // FIX: use indexed access + Number() to safely handle Java byte proxies,
    // plain JS arrays, and Uint8Arrays without relying on for...of iteration.
    if (!arr || arr.length === 0) return null;
    let s = "";
    for (let i = 0; i < arr.length; i++) {
        const c = Number(arr[i]) & 0xff;
        if (c === 0) break;
        if (c < 0x20 || c > 0x7e) return null;
        s += String.fromCharCode(c);
    }
    return s.length >= 4 ? s : null;
}

function fromJavaBytes(jBytes, minLen) {
    // FIX: accept both Java byte[] proxies and plain JS arrays/Uint8Arrays.
    // Java.array() must only be called on actual Java proxies, not JS arrays.
    if (!jBytes) return null;
    let arr;
    try {
        // If it already looks like a plain JS array (has a constructor that
        // isn't a Java wrapper), use it directly.
        if (Array.isArray(jBytes) || jBytes instanceof Uint8Array) {
            arr = jBytes;
        } else {
            arr = Java.array("byte", jBytes);
        }
    } catch (_) {
        // Last resort: try treating it as-is
        arr = jBytes;
    }
    if (!arr || arr.length < (minLen || CONFIG.MIN_KEY_BYTES)) return null;
    const hex = bytesToHex(arr);
    const str = tryString(arr);
    const result = { hex, bytes: arr.length };
    if (str) result.str = str;
    return result;
}

function fromNativePtr(ptr, len, minLen) {
    if (ptr.isNull() || len <= 0) return null;
    if (len < (minLen || CONFIG.MIN_KEY_BYTES)) return null;
    const capped = Math.min(len, 512);
    let arr;
    try { arr = ptr.readByteArray(capped); } catch (_) { return null; }
    if (!arr) return null;
    const u8  = new Uint8Array(arr);
    const hex = bytesToHex(u8);
    const str = tryString(u8);
    const result = { hex, bytes: len };
    if (str) result.str = str;
    return result;
}

// ─── Java layer ────────────────────────────────────────────────────────────────

if (CONFIG.JAVA_HOOKS) {
Java.perform(function () {

    // ── SecretKeySpec ──────────────────────────────────────────────────────────
    try {
        const SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");

        SecretKeySpec.$init.overload("[B", "java.lang.String")
            .implementation = function (key, algo) {
            const v = fromJavaBytes(key);
            if (v) report("SecretKeySpec.<init>", "KEY", v, { algo });
            return this.$init(key, algo);
        };

        SecretKeySpec.$init.overload("[B", "int", "int", "java.lang.String")
            .implementation = function (key, off, len, algo) {
            const sub = Java.array("byte", key).slice(off, off + len);
            const v = fromJavaBytes(sub);
            if (v) report("SecretKeySpec.<init>(offset)", "KEY", v, { algo, offset: off, len });
            return this.$init(key, off, len, algo);
        };
    } catch (e) { console.log("[!] SecretKeySpec hook failed: " + e); }

    // ── IvParameterSpec ────────────────────────────────────────────────────────
    try {
        const IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
        IvParameterSpec.$init.overload("[B")
            .implementation = function (iv) {
            const v = fromJavaBytes(iv, 1);
            if (v) report("IvParameterSpec.<init>", "IV", v);
            return this.$init(iv);
        };
    } catch (e) { console.log("[!] IvParameterSpec hook failed: " + e); }

    // ── GCMParameterSpec ───────────────────────────────────────────────────────
    try {
        const GCMParameterSpec = Java.use("javax.crypto.spec.GCMParameterSpec");
        GCMParameterSpec.$init.overload("int", "[B")
            .implementation = function (tlen, iv) {
            const v = fromJavaBytes(iv, 1);
            if (v) report("GCMParameterSpec.<init>", "NONCE", v, { tagBits: tlen });
            return this.$init(tlen, iv);
        };
        GCMParameterSpec.$init.overload("int", "[B", "int", "int")
            .implementation = function (tlen, iv, off, len) {
            // FIX: Java array proxy has no .slice() — convert to JS Array first
            const sub = Array.from(Java.array("byte", iv)).slice(off, off + len);
            const v = fromJavaBytes(sub, 1);
            if (v) report("GCMParameterSpec.<init>(offset)", "NONCE", v, { tagBits: tlen });
            return this.$init(tlen, iv, off, len);
        };
    } catch (e) { console.log("[!] GCMParameterSpec hook failed: " + e); }

    // ── PBEKeySpec ────────────────────────────────────────────────────────────
    try {
        const PBEKeySpec = Java.use("javax.crypto.spec.PBEKeySpec");
        PBEKeySpec.$init.overload("[C", "[B", "int", "int")
            .implementation = function (password, salt, iter, keyLen) {
            const pw = password ? Array.from(password).map(c => c & 0xff) : [];
            const pwStr = pw.map(c => String.fromCharCode(c)).join("");
            const sv = fromJavaBytes(salt, 1);
            report("PBEKeySpec.<init>", "PASSPHRASE",
                { str: pwStr, bytes: pw.length },
                { saltHex: sv ? sv.hex : null, iterations: iter, keyLen });
            return this.$init(password, salt, iter, keyLen);
        };
        PBEKeySpec.$init.overload("[C")
            .implementation = function (password) {
            const pw = password ? Array.from(password).map(c => c & 0xff) : [];
            const pwStr = pw.map(c => String.fromCharCode(c)).join("");
            report("PBEKeySpec.<init>", "PASSPHRASE", { str: pwStr, bytes: pw.length });
            return this.$init(password);
        };
    } catch (e) { console.log("[!] PBEKeySpec hook failed: " + e); }

    // ── Cipher.init ────────────────────────────────────────────────────────────
    // FIX: call the explicit overload instead of bare this.init() to avoid
    //      "not a function" / recursive dispatch errors in Frida's Java bridge.
    try {
        const Cipher = Java.use("javax.crypto.Cipher");
        const MODES = { 1: "ENCRYPT", 2: "DECRYPT", 3: "WRAP", 4: "UNWRAP" };

        // Cache overload references once so we can call them safely
        const cipherInit2 = Cipher.init.overload("int", "java.security.Key");
        const cipherInit3 = Cipher.init.overload(
            "int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec");

        function extractCipherArgs(ctx, opmode, key, params) {
            const algo    = (() => { try { return ctx.getAlgorithm(); } catch(_) { return "?"; } })();
            const modeStr = MODES[opmode] || String(opmode);
            if (key) {
                try {
                    const encoded = key.getEncoded();
                    if (encoded) {
                        const v = fromJavaBytes(encoded);
                        if (v) report("Cipher.init", "KEY", v, { algo, mode: modeStr });
                    }
                } catch (_) {}
            }
            if (params) {
                try {
                    const IvPS = Java.use("javax.crypto.spec.IvParameterSpec");
                    if (params.$className === "javax.crypto.spec.IvParameterSpec") {
                        const v = fromJavaBytes(params.getIV(), 1);
                        if (v) report("Cipher.init [params]", "IV", v, { algo });
                    }
                } catch (_) {}
                try {
                    if (params.$className === "javax.crypto.spec.GCMParameterSpec") {
                        const v = fromJavaBytes(params.getIV(), 1);
                        if (v) report("Cipher.init [params]", "NONCE", v, { algo });
                    }
                } catch (_) {}
            }
        }

        cipherInit2.implementation = function (m, k) {
            extractCipherArgs(this, m, k, null);
            return cipherInit2.call(this, m, k);   // ← explicit overload call
        };
        cipherInit3.implementation = function (m, k, p) {
            extractCipherArgs(this, m, k, p);
            return cipherInit3.call(this, m, k, p); // ← explicit overload call
        };
    } catch (e) { console.log("[!] Cipher.init hook failed: " + e); }

    // ── Mac.init (HMAC) ────────────────────────────────────────────────────────
    // FIX: store overload ref and call it explicitly.
    try {
        const Mac = Java.use("javax.crypto.Mac");
        const macInit = Mac.init.overload("java.security.Key");
        macInit.implementation = function (key) {
            const algo = (() => { try { return this.getAlgorithm(); } catch(_) { return "?"; } })();
            if (key) {
                try {
                    const v = fromJavaBytes(key.getEncoded());
                    if (v) report("Mac.init", "HMAC_KEY", v, { algo });
                } catch (_) {}
            }
            return macInit.call(this, key); // ← explicit
        };
    } catch (e) { console.log("[!] Mac.init hook failed: " + e); }

    // ── KeyGenerator.init ─────────────────────────────────────────────────────
    try {
        const KeyGenerator = Java.use("javax.crypto.KeyGenerator");
        const kgInit = KeyGenerator.init.overload("int");
        kgInit.implementation = function (keysize) {
            const algo = (() => { try { return this.getAlgorithm(); } catch(_) { return "?"; } })();
            report("KeyGenerator.init", "GENERIC",
                { int: keysize, label: "key-size bits" }, { algo });
            return kgInit.call(this, keysize); // ← explicit
        };
    } catch (e) { console.log("[!] KeyGenerator.init hook failed: " + e); }

    // ── SecretKeyFactory.generateSecret ───────────────────────────────────────
    // FIX: explicit overload call.
    try {
        const SKF = Java.use("javax.crypto.SecretKeyFactory");
        const skfGen = SKF.generateSecret.overload("java.security.spec.KeySpec");
        skfGen.implementation = function (spec) {
            const key = skfGen.call(this, spec); // ← explicit
            if (key) {
                try {
                    const v = fromJavaBytes(key.getEncoded());
                    if (v) report("SecretKeyFactory.generateSecret", "DERIVED", v,
                        { algo: this.getAlgorithm() });
                } catch (_) {}
            }
            return key;
        };
    } catch (e) { console.log("[!] SecretKeyFactory.generateSecret hook failed: " + e); }

    // ── MessageDigest ─────────────────────────────────────────────────────────
    // FIX: explicit overload calls.
    try {
        const MD = Java.use("java.security.MessageDigest");
        const mdUpdate = MD.update.overload("[B");
        const mdDigest = MD.digest.overload();

        mdUpdate.implementation = function (input) {
            const v = fromJavaBytes(input);
            if (v) report("MessageDigest.update", "HASH_IN", v,
                { algo: this.getAlgorithm() });
            return mdUpdate.call(this, input); // ← explicit
        };

        mdDigest.implementation = function () {
            const result = mdDigest.call(this); // ← explicit
            const v = fromJavaBytes(result, 1);
            if (v) report("MessageDigest.digest", "HASH_OUT", v,
                { algo: this.getAlgorithm() });
            return result;
        };
    } catch (e) { console.log("[!] MessageDigest hook failed: " + e); }

    // ── KeyAgreement.doPhase ──────────────────────────────────────────────────
    // FIX: explicit overload call; inner generateSecret wrapped safely.
    try {
        const KA = Java.use("javax.crypto.KeyAgreement");
        const kaDoPhase = KA.doPhase.overload("java.security.Key", "boolean");
        kaDoPhase.implementation = function (key, lastPhase) {
            const result = kaDoPhase.call(this, key, lastPhase); // ← explicit
            if (lastPhase) {
                try {
                    const secret = KA.generateSecret.overload()
                        ? this.generateSecret()
                        : null;
                    if (secret) {
                        const v = fromJavaBytes(secret);
                        if (v) report("KeyAgreement.generateSecret [after doPhase]",
                            "DH_SECRET", v, { algo: this.getAlgorithm() });
                    }
                } catch (_) {}
            }
            return result;
        };
    } catch (e) { console.log("[!] KeyAgreement.doPhase hook failed: " + e); }

    // ── SQLCipher ─────────────────────────────────────────────────────────────
    const sqlcipherClasses = [
        "net.sqlcipher.database.SQLiteDatabase",
        "org.signal.sqlcipher.database.SQLiteDatabase",
        "net.zetetic.database.sqlcipher.SQLiteDatabase",
    ];
    for (const cls of sqlcipherClasses) {
        try {
            const SQLiteDB = Java.use(cls);
            // FIX: wrap each overload in an IIFE so `ov` is captured before
            // .implementation is set. ov.call() dispatches to the real JNI
            // method, NOT recursively back through our wrapper.
            for (const overload of SQLiteDB.openOrCreateDatabase.overloads) {
                (function (ov) {
                    ov.implementation = function () {
                        const args = Array.from(arguments);
                        if (args.length >= 2 && args[1]) {
                            const pw = args[1].toString();
                            if (pw && pw.length >= 4) {
                                const hex = pw.length <= 130 && /^[0-9a-fA-F]+$/.test(pw)
                                    ? pw : bytesToHex(Array.from(pw).map(c => c.charCodeAt(0)));
                                report(`${cls}.openOrCreateDatabase`, "PASSPHRASE",
                                    { str: pw.substring(0, 128), hex, bytes: pw.length },
                                    { db: args[0] });
                            }
                        }
                        return ov.call(this, ...args); // ← not recursive
                    };
                })(overload);
            }
        } catch (_) {}
    }

    // ── Android Keystore – SecretKeyEntry import ──────────────────────────────
    try {
        const KeyStore = Java.use("java.security.KeyStore");
        const ksSetEntry = KeyStore.setEntry.overload(
            "java.lang.String",
            "java.security.KeyStore$Entry",
            "java.security.KeyStore$ProtectionParameter"
        );
        ksSetEntry.implementation = function (alias, entry, prot) {
            try {
                const SKE = Java.use("java.security.KeyStore$SecretKeyEntry");
                if (entry.$className === "java.security.KeyStore$SecretKeyEntry") {
                    const key = entry.getSecretKey();
                    const encoded = key.getEncoded();
                    if (encoded) {
                        const v = fromJavaBytes(encoded);
                        if (v) report("KeyStore.setEntry (SecretKeyEntry)", "KEY", v,
                            { alias, algo: key.getAlgorithm() });
                    }
                }
            } catch (_) {}
            return ksSetEntry.call(this, alias, entry, prot); // ← explicit
        };
    } catch (e) { console.log("[!] KeyStore.setEntry hook failed: " + e); }

    console.log(`${C.bold}${C.green}[*] Java crypto hooks installed${C.reset}`);
}); // Java.perform
} // CONFIG.JAVA_HOOKS

// ─── Native layer ──────────────────────────────────────────────────────────────

if (CONFIG.NATIVE_SCAN) {

/**
 * FIX: Use m.findExportByName(sym) (instance method on the Module object)
 *      instead of Module.findExportByName(m.name, sym).  The static form
 *      fails on some Frida versions when the name contains path separators
 *      or when the module hasn't fully loaded — the instance method is safer.
 */
function findNativeExports(symName, libPattern) {
    const found = [];
    const pat = typeof libPattern === "string"
        ? new RegExp(libPattern, "i") : libPattern;

    for (const m of Process.enumerateModules()) {
        if (!pat.test(m.name)) continue;
        try {
            // ← FIXED: instance method instead of static Module.findExportByName
            const exp = m.findExportByName(symName);
            if (exp) found.push({ lib: m.name, addr: exp });
        } catch (_) {}
    }
    return found;
}

function hookAllInstances(symName, libPattern, onEnter, onLeave) {
    const instances = findNativeExports(symName, libPattern);
    if (instances.length === 0) {
        // Fallback: global scan (handles statically-linked BoringSSL)
        try {
            const addr = Module.findExportByName(null, symName);
            if (addr) instances.push({ lib: "in-process", addr });
        } catch (_) {}
    }
    for (const { lib, addr } of instances) {
        try {
            Interceptor.attach(addr, {
                onEnter: onEnter ? function (args) { onEnter.call(this, args, lib); } : undefined,
                onLeave: onLeave ? function (ret)  { onLeave.call(this, ret, lib);  } : undefined,
            });
            console.log(`${C.dim}  [native] hooked ${symName} in ${lib}${C.reset}`);
        } catch (e) {
            console.log(`${C.dim}  [native] failed ${symName} in ${lib}: ${e}${C.reset}`);
        }
    }
}

const CRYPTO_LIBS = /libcrypto|libssl|libsqlcipher|libsignalprotocol|libmolly|libsession/i;

// ── EVP_CipherInit_ex / EVP_EncryptInit_ex / EVP_DecryptInit_ex ───────────────
function evpCipherInitHook(fnName) {
    hookAllInstances(fnName, CRYPTO_LIBS, function (args, lib) {
        const keyPtr = args[3];
        const ivPtr  = args[4];
        const enc    = args[5].toInt32();

        if (!keyPtr.isNull()) {
            const kv = fromNativePtr(keyPtr, 64);
            if (kv) report(fnName, "KEY", kv,
                { lib, dir: enc === 1 ? "ENC" : enc === 0 ? "DEC" : "KEEP" });
        }
        if (!ivPtr.isNull()) {
            const iv = fromNativePtr(ivPtr, 16, 1);
            if (iv) report(fnName + " [iv]", "IV", iv, { lib });
        }
    });
}

evpCipherInitHook("EVP_CipherInit_ex");
evpCipherInitHook("EVP_EncryptInit_ex");
evpCipherInitHook("EVP_DecryptInit_ex");
evpCipherInitHook("EVP_CipherInit_ex2");

// ── EVP_AEAD_CTX_init ─────────────────────────────────────────────────────────
hookAllInstances("EVP_AEAD_CTX_init", CRYPTO_LIBS, function (args, lib) {
    const keyPtr = args[2];
    const keyLen = args[3].toInt32();
    if (!keyPtr.isNull() && keyLen > 0) {
        const v = fromNativePtr(keyPtr, keyLen);
        if (v) report("EVP_AEAD_CTX_init", "AEAD_KEY", v, { lib, tagLen: args[4].toInt32() });
    }
});

hookAllInstances("EVP_AEAD_CTX_open", CRYPTO_LIBS, () => {});
hookAllInstances("EVP_AEAD_CTX_seal", CRYPTO_LIBS, () => {});

// ── AES_set_encrypt_key / AES_set_decrypt_key ─────────────────────────────────
function aesKeyHook(fnName) {
    hookAllInstances(fnName, CRYPTO_LIBS, function (args, lib) {
        const keyPtr  = args[0];
        const keyBits = args[1].toInt32();
        const keyLen  = Math.ceil(keyBits / 8);
        if (!keyPtr.isNull() && keyLen > 0) {
            const v = fromNativePtr(keyPtr, keyLen);
            if (v) report(fnName, "KEY", v, { lib, bits: keyBits });
        }
    });
}
aesKeyHook("AES_set_encrypt_key");
aesKeyHook("AES_set_decrypt_key");

// ── HMAC_Init_ex ──────────────────────────────────────────────────────────────
hookAllInstances("HMAC_Init_ex", CRYPTO_LIBS, function (args, lib) {
    const keyPtr = args[1];
    const keyLen = args[2].toInt32();
    if (!keyPtr.isNull() && keyLen > 0) {
        const v = fromNativePtr(keyPtr, keyLen);
        if (v) report("HMAC_Init_ex", "HMAC_KEY", v, { lib });
    }
});

// ── PKCS5_PBKDF2_HMAC ─────────────────────────────────────────────────────────
hookAllInstances("PKCS5_PBKDF2_HMAC", CRYPTO_LIBS, function (args, lib) {
    const passPtr  = args[0];
    const passLen  = args[1].toInt32();
    const saltPtr  = args[2];
    const saltLen  = args[3].toInt32();
    const iter     = args[4].toInt32();
    const keyLen   = args[6].toInt32();
    const outPtr   = args[7];

    const effectivePassLen = passLen < 0
        ? (passPtr.isNull() ? 0 : passPtr.readCString().length)
        : passLen;

    if (!passPtr.isNull() && effectivePassLen > 0) {
        const pv = fromNativePtr(passPtr, effectivePassLen);
        if (pv) report("PKCS5_PBKDF2_HMAC [password]", "PASSPHRASE", pv,
            { lib, iterations: iter, keyLen });
    }
    if (!saltPtr.isNull() && saltLen > 0) {
        const sv = fromNativePtr(saltPtr, saltLen, 1);
        if (sv) report("PKCS5_PBKDF2_HMAC [salt]", "GENERIC", sv, { lib });
    }

    this._outPtr = outPtr;
    this._keyLen = keyLen;
}, function (ret, lib) {
    if (ret.toInt32() !== 0 && this._outPtr && !this._outPtr.isNull()) {
        const v = fromNativePtr(this._outPtr, this._keyLen);
        if (v) report("PKCS5_PBKDF2_HMAC [derived]", "DERIVED", v, { lib });
    }
});

// ── HKDF ──────────────────────────────────────────────────────────────────────
hookAllInstances("HKDF", CRYPTO_LIBS, function (args, lib) {
    const outPtr  = args[0];
    const outLen  = args[1].toInt32();
    const secPtr  = args[3];
    const secLen  = args[4].toInt32();
    const saltPtr = args[5];
    const saltLen = args[6].toInt32();

    if (!secPtr.isNull() && secLen > 0) {
        const sv = fromNativePtr(secPtr, secLen);
        if (sv) report("HKDF [ikm]", "KEY", sv, { lib });
    }
    if (!saltPtr.isNull() && saltLen > 0) {
        const sv = fromNativePtr(saltPtr, saltLen, 1);
        if (sv) report("HKDF [salt]", "GENERIC", sv, { lib });
    }
    this._outPtr = outPtr;
    this._outLen = outLen;
}, function (ret, lib) {
    if (this._outPtr && !this._outPtr.isNull() && this._outLen > 0) {
        const v = fromNativePtr(this._outPtr, this._outLen);
        if (v) report("HKDF [okm]", "DERIVED", v, { lib });
    }
});

// ── HKDF_extract ──────────────────────────────────────────────────────────────
hookAllInstances("HKDF_extract", CRYPTO_LIBS, function (args, lib) {
    const secPtr  = args[3];
    const secLen  = args[4].toInt32();
    const saltPtr = args[5];
    const saltLen = args[6].toInt32();

    if (!secPtr.isNull() && secLen > 0) {
        const v = fromNativePtr(secPtr, secLen);
        if (v) report("HKDF_extract [ikm]", "KEY", v, { lib });
    }
    if (!saltPtr.isNull() && saltLen > 0) {
        const v = fromNativePtr(saltPtr, saltLen, 1);
        if (v) report("HKDF_extract [salt]", "GENERIC", v, { lib });
    }
    this._outPtr    = args[0];
    this._outLenPtr = args[1];
}, function (ret, lib) {
    if (this._outPtr && !this._outPtr.isNull()) {
        let outLen = 32;
        try { outLen = this._outLenPtr.readUInt(); } catch (_) {}
        const v = fromNativePtr(this._outPtr, outLen);
        if (v) report("HKDF_extract [prk]", "DERIVED", v, { lib });
    }
});

// ── HKDF_expand ───────────────────────────────────────────────────────────────
hookAllInstances("HKDF_expand", CRYPTO_LIBS, function (args, lib) {
    const prkPtr = args[3];
    const prkLen = args[4].toInt32();
    if (!prkPtr.isNull() && prkLen > 0) {
        const v = fromNativePtr(prkPtr, prkLen);
        if (v) report("HKDF_expand [prk]", "KEY", v, { lib });
    }
    this._outPtr = args[0];
    this._outLen = args[1].toInt32();
}, function (ret, lib) {
    if (this._outPtr && !this._outPtr.isNull() && this._outLen > 0) {
        const v = fromNativePtr(this._outPtr, this._outLen);
        if (v) report("HKDF_expand [okm]", "DERIVED", v, { lib });
    }
});

// ── sqlite3_key / sqlite3_key_v2 ──────────────────────────────────────────────
hookAllInstances("sqlite3_key", /.*/, function (args, lib) {
    const keyPtr = args[1];
    const keyLen = args[2].toInt32();
    if (!keyPtr.isNull() && keyLen > 0) {
        const v = fromNativePtr(keyPtr, keyLen, 1);
        if (v) report("sqlite3_key", "PASSPHRASE", v, { lib });
    }
});

hookAllInstances("sqlite3_key_v2", /.*/, function (args, lib) {
    const dbNamePtr = args[1];
    const keyPtr    = args[2];
    const keyLen    = args[3].toInt32();
    const dbName = dbNamePtr.isNull() ? "main" : dbNamePtr.readCString();
    if (!keyPtr.isNull() && keyLen > 0) {
        const v = fromNativePtr(keyPtr, keyLen, 1);
        if (v) report("sqlite3_key_v2", "PASSPHRASE", v, { lib, db: dbName });
    }
});

hookAllInstances("sqlite3_rekey", /.*/, function (args, lib) {
    const keyPtr = args[1];
    const keyLen = args[2].toInt32();
    if (!keyPtr.isNull() && keyLen > 0) {
        const v = fromNativePtr(keyPtr, keyLen, 1);
        if (v) report("sqlite3_rekey", "PASSPHRASE", v, { lib, note: "NEW key" });
    }
});

// ── EC_KEY_generate_key ───────────────────────────────────────────────────────
hookAllInstances("EC_KEY_generate_key", CRYPTO_LIBS, function (args, lib) {
    report("EC_KEY_generate_key", "GENERIC",
        { str: "EC key pair generation triggered", bytes: 0 }, { lib });
}, function (ret, lib) {
    if (ret.toInt32() === 1)
        report("EC_KEY_generate_key [done]", "GENERIC",
            { str: "EC key pair generated (use ECPrivateKey hook to capture scalar)", bytes: 0 }, { lib });
});

// ── ChaCha20_ctr32 ────────────────────────────────────────────────────────────
hookAllInstances("ChaCha20_ctr32", CRYPTO_LIBS, function (args, lib) {
    const keyPtr = args[3];
    if (!keyPtr.isNull()) {
        const v = fromNativePtr(keyPtr, 32);
        if (v) report("ChaCha20_ctr32 [key]", "KEY", v, { lib });
    }
    const ctrPtr = args[4];
    if (!ctrPtr.isNull()) {
        const nonce = fromNativePtr(ctrPtr, 16, 1);
        if (nonce) report("ChaCha20_ctr32 [nonce+ctr]", "NONCE", nonce, { lib });
    }
});

console.log(`${C.bold}${C.green}[*] Native crypto hooks installed${C.reset}`);

} // CONFIG.NATIVE_SCAN

// ─── Startup banner ────────────────────────────────────────────────────────────

console.log(`
${C.bold}${C.blue}╔══════════════════════════════════════════════════════╗
║      frida_crypto_hooks.js (fixed) – active         ║
╚══════════════════════════════════════════════════════╝${C.reset}
${C.dim}  Java hooks  : ${CONFIG.JAVA_HOOKS ? "ON" : "OFF"}
  Native hooks : ${CONFIG.NATIVE_SCAN ? "ON" : "OFF"}
  Stack trace  : ${CONFIG.SHOW_STACK ? "ON" : "OFF"}
  Dedup window : ${CONFIG.DEDUP_WINDOW} ms${C.reset}
`);
