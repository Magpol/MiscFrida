/**
 * frida_crypto_hooks.js
 * =====================
 * Intercepts cryptographic operations at both the Java (JCA/JCE) and native
 * (BoringSSL / OpenSSL / libcrypto.so) layers. Prints the hooked function name
 * alongside every key, IV, nonce, passphrase, or derived secret it observes.
 *
 * Hooked surface:
 *   Java layer
 *     • javax.crypto.Cipher.init           – symmetric cipher key + IV
 *     • javax.crypto.spec.SecretKeySpec    – raw key bytes at construction
 *     • javax.crypto.spec.IvParameterSpec  – IV bytes
 *     • javax.crypto.spec.GCMParameterSpec – GCM nonce
 *     • javax.crypto.spec.PBEKeySpec       – password-based key spec
 *     • javax.crypto.KeyGenerator.init     – key generation parameters
 *     • javax.crypto.Mac.init              – HMAC / MAC key
 *     • javax.crypto.KeyAgreement.doPhase  – DH/ECDH shared secret
 *     • javax.crypto.SecretKeyFactory.generateSecret  – derived key
 *     • java.security.MessageDigest        – hash inputs + outputs
 *     • android.security.keystore (import / key-gen params)
 *     • SQLCipher (net.sqlcipher / org.signal.sqlcipher)
 *     • Signal libsignal-android key ops
 *
 *   Native layer (libcrypto.so / libssl.so / in-process BoringSSL)
 *     • EVP_CipherInit_ex / EVP_EncryptInit_ex / EVP_DecryptInit_ex
 *     • EVP_AEAD_CTX_init                  – AEAD (AES-GCM / ChaCha20-Poly1305)
 *     • AES_set_encrypt_key / AES_set_decrypt_key
 *     • HMAC_Init_ex                       – HMAC key
 *     • PKCS5_PBKDF2_HMAC                  – PBKDF2 key derivation
 *     • HKDF / HKDF_extract / HKDF_expand  – HKDF
 *     • sqlite3_key / sqlite3_key_v2       – SQLCipher passphrase (any library)
 *     • EC_KEY_generate_key / RSA_generate_key_ex
 *
 * Configuration (edit the CONFIG block below):
 *   • SHOW_STACK     – print Java/native call stack on each hit
 *   • SHOW_HEX       – always show hex dump regardless of printability
 *   • MIN_KEY_BYTES  – ignore buffers shorter than this (reduces noise)
 *   • FILTER_PKG     – if non-empty, only print hits from this class prefix
 *   • COLOUR         – ANSI-coloured output
 *
 * Usage:
 *   frida -U -f <package> --no-pause -l frida_crypto_hooks.js
 *   frida -U -p <pid>                -l frida_crypto_hooks.js
 */

"use strict";

// ─── Configuration ─────────────────────────────────────────────────────────────

const CONFIG = {
    SHOW_STACK:     false,   // include Java call stack in output
    SHOW_HEX:       true,    // always show hex even for printable strings
    MIN_KEY_BYTES:  4,       // ignore buffers shorter than this
    FILTER_PKG:     "",      // e.g. "org.thoughtcrime" – empty = all
    COLOUR:         true,    // ANSI colours
    NATIVE_SCAN:    true,    // hook native libcrypto / in-process BoringSSL
    JAVA_HOOKS:     true,    // hook Java JCA/JCE layer
    DEDUP_WINDOW:   500,     // ms – suppress exact duplicate hits within this window
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

function categoryColor(cat) {
    return CATEGORY_COLOR[cat] || C.white;
}

const _dedupCache = new Map();
function isDuplicate(key) {
    const now = Date.now();
    const last = _dedupCache.get(key);
    if (last && (now - last) < CONFIG.DEDUP_WINDOW) return true;
    _dedupCache.set(key, now);
    // Prune old entries to avoid unbounded growth
    if (_dedupCache.size > 512) {
        const oldest = _dedupCache.keys().next().value;
        _dedupCache.delete(oldest);
    }
    return false;
}

/**
 * Central output function. All hooks call this.
 * @param {string} fn      - hooked function / method name
 * @param {string} cat     - category label (KEY, IV, PASSPHRASE …)
 * @param {object} value   - { hex, str, int, label } – at least one field
 * @param {object} [extra] - optional extra fields
 */
function report(fn, cat, value, extra) {
    if (!value) return;

    const dedupKey = `${fn}:${cat}:${JSON.stringify(value)}`;
    if (isDuplicate(dedupKey)) return;

    const cc = categoryColor(cat);
    let line = `${C.bold}[${cat}]${C.reset} ${cc}${fn}${C.reset}`;

    if (value.label)  line += `  ${C.dim}(${value.label})${C.reset}`;
    if (value.int    !== undefined) line += `  int=${value.int}`;
    if (value.str)    line += `  str=${C.yellow}"${value.str}"${C.reset}`;
    if (value.hex)    line += `  hex=${C.green}${value.hex}${C.reset}`;
    if (value.bytes)  line += `  len=${value.bytes}`;

    if (extra) {
        for (const [k, v] of Object.entries(extra)) {
            if (v !== null && v !== undefined)
                line += `  ${k}=${C.cyan}${v}${C.reset}`;
        }
    }

    if (CONFIG.SHOW_STACK) {
        try {
            const stack = Java.use("java.lang.Thread")
                .currentThread().getStackTrace();
            const frames = Array.from(stack)
                .map(f => `    ${f.getClassName()}.${f.getMethodName()}(${f.getFileName()}:${f.getLineNumber()})`)
                .filter(f => !f.includes("java.lang.Thread") && !f.includes("art."))
                .slice(0, 8)
                .join("\n");
            line += `\n${C.dim}${frames}${C.reset}`;
        } catch (_) {}
    }

    console.log(line);
}

// ─── Buffer / value helpers ────────────────────────────────────────────────────

function bytesToHex(arr) {
    if (!arr || arr.length === 0) return "";
    return Array.from(arr).map(b => (b & 0xff).toString(16).padStart(2, "0")).join(" ");
}

function tryString(arr) {
    if (!arr || arr.length === 0) return null;
    let s = "";
    for (const b of arr) {
        const c = b & 0xff;
        if (c === 0) break;
        if (c < 0x20 || c > 0x7e) return null;
        s += String.fromCharCode(c);
    }
    return s.length >= 4 ? s : null;
}

/**
 * Build a { hex, str, bytes } value object from a Java byte array.
 */
function fromJavaBytes(jBytes, minLen) {
    if (!jBytes) return null;
    const arr = Java.array("byte", jBytes);
    if (!arr || arr.length < (minLen || CONFIG.MIN_KEY_BYTES)) return null;
    const hex = bytesToHex(arr);
    const str = tryString(arr);
    const result = { hex, bytes: arr.length };
    if (str) result.str = str;
    return result;
}

/**
 * Build a value object from a NativePointer + length.
 */
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
    // new SecretKeySpec(byte[] key, String algorithm)
    // new SecretKeySpec(byte[] key, int offset, int len, String algorithm)
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
    } catch (e) { /* javax.crypto not available */ }

    // ── IvParameterSpec ────────────────────────────────────────────────────────
    try {
        const IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
        IvParameterSpec.$init.overload("[B")
            .implementation = function (iv) {
            const v = fromJavaBytes(iv, 1);
            if (v) report("IvParameterSpec.<init>", "IV", v);
            return this.$init(iv);
        };
    } catch (_) {}

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
            const sub = Java.array("byte", iv).slice(off, off + len);
            const v = fromJavaBytes(sub, 1);
            if (v) report("GCMParameterSpec.<init>(offset)", "NONCE", v, { tagBits: tlen });
            return this.$init(tlen, iv, off, len);
        };
    } catch (_) {}

    // ── PBEKeySpec (password-based) ────────────────────────────────────────────
    try {
        const PBEKeySpec = Java.use("javax.crypto.spec.PBEKeySpec");
        PBEKeySpec.$init.overload("[C", "[B", "int", "int")
            .implementation = function (password, salt, iter, keyLen) {
            const pw  = password ? Array.from(password).map(c => c & 0xff) : [];
            const pwStr = pw.map(c => String.fromCharCode(c)).join("");
            const sv  = fromJavaBytes(salt, 1);
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
    } catch (_) {}

    // ── Cipher.init ────────────────────────────────────────────────────────────
    // init(int opmode, Key key)
    // init(int opmode, Key key, AlgorithmParameterSpec params)
    try {
        const Cipher = Java.use("javax.crypto.Cipher");
        const MODES = { 1: "ENCRYPT", 2: "DECRYPT", 3: "WRAP", 4: "UNWRAP" };

        function cipherInit(opmode, key, params) {
            const algo = this.getAlgorithm ? this.getAlgorithm() : "?";
            const modeStr = MODES[opmode] || opmode;
            if (key) {
                try {
                    const encoded = key.getEncoded ? key.getEncoded() : null;
                    if (encoded) {
                        const v = fromJavaBytes(encoded);
                        if (v) report("Cipher.init", "KEY", v, { algo, mode: modeStr });
                    }
                } catch (_) {}
            }
            if (params) {
                // Try to extract IV from AlgorithmParameterSpec (IvParameterSpec or GCMParameterSpec)
                try {
                    const IvPS = Java.use("javax.crypto.spec.IvParameterSpec");
                    if (params instanceof IvPS.$class) {
                        const v = fromJavaBytes(params.getIV(), 1);
                        if (v) report("Cipher.init [params]", "IV", v, { algo });
                    }
                } catch (_) {}
                try {
                    const GCMPS = Java.use("javax.crypto.spec.GCMParameterSpec");
                    if (params instanceof GCMPS.$class) {
                        const v = fromJavaBytes(params.getIV(), 1);
                        if (v) report("Cipher.init [params]", "NONCE", v, { algo });
                    }
                } catch (_) {}
            }
        }

        Cipher.init.overload("int", "java.security.Key")
            .implementation = function (m, k) {
            cipherInit.call(this, m, k, null);
            return this.init(m, k);
        };
        Cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec")
            .implementation = function (m, k, p) {
            cipherInit.call(this, m, k, p);
            return this.init(m, k, p);
        };
    } catch (_) {}

    // ── Mac.init (HMAC) ────────────────────────────────────────────────────────
    try {
        const Mac = Java.use("javax.crypto.Mac");
        Mac.init.overload("java.security.Key")
            .implementation = function (key) {
            const algo = this.getAlgorithm ? this.getAlgorithm() : "?";
            if (key) {
                try {
                    const encoded = key.getEncoded();
                    const v = fromJavaBytes(encoded);
                    if (v) report("Mac.init", "HMAC_KEY", v, { algo });
                } catch (_) {}
            }
            return this.init(key);
        };
    } catch (_) {}

    // ── KeyGenerator.init – capture key size ───────────────────────────────────
    try {
        const KeyGenerator = Java.use("javax.crypto.KeyGenerator");
        KeyGenerator.init.overload("int")
            .implementation = function (keysize) {
            const algo = this.getAlgorithm ? this.getAlgorithm() : "?";
            report("KeyGenerator.init", "GENERIC",
                   { int: keysize, label: "key-size bits" }, { algo });
            return this.init(keysize);
        };
    } catch (_) {}

    // ── SecretKeyFactory.generateSecret ───────────────────────────────────────
    try {
        const SKF = Java.use("javax.crypto.SecretKeyFactory");
        SKF.generateSecret.overload("java.security.spec.KeySpec")
            .implementation = function (spec) {
            const key = this.generateSecret(spec);
            if (key) {
                try {
                    const encoded = key.getEncoded();
                    const v = fromJavaBytes(encoded);
                    if (v) report("SecretKeyFactory.generateSecret", "DERIVED", v,
                                  { algo: this.getAlgorithm() });
                } catch (_) {}
            }
            return key;
        };
    } catch (_) {}

    // ── MessageDigest – capture inputs and output ──────────────────────────────
    try {
        const MD = Java.use("java.security.MessageDigest");

        MD.update.overload("[B")
            .implementation = function (input) {
            const v = fromJavaBytes(input);
            if (v) report("MessageDigest.update", "HASH_IN", v,
                          { algo: this.getAlgorithm() });
            return this.update(input);
        };

        MD.digest.overload()
            .implementation = function () {
            const result = this.digest();
            const v = fromJavaBytes(result, 1);
            if (v) report("MessageDigest.digest", "HASH_OUT", v,
                          { algo: this.getAlgorithm() });
            return result;
        };
    } catch (_) {}

    // ── KeyAgreement.doPhase (DH / ECDH) ──────────────────────────────────────
    try {
        const KA = Java.use("javax.crypto.KeyAgreement");
        KA.doPhase.overload("java.security.Key", "boolean")
            .implementation = function (key, lastPhase) {
            const result = this.doPhase(key, lastPhase);
            if (lastPhase) {
                try {
                    const secret = this.generateSecret();
                    const v = fromJavaBytes(secret);
                    if (v) report("KeyAgreement.generateSecret [after doPhase]",
                                  "DH_SECRET", v, { algo: this.getAlgorithm() });
                } catch (_) {}
            }
            return result;
        };
    } catch (_) {}

    // ── SQLCipher – net.sqlcipher & org.signal.sqlcipher ──────────────────────
    const sqlcipherClasses = [
        "net.sqlcipher.database.SQLiteDatabase",
        "org.signal.sqlcipher.database.SQLiteDatabase",
        "net.zetetic.database.sqlcipher.SQLiteDatabase",
    ];
    for (const cls of sqlcipherClasses) {
        try {
            const SQLiteDB = Java.use(cls);
            // openOrCreateDatabase(String path, String password, ...)
            for (const m of SQLiteDB.openOrCreateDatabase.overloads) {
                m.implementation = function () {
                    const args = Array.from(arguments);
                    // password is typically the 2nd argument (String or char[])
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
                    return m.apply(this, arguments);
                };
            }
        } catch (_) {}
    }

    // ── Android Keystore – SecretKeyEntry import ───────────────────────────────
    try {
        const KeyStore = Java.use("java.security.KeyStore");
        KeyStore.setEntry.overload(
            "java.lang.String",
            "java.security.KeyStore$Entry",
            "java.security.KeyStore$ProtectionParameter"
        ).implementation = function (alias, entry, prot) {
            try {
                const SKE = Java.use("java.security.KeyStore$SecretKeyEntry");
                if (entry instanceof SKE.$class) {
                    const key = entry.getSecretKey();
                    const encoded = key.getEncoded();
                    if (encoded) {
                        const v = fromJavaBytes(encoded);
                        if (v) report("KeyStore.setEntry (SecretKeyEntry)", "KEY", v,
                                      { alias, algo: key.getAlgorithm() });
                    }
                }
            } catch (_) {}
            return this.setEntry(alias, entry, prot);
        };
    } catch (_) {}

    console.log(`${C.bold}${C.green}[*] Java crypto hooks installed${C.reset}`);
}); // Java.perform
} // CONFIG.JAVA_HOOKS

// ─── Native layer ──────────────────────────────────────────────────────────────

if (CONFIG.NATIVE_SCAN) {

/**
 * Resolve a symbol from any loaded library whose name matches libName regex.
 * Returns an array of { lib, addr } for every matching export.
 */
function findNativeExports(symName, libPattern) {
    const found = [];
    const pat = typeof libPattern === "string"
        ? new RegExp(libPattern, "i") : libPattern;

    for (const m of Process.enumerateModules()) {
        if (!pat.test(m.name)) continue;
        try {
            const exp = Module.findExportByName(m.name, symName);
            if (exp) found.push({ lib: m.name, addr: exp });
        } catch (_) {}
    }
    return found;
}

/**
 * Hook all instances of symName in all matching libs.
 */
function hookAllInstances(symName, libPattern, onEnter, onLeave) {
    const instances = findNativeExports(symName, libPattern);
    if (instances.length === 0) {
        // Also try global lookup (works for in-process static-link)
        const addr = Module.findExportByName(null, symName);
        if (addr) instances.push({ lib: "in-process", addr });
    }
    for (const { lib, addr } of instances) {
        try {
            Interceptor.attach(addr, {
                onEnter: onEnter ? function (args) { onEnter.call(this, args, lib); } : undefined,
                onLeave: onLeave ? function (ret)  { onLeave.call(this, ret, lib);  } : undefined,
            });
            console.log(`${C.dim}  [native] hooked ${symName} in ${lib}${C.reset}`);
        } catch (e) {
            console.log(`${C.dim}  [native] failed to hook ${symName} in ${lib}: ${e}${C.reset}`);
        }
    }
}

const CRYPTO_LIBS = /libcrypto|libssl|libsqlcipher|libsignalprotocol|libmolly|libsession/i;

// ── EVP_CipherInit_ex / EVP_EncryptInit_ex / EVP_DecryptInit_ex ───────────────
//   int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
//                         ENGINE *impl, const unsigned char *key,
//                         const unsigned char *iv, int enc);
//   Arg indices: 0=ctx, 1=type, 2=engine, 3=key, 4=iv, 5=enc

function evpCipherInitHook(fnName) {
    hookAllInstances(fnName, CRYPTO_LIBS, function (args, lib) {
        // key length depends on cipher; we read up to 64 bytes heuristically
        // (EVP_CIPHER_CTX_key_length requires calling back into OpenSSL which
        //  may deadlock — so we read a capped window and let output speak)
        const keyPtr = args[3];
        const ivPtr  = args[4];
        const enc    = args[5].toInt32();   // 1=encrypt, 0=decrypt, -1=no change

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

// Also hook the EVP_CipherInit_ex2 variant (BoringSSL / OpenSSL 3.x)
evpCipherInitHook("EVP_CipherInit_ex2");

// ── EVP_AEAD_CTX_init ──────────────────────────────────────────────────────────
//   int EVP_AEAD_CTX_init(EVP_AEAD_CTX *ctx, const EVP_AEAD *aead,
//                         const uint8_t *key, size_t key_len,
//                         size_t tag_len, ENGINE *impl);
hookAllInstances("EVP_AEAD_CTX_init", CRYPTO_LIBS, function (args, lib) {
    const keyPtr = args[2];
    const keyLen = args[3].toInt32();
    if (!keyPtr.isNull() && keyLen > 0) {
        const v = fromNativePtr(keyPtr, keyLen);
        if (v) report("EVP_AEAD_CTX_init", "AEAD_KEY", v, { lib, tagLen: args[4].toInt32() });
    }
});

// BoringSSL alternative name
hookAllInstances("EVP_AEAD_CTX_open",   CRYPTO_LIBS, () => {});  // just detect
hookAllInstances("EVP_AEAD_CTX_seal",   CRYPTO_LIBS, () => {});

// ── AES_set_encrypt_key / AES_set_decrypt_key ─────────────────────────────────
//   int AES_set_encrypt_key(const unsigned char *userKey, int bits, AES_KEY *key);
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
//   int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int key_len,
//                   const EVP_MD *md, ENGINE *impl);
hookAllInstances("HMAC_Init_ex", CRYPTO_LIBS, function (args, lib) {
    const keyPtr = args[1];
    const keyLen = args[2].toInt32();
    if (!keyPtr.isNull() && keyLen > 0) {
        const v = fromNativePtr(keyPtr, keyLen);
        if (v) report("HMAC_Init_ex", "HMAC_KEY", v, { lib });
    }
});

// ── PKCS5_PBKDF2_HMAC ─────────────────────────────────────────────────────────
//   int PKCS5_PBKDF2_HMAC(const char *pass, int passlen,
//                          const unsigned char *salt, int saltlen,
//                          int iter, const EVP_MD *digest,
//                          int keylen, unsigned char *out);
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
    // Capture derived key on return
    if (ret.toInt32() !== 0 && this._outPtr && !this._outPtr.isNull()) {
        const v = fromNativePtr(this._outPtr, this._keyLen);
        if (v) report("PKCS5_PBKDF2_HMAC [derived]", "DERIVED", v, { lib });
    }
});

// ── HKDF / HKDF_extract / HKDF_expand ────────────────────────────────────────
//   int HKDF(uint8_t *out_key, size_t out_len,
//            const EVP_MD *digest, const uint8_t *secret, size_t secret_len,
//            const uint8_t *salt, size_t salt_len,
//            const uint8_t *info, size_t info_len);
hookAllInstances("HKDF", CRYPTO_LIBS, function (args, lib) {
    const outPtr    = args[0];
    const outLen    = args[1].toInt32();
    const secPtr    = args[3];
    const secLen    = args[4].toInt32();
    const saltPtr   = args[5];
    const saltLen   = args[6].toInt32();

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

//   int HKDF_extract(uint8_t *out_key, size_t *out_len,
//                    const EVP_MD *digest,
//                    const uint8_t *secret, size_t secret_len,
//                    const uint8_t *salt, size_t salt_len);
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
    this._outPtr   = args[0];
    this._outLenPtr = args[1];
}, function (ret, lib) {
    if (this._outPtr && !this._outPtr.isNull()) {
        const outLen = this._outLenPtr ? this._outLenPtr.readUInt() : 32;
        const v = fromNativePtr(this._outPtr, outLen);
        if (v) report("HKDF_extract [prk]", "DERIVED", v, { lib });
    }
});

//   int HKDF_expand(uint8_t *out_key, size_t out_len,
//                   const EVP_MD *digest,
//                   const uint8_t *prk, size_t prk_len,
//                   const uint8_t *info, size_t info_len);
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
//   int sqlite3_key(sqlite3 *db, const void *pKey, int nKey);
//   int sqlite3_key_v2(sqlite3 *db, const char *zDbName,
//                      const void *pKey, int nKey);
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

// ── sqlite3_rekey / sqlite3_rekey_v2 ─────────────────────────────────────────
hookAllInstances("sqlite3_rekey", /.*/, function (args, lib) {
    const keyPtr = args[1];
    const keyLen = args[2].toInt32();
    if (!keyPtr.isNull() && keyLen > 0) {
        const v = fromNativePtr(keyPtr, keyLen, 1);
        if (v) report("sqlite3_rekey", "PASSPHRASE", v, { lib, note: "NEW key" });
    }
});

// ── EC_KEY_generate_key ───────────────────────────────────────────────────────
// Notify when a new EC key pair is generated (can be captured on d2i / getkey calls)
hookAllInstances("EC_KEY_generate_key", CRYPTO_LIBS, function (args, lib) {
    report("EC_KEY_generate_key", "GENERIC",
           { str: "EC key pair generation triggered", bytes: 0 }, { lib });
}, function (ret, lib) {
    // ret is the EC_KEY * – we can't easily dump the private scalar here
    // without knowing the curve order. Flag it for the analyst.
    if (ret.toInt32() === 1)
        report("EC_KEY_generate_key [done]", "GENERIC",
               { str: "EC key pair generated (use Keystore export or ECPrivateKey hook)", bytes: 0 }, { lib });
});

// ── ChaCha20_ctr32 / chacha20_poly1305_open (BoringSSL internal) ───────────────
// These are low-level but appear in Signal's ChaCha20-Poly1305 path
hookAllInstances("ChaCha20_ctr32", CRYPTO_LIBS, function (args, lib) {
    // void ChaCha20_ctr32(uint8_t *out, const uint8_t *in, size_t in_len,
    //                     const uint32_t key[8], const uint32_t counter[4])
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
║        frida_crypto_hooks.js – active               ║
╚══════════════════════════════════════════════════════╝${C.reset}
${C.dim}  Java hooks  : ${CONFIG.JAVA_HOOKS ? "ON" : "OFF"}
  Native hooks : ${CONFIG.NATIVE_SCAN ? "ON" : "OFF"}
  Stack trace  : ${CONFIG.SHOW_STACK ? "ON" : "OFF"}
  Dedup window : ${CONFIG.DEDUP_WINDOW} ms${C.reset}

  Toggle options:  (edit CONFIG at top of script)
  ${C.yellow}SHOW_STACK=true${C.reset} to see call stacks
  ${C.yellow}MIN_KEY_BYTES=N${C.reset} to filter short values
`);
