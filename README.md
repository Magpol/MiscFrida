Bits and stuff.

Best cookie is:

frida_crypto_hooks.js
=====================
Intercepts cryptographic operations at both the Java (JCA/JCE) and native
(BoringSSL / OpenSSL / libcrypto.so) layers. Prints the hooked function name
alongside every key, IV, nonce, passphrase, or derived secret it observes.

## Hooked surface:
Java layer
-  javax.crypto.Cipher.init           – symmetric cipher key + IV
- avax.crypto.spec.SecretKeySpec    – raw key bytes at construction
- javax.crypto.spec.IvParameterSpec  – IV bytes
- javax.crypto.spec.GCMParameterSpec – GCM nonce
- javax.crypto.spec.PBEKeySpec       – password-based key spec
- javax.crypto.KeyGenerator.init     – key generation parameters
- javax.crypto.Mac.init              – HMAC / MAC key
- javax.crypto.KeyAgreement.doPhase  – DH/ECDH shared secret
- javax.crypto.SecretKeyFactory.generateSecret  – derived key
- java.security.MessageDigest        – hash inputs + outputs
- android.security.keystore (import / key-gen params)
- SQLCipher (net.sqlcipher / org.signal.sqlcipher)
- Signal libsignal-android key ops

## Native layer (libcrypto.so / libssl.so / in-process BoringSSL)
- EVP_CipherInit_ex / EVP_EncryptInit_ex / EVP_DecryptInit_ex
- EVP_AEAD_CTX_init                  – AEAD (AES-GCM / ChaCha20-Poly1305)
- AES_set_encrypt_key / AES_set_decrypt_key
- HMAC_Init_ex                       – HMAC key
- PKCS5_PBKDF2_HMAC                  – PBKDF2 key derivation
- HKDF / HKDF_extract / HKDF_expand  – HKDF
- sqlite3_key / sqlite3_key_v2       – SQLCipher passphrase (any library)
- EC_KEY_generate_key / RSA_generate_key_ex

## Configuration (edit the CONFIG block below):
- SHOW_STACK     – print Java/native call stack on each hit
- SHOW_HEX       – always show hex dump regardless of printability
- MIN_KEY_BYTES  – ignore buffers shorter than this (reduces noise)
- FILTER_PKG     – if non-empty, only print hits from this class prefix
- COLOUR         – ANSI-coloured output

## Usage:
frida -U -f <package> --no-pause -l frida_crypto_hooks.js
frida -U -p <pid>                -l frida_crypto_hooks.js

## Output format
Every hit prints one line:
- [KEY]  SecretKeySpec.<init>  (AES)  str="password123"  hex=70 61 73 73 77 6f 72 64 31 32 33  len=11
- [NONCE]  GCMParameterSpec.<init>  hex=a3 f1 9c 2b 00 11 22 33 44 55 66 77  tagBits=128  len=12
- [PASSPHRASE]  sqlite3_key  str=x'3e4a...  hex=78 27 33 65 ...  len=64  lib=libsqlcipher.so
- [DERIVED]  PKCS5_PBKDF2_HMAC [derived]  hex=8f 2a ...  lib=libcrypto.so
