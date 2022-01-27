// Original script: https://www.codenong.com/jsecbee028022b/
//
// frida -U -f com.fun.app -l .\hook_AESDESRSA.js

var N_ENCRYPT_MODE = 1
var N_DECRYPT_MODE = 2

function showStacks() {
    var Exception = Java.use("java.lang.Exception");
    var ins = Exception.$new("Exception");
    var straces = ins.getStackTrace();

    if (undefined == straces || null == straces) {
        return;
    }

    console.log("============================= Stack strat=======================");
    console.log("");

    for (var i = 0; i < straces.length; i++) {
        var str = "   " + straces[i].toString();
        console.log(str);
    }

    console.log("");
    console.log("============================= Stack end=======================\r\n");
    Exception.$dispose();
}

var base64EncodeChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
    base64DecodeChars = new Array((-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), (-1), 62, (-1), (-1), (-1), 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, (-1), (-1), (-1), (-1), (-1), (-1), (-1), 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, (-1), (-1), (-1), (-1), (-1), (-1), 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, (-1), (-1), (-1), (-1), (-1));

function stringToBase64(e) {
    var r, a, c, h, o, t;
    for (c = e.length, a = 0, r = ''; a < c;) {
        if (h = 255 & e.charCodeAt(a++), a == c) {
            r += base64EncodeChars.charAt(h >> 2),
                r += base64EncodeChars.charAt((3 & h) << 4),
                r += '==';
            break
        }
        if (o = e.charCodeAt(a++), a == c) {
            r += base64EncodeChars.charAt(h >> 2),
                r += base64EncodeChars.charAt((3 & h) << 4 | (240 & o) >> 4),
                r += base64EncodeChars.charAt((15 & o) << 2),
                r += '=';
            break
        }
        t = e.charCodeAt(a++),
            r += base64EncodeChars.charAt(h >> 2),
            r += base64EncodeChars.charAt((3 & h) << 4 | (240 & o) >> 4),
            r += base64EncodeChars.charAt((15 & o) << 2 | (192 & t) >> 6),
            r += base64EncodeChars.charAt(63 & t)
    }
    return r
}
function base64ToString(e) {
    var r, a, c, h, o, t, d;
    for (t = e.length, o = 0, d = ''; o < t;) {
        do
            r = base64DecodeChars[255 & e.charCodeAt(o++)];
        while (o < t && r == -1);
        if (r == -1)
            break;
        do
            a = base64DecodeChars[255 & e.charCodeAt(o++)];
        while (o < t && a == -1);
        if (a == -1)
            break;
        d += String.fromCharCode(r << 2 | (48 & a) >> 4);
        do {
            if (c = 255 & e.charCodeAt(o++), 61 == c)
                return d;
            c = base64DecodeChars[c]
        } while (o < t && c == -1);
        if (c == -1)
            break;
        d += String.fromCharCode((15 & a) << 4 | (60 & c) >> 2);
        do {
            if (h = 255 & e.charCodeAt(o++), 61 == h)
                return d;
            h = base64DecodeChars[h]
        } while (o < t && h == -1);
        if (h == -1)
            break;
        d += String.fromCharCode((3 & c) << 6 | h)
    }
    return d
}
function hexToBase64(str) {
    return base64Encode(String.fromCharCode.apply(null, str.replace(/\r|\n/g, "").replace(/([\da-fA-F]{2}) ?/g, "0x$1 ").replace(/ +$/, "").split(" ")));
}
function base64ToHex(str) {
    for (var i = 0, bin = base64Decode(str.replace(/[ \r\n]+$/, "")), hex = []; i < bin.length; ++i) {
        var tmp = bin.charCodeAt(i).toString(16);
        if (tmp.length === 1)
            tmp = "0" + tmp;
        hex[hex.length] = tmp;
    }
    return hex.join("");
}
function hexToBytes(str) {
    var pos = 0;
    var len = str.length;
    if (len % 2 != 0) {
        return null;
    }
    len /= 2;
    var hexA = new Array();
    for (var i = 0; i < len; i++) {
        var s = str.substr(pos, 2);
        var v = parseInt(s, 16);
        hexA.push(v);
        pos += 2;
    }
    return hexA;
}
function bytesToHex(arr) {
    var str = '';
    var k, j;
    for (var i = 0; i < arr.length; i++) {
        k = arr[i];
        j = k;
        if (k < 0) {
            j = k + 256;
        }
        if (j < 16) {
            str += "0";
        }
        str += j.toString(16);
    }
    return str;
}
function stringToHex(str) {
    var val = "";
    for (var i = 0; i < str.length; i++) {
        if (val == "")
            val = str.charCodeAt(i).toString(16);
        else
            val += str.charCodeAt(i).toString(16);
    }
    return val
}
function stringToBytes(str) {
    var ch, st, re = [];
    for (var i = 0; i < str.length; i++) {
        ch = str.charCodeAt(i);
        st = [];
        do {
            st.push(ch & 0xFF);
            ch = ch >> 8;
        }
        while (ch);
        re = re.concat(st.reverse());
    }
    return re;
}

function bytesToString(arr) {
    var str = '';
    arr = new Uint8Array(arr);
    for (var i in arr) {
        str += String.fromCharCode(arr[i]);
    }
    return str;
}
function bytesToBase64(e) {
    var r, a, c, h, o, t;
    for (c = e.length, a = 0, r = ''; a < c;) {
        if (h = 255 & e[a++], a == c) {
            r += base64EncodeChars.charAt(h >> 2),
                r += base64EncodeChars.charAt((3 & h) << 4),
                r += '==';
            break
        }
        if (o = e[a++], a == c) {
            r += base64EncodeChars.charAt(h >> 2),
                r += base64EncodeChars.charAt((3 & h) << 4 | (240 & o) >> 4),
                r += base64EncodeChars.charAt((15 & o) << 2),
                r += '=';
            break
        }
        t = e[a++],
            r += base64EncodeChars.charAt(h >> 2),
            r += base64EncodeChars.charAt((3 & h) << 4 | (240 & o) >> 4),
            r += base64EncodeChars.charAt((15 & o) << 2 | (192 & t) >> 6),
            r += base64EncodeChars.charAt(63 & t)
    }
    return r
}
function base64ToBytes(e) {
    var r, a, c, h, o, t, d;
    for (t = e.length, o = 0, d = []; o < t;) {
        do
            r = base64DecodeChars[255 & e.charCodeAt(o++)];
        while (o < t && r == -1);
        if (r == -1)
            break;
        do
            a = base64DecodeChars[255 & e.charCodeAt(o++)];
        while (o < t && a == -1);
        if (a == -1)
            break;
        d.push(r << 2 | (48 & a) >> 4);
        do {
            if (c = 255 & e.charCodeAt(o++), 61 == c)
                return d;
            c = base64DecodeChars[c]
        } while (o < t && c == -1);
        if (c == -1)
            break;
        d.push((15 & a) << 4 | (60 & c) >> 2);
        do {
            if (h = 255 & e.charCodeAt(o++), 61 == h)
                return d;
            h = base64DecodeChars[h]
        } while (o < t && h == -1);
        if (h == -1)
            break;
        d.push((3 & c) << 6 | h)
    }
    return d
}
//stringToBase64 stringToHex stringToBytes
//base64ToString base64ToHex base64ToBytes
//               hexToBase64  hexToBytes    
// bytesToBase64 bytesToHex bytesToString


Java.perform(function () {
    var secretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    secretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function (a, b) {
        showStacks();
        var result = this.$init(a, b);
        console.log("======================================");
        console.log("secretKeySpec.$init： " + b + "|str: " + bytesToString(a));
        console.log("secretKeySpec.$init： " + b + "|Hex: " + bytesToHex(a));
        return result;
    }

    var DESKeySpec = Java.use('javax.crypto.spec.DESKeySpec');
    DESKeySpec.$init.overload('[B').implementation = function (a) {
        showStacks();
        var result = this.$init(a);
        console.log("======================================");
        var bytes_key_des = this.getKey();
        console.log("des  |str " + bytesToString(bytes_key_des));
        console.log("des  |hex " + bytesToHex(bytes_key_des));
        return result;
    }

    DESKeySpec.$init.overload('[B', 'int').implementation = function (a, b) {
        showStacks();
        var result = this.$init(a, b);
        console.log("======================================");
        var bytes_key_des = this.getKey();
        console.log("des  |str " + bytesToString(bytes_key_des));
        console.log("des  |hex " + bytesToHex(bytes_key_des));
        return result;
    }

    var mac = Java.use('javax.crypto.Mac');
    mac.getInstance.overload('java.lang.String').implementation = function (a) {
        showStacks();
        var result = this.getInstance(a);
        console.log("======================================");
        console.log("getInstance：" + a);
        return result;
    }
    mac.update.overload('[B').implementation = function (a) {
        //showStacks();
        this.update(a);
        console.log("======================================");
        //console.log("update:" + bytesToString(a));
		console.log("update:" + bytesToHex(a));
    }
    mac.update.overload('[B', 'int', 'int').implementation = function (a, b, c) {
        //showStacks();
        this.update(a, b, c)
        console.log("======================================");
        console.log("update:" + bytesToHex(a) + "|" + b + "|" + c);
    }
    mac.doFinal.overload().implementation = function () {
        //showStacks();
        var result = this.doFinal();
        console.log("======================================");
        console.log("doFinal: |str  :"     + bytesToString(result));
        console.log("doFinal: |hex  :"     + bytesToHex(result));
        console.log("doFinal: |base64  :"  + bytesToBase64(result));
        return result;
    }
    mac.doFinal.overload('[B').implementation = function (a) {
        //showStacks();
        var result = this.doFinal(a);
        console.log("======================================");
        console.log("doFinal: |str  :"     + bytesToString(a));
        console.log("doFinal: |str  :"     + bytesToString(result));
        console.log("doFinal: |hex  :"     + bytesToHex(result));
        console.log("doFinal: |base64  :"  + bytesToBase64(result));
        return result;
    }

    var md = Java.use('java.security.MessageDigest');
    md.getInstance.overload('java.lang.String', 'java.lang.String').implementation = function (a, b) {
        //showStacks();
        console.log("======================================");
        console.log("getInstance：" + a);
		console.log(Process.getCurrentThreadId());		
        return this.getInstance(a, b);
    }
    md.getInstance.overload('java.lang.String').implementation = function (a) {
        //showStacks();
        console.log("======================================");
        console.log("getInstance：" + a);
		console.log(Process.getCurrentThreadId());		
        return this.getInstance(a);
    }
    md.update.overload('[B').implementation = function (a) {
        //showStacks();
        console.log("======================================");
		console.log("update:" + bytesToHex(a));		
		console.log(Process.getCurrentThreadId());		
        return this.update(a);
    }
    md.update.overload('[B', 'int', 'int').implementation = function (a, b, c) {
        //showStacks();
        console.log("======================================");
        console.log("update:" + bytesToHex(a) + "|" + b + "|" + c);
		console.log(Process.getCurrentThreadId());		
        return this.update(a, b, c);
    }
    md.digest.overload().implementation = function () {
        //showStacks();
        console.log("======================================");
        var result = this.digest();
        console.log("digest result:" + bytesToHex(result));
        console.log("digest result:" + bytesToBase64(result));
		console.log(Process.getCurrentThreadId());
        return result;
    }
    md.digest.overload('[B').implementation = function (a) {
        //showStacks();
        console.log("======================================");
        console.log("digest arg:" + bytesToHex(a));
        var result = this.digest(a);
        console.log("digest result:" + bytesToHex(result));
        console.log("digest result:" + bytesToBase64(result));
		console.log(Process.getCurrentThreadId());
        return result;
    }

    var ivParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
    ivParameterSpec.$init.overload('[B').implementation = function (a) {
        //showStacks();
        var result = this.$init(a);
        console.log("======================================");
        console.log("iv: |str:" + bytesToString(a));
        console.log("iv: |hex:" + bytesToHex(a));
        return result;
    }

    var cipher = Java.use('javax.crypto.Cipher');
    cipher.getInstance.overload('java.lang.String').implementation = function (a) {
        //showStacks();
        var result = this.getInstance(a);
        console.log("======================================");
        console.log("getInstance:" + a);
		console.log(Process.getCurrentThreadId());		
        return result;
    }
    cipher.init.overload('int', 'java.security.Key').implementation = function (a, b) {
        //showStacks();
        var result = this.init(a, b);
        console.log("======================================");
        if (N_ENCRYPT_MODE == a) 
        {
            console.log("init  ");    
        }
        else if(N_DECRYPT_MODE == a)
        {
            console.log("init  ");    
        }

        var bytes_key = b.getEncoded();
        console.log("init key:" + "|str:" + bytesToString(bytes_key));
        console.log("init key:" + "|Hex:" + bytesToHex(bytes_key));
        return result;
    }
    cipher.init.overload('int', 'java.security.cert.Certificate').implementation = function (a, b) {
        //showStacks();
        var result = this.init(a, b);
        console.log("======================================");
        
        if (N_ENCRYPT_MODE == a) 
        {
            console.log("init ");    
        }
        else if(N_DECRYPT_MODE == a)
        {
            console.log("init ");    
        }

        return result;
    }
    cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function (a, b, c) {
        //showStacks();
        var result = this.init(a, b, c);
        console.log("======================================");
        
        if (N_ENCRYPT_MODE == a) 
        {
            console.log("init  ");    
        }
        else if(N_DECRYPT_MODE == a)
        {
            console.log("init  ");    
        }
     
        var bytes_key = b.getEncoded();
        console.log("init key:" + "|str:" + bytesToString(bytes_key));
        console.log("init key:" + "|Hex:" + bytesToHex(bytes_key));

        return result;
    }
    cipher.init.overload('int', 'java.security.cert.Certificate', 'java.security.SecureRandom').implementation = function (a, b, c) {
        //showStacks();
        var result = this.init(a, b, c);
        if (N_ENCRYPT_MODE == a) 
        {
            console.log("init ");    
        }
        else if(N_DECRYPT_MODE == a)
        {
            console.log("init ");    
        }
        return result;
    }
    cipher.init.overload('int', 'java.security.Key', 'java.security.SecureRandom').implementation = function (a, b, c) {
        //showStacks();
        var result = this.init(a, b, c);
        if (N_ENCRYPT_MODE == a) 
        {
            console.log("init  ");    
        }
        else if(N_DECRYPT_MODE == a)
        {
            console.log("init  ");    
        }

         var bytes_key = b.getEncoded();
        console.log("init key:" + "|str:" + bytesToString(bytes_key));
        console.log("init key:" + "|Hex:" + bytesToHex(bytes_key));
        return result;
    }
    cipher.init.overload('int', 'java.security.Key', 'java.security.AlgorithmParameters').implementation = function (a, b, c) {
        //showStacks();
        var result = this.init(a, b, c);
        if (N_ENCRYPT_MODE == a) 
        {
            console.log("init");    
        }
        else if(N_DECRYPT_MODE == a)
        {
            console.log("init");    
        }

        var bytes_key = b.getEncoded();
        console.log("init key:" + "|str:" + bytesToString(bytes_key));
        console.log("init key:" + "|Hex:" + bytesToHex(bytes_key));
        return result;
    }
    cipher.init.overload('int', 'java.security.Key', 'java.security.AlgorithmParameters', 'java.security.SecureRandom').implementation = function (a, b, c, d) {
        //showStacks();
        var result = this.init(a, b, c, d);
        if (N_ENCRYPT_MODE == a) 
        {
            console.log("init  ");    
        }
        else if(N_DECRYPT_MODE == a)
        {
            console.log("init ");    
        }

        var bytes_key = b.getEncoded();
        console.log("init key:" + "|str:" + bytesToString(bytes_key));
        console.log("init key:" + "|Hex:" + bytesToHex(bytes_key));
        return result;
    }
    cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec', 'java.security.SecureRandom').implementation = function (a, b, c, d) {
        //showStacks();
        var result = this.update(a, b, c, d);
        if (N_ENCRYPT_MODE == a) 
        {
            console.log("init  ");    
        }
        else if(N_DECRYPT_MODE == a)
        {
            console.log("init  ");    
        }

         var bytes_key = b.getEncoded();
        console.log("init key:" + "|str:" + bytesToString(bytes_key));
        console.log("init key:" + "|Hex:" + bytesToHex(bytes_key));
        return result;
    }

    cipher.update.overload('[B').implementation = function (a) {
        //showStacks();
        var result = this.update(a);
        console.log("======================================");
        console.log("update:" + bytesToHex(a));
        return result;
    }
    cipher.update.overload('[B', 'int', 'int').implementation = function (a, b, c) {
        //showStacks();
        var result = this.update(a, b, c);
        console.log("======================================");
        console.log("update:" + bytesToHex(a) + "|" + b + "|" + c);
        return result;
    }
    cipher.doFinal.overload().implementation = function () {
        //showStacks();
        var result = this.doFinal();
        console.log("======================================");
        console.log("doFinal: |str  :"     + bytesToString(result));
        console.log("doFinal: |hex  :"     + bytesToHex(result));
        console.log("doFinal: |base64  :"  + bytesToBase64(result));
        return result;
    }
    cipher.doFinal.overload('[B').implementation = function (a) {
        //showStacks();
        var result = this.doFinal(a);
        console.log("======================================");
        console.log("doFinal: |str  :"     + bytesToString(a));
        console.log("doFinal: |str  :"     + bytesToString(result));
        console.log("doFinal: |hex  :"     + bytesToHex(result));
        console.log("doFinal: |base64  :"  + bytesToBase64(result));
        return result;
    }

    var x509EncodedKeySpec = Java.use('java.security.spec.X509EncodedKeySpec');
    x509EncodedKeySpec.$init.overload('[B').implementation = function (a) {
        //showStacks();
        var result = this.$init(a);
        console.log("======================================");
        console.log("RSA:" + bytesToBase64(a));
        return result;
    }

    var rSAPublicKeySpec = Java.use('java.security.spec.RSAPublicKeySpec');
    rSAPublicKeySpec.$init.overload('java.math.BigInteger', 'java.math.BigInteger').implementation = function (a, b) {
        //showStacks();
        var result = this.$init(a, b);
        console.log("======================================");
        //console.log("RSA:" + bytesToBase64(a));
        console.log("RSAN:" + a.toString(16));
        console.log("RSAE:" + b.toString(16));
        return result;
    }

    var KeyPairGenerator = Java.use('java.security.KeyPairGenerator');
    KeyPairGenerator.generateKeyPair.implementation = function () 
    {
        //showStacks();
        var result = this.generateKeyPair();
        console.log("======================================");
        
        var str_private = result.getPrivate().getEncoded();
        var str_public = result.getPublic().getEncoded();
        console.log("generateKeyPair  |hex" + bytesToHex(str_public));
        console.log("generateKeyPair |hex" + bytesToHex(str_private));

        return result;
    }

    KeyPairGenerator.genKeyPair.implementation = function () 
    {
        //showStacks();
        var result = this.genKeyPair();
        console.log("======================================");

        var str_private = result.getPrivate().getEncoded();
        var str_public = result.getPublic().getEncoded();
        console.log("genKeyPair  |hex" + bytesToHex(str_public));
        console.log("genKeyPair  |hex" + bytesToHex(str_private));

        return result;
    }
});
