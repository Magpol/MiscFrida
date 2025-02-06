// frida -U -f com.wire -l earlyInstr.js
// Hook library on launch and get values from function...
function tryHookTestlib() {
    var baseAddr = Module.findBaseAddress("libsqlcipher.so");
    if (baseAddr) {
        console.log("libsqlcipher.so loaded at: " + baseAddr);
        hookTestlibFunctions(baseAddr);
    } else {
        setTimeout(tryHookTestlib, 100);
    }
}

function hookTestlibFunctions(baseAddr) {
    var targetFunc = Module.findExportByName("libsqlcipher.so", "sqlite3_key");
    if (targetFunc) {
        console.log("Hooking target_function at: " + targetFunc + " at baseadress: " + baseAddr);
        Interceptor.attach(targetFunc, {
            onEnter: function (args) {
               console.log("[Database]-> " + args[0]);  
                console.log(hexdump(args[1]), {
                    offset: 0,
                    length: args[2].toInt32(),
                    header: true,
                    ansi: true
                }); // print key part
               console.log("[length]-> " + args[2].toInt32());  // print key length   
                console.log("sqlite3_key called from:\n" +
                Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress).join("\n") + "\n");      
                console.log("Use \"addr2line -f -C -i -e libsqlcipher.so libname!0xadress\" to get functionname...");
            },
            onLeave: function (retval) {
                console.log("target_function returned: " + retval);
            }
        });
    } else {
        console.log("target_function not found in libsqlcipher.so");
    }
}

tryHookTestlib();

/*
To find all exported *sqlite* functions...

Module.enumerateExports("libsqlcipher.so", {
    onMatch: function(exp) {
        if (exp.name.indexOf("sqlite") !== -1) {
            console.log("Name: " + exp.name + " | Address: " + exp.address + " | Type: " + exp.type);
        }
    },
    onComplete: function() {
        console.log("Export enumeration complete.");
    }
});

*/
