#!/usr/bin/env python
import frida
import sys

"""
var write = new NativeFunction(Module.findExportByName(null, 'write'),  'ssize_t', ['int', 'pointer',  'size_t']);
Interceptor.replace(write, new NativeCallback(function(d, f, e) {
    return write(d,f,e);
},   'ssize_t', ['int', 'pointer',  'size_t']));


Interceptor.attach(Module.findExportByName(null, "write"), {
  onEnter: function(args) {
    console.log(args[0].toInt32());
	var buffer = Memory.readByteArray(args[1], args[2].toInt32());
	console.log(hexdump(buffer, { offset: 0, length: 512, header: false, ansi: false }));
  },
  onLeave: function(retval) {
    console.log(retval);
  }
});


"""
device = frida.get_usb_device()
session = device.attach("teei_daemon")

def on_message(message, data):
    global index, filename
    if message['payload'] == 'output':
        with open("dump.bin", "wb") as d:
            d.write(data)
            d.close()
    else:
        print(message)

JSscript = ("""

Interceptor.attach(Module.findExportByName(null, "write"), {
  onEnter: function(args) {
    console.log(args[0].toInt32());
	let buffer = Memory.readByteArray(args[1], args[2].toInt32());
    send("output",buffer);
  },
  onLeave: function(retval) {
    console.log(retval);
  }
});

""")

script = session.create_script(JSscript)
script.load()
script.on('message', on_message)
sys.stdin.read()
