# -*- coding: utf-8 -*-
"""
@author: obaby
@license: (C) Copyright 2013-2020, obaby@mars.
@contact: root@obaby.org.cn
@link: http://www.obaby.org.cn
        http://www.h4ck.org.cn
        http://www.findu.co
@file: f_test.py
@time: 2020/6/29 13:35
@desc:
"""

import frida
import sys
rdev = frida.get_remote_device()
session = rdev.attach('com.ilulutv.fulao2')

src = """
Java.perform(function () {
  // Function to hook is defined here
  var base64 = Java.use('android.util.Base64');
  var aes = Java.use('com.ilulutv.fulao2.other.g.b');
    // 图片加密处理
    aes.b.overload("[B", "[B", "java.lang.String").implementation = function(k, iv, source_string){
        send("===========================override image a begin ===========================")
        send("Image_key:"+k);
        send(base64.encodeToString(k, 0))
        send("Image_iv:"+iv);
        send(base64.encodeToString(iv, 0))
        send("===========================override image a end ===========================")
        return this.b(k, iv, source_string);
    };
    // 接口加密处理
    aes.c.overload("[B", "[B", "java.lang.String").implementation = function(k, iv, source_string){
        send("===========================override c begin ===========================")
        send("key:"+k);
        send(base64.encodeToString(k, 0))
        send("iv:"+iv);
        send(base64.encodeToString(iv, 0))
        send("source_string:");
        send(source_string);
        var res = this.c(k, iv, source_string);
        send('result:');
        send(res)
        send("===========================override c end ===========================")
        return res;
    };
    // 接口解密处理
    aes.a.overload( "java.lang.String",  "java.lang.String", "java.lang.String").implementation = function(k, iv, source_string){
        send("===========================override a begin ===========================")
        send("key:"+k);
        //send(base64.encodeToString(k, 0))
        send("iv:"+iv);
        //send(base64.encodeToString(iv, 0))
        send("source_string:");
        send(source_string);
        var new_key = this.e(k);
        send("new key:" + new_key);
        var res = this.a(k, iv, source_string);
        send('result:');
        send(res)
        send("===========================override a end ===========================")
        return res;
    };
    aes.a.overload("[B", "[B", "java.lang.String").implementation = function(k, iv, source_string){
        send("===========================override a bytes begin ===========================")
        send("key:"+k);
        send(base64.encodeToString(k, 0))
        send("iv:"+iv);
        send(base64.encodeToString(iv, 0))
        send("source_string:");
        send(source_string);
        var res = this.a(k, iv, source_string);
        send('result:');
        send(res)
        send("===========================override a bytes end ===========================")
        return res;
    };
    // md5函数
    aes.e.overload("java.lang.String").implementation = function(source_string){
        send("===========================override e begin ===========================")
        send("source_string:");
        send(source_string);
        var res = this.e(source_string);
        send('result:');
        send(res)
        send("===========================override e end ===========================")
        return res;
    };
    
    aes.a.overload("i.r").implementation = function(source_string){
        send("===========================override ia  begin ===========================")
        send("source_string:");
        send(source_string.toString());
        var res = this.a(source_string);
        send('result:');
        send(res)
        send("===========================override ia end ===========================")
        return res;
    };
    
    var iv_class = Java.use('e.s');
    iv_class.a.overload("java.lang.String").implementation = function(arg2){
        send("===========================iv test ===========================")
        send("source_string:");
        send(arg2);
        var res = this.a(arg2);
        send('result:');
        send(res)
        send("===========================iv test ===========================")
        return res;
    };
});

"""

script = session.create_script(src)

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

script.on('message', on_message)
script.load()
sys.stdin.read()
