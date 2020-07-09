@echo off
adb push .\libs\armeabi-v7a\mprop /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/mprop"

:: inject & hack
adb shell "/data/local/tmp/mprop"

:: verbose mode ==> dump memory 
:: adb shell "/data/local/tmp/mprop -v" > myprop.txt

:: restore
:: adb shell "/data/local/tmp/mprop -r"

:: change ro.xx property
adb shell "setprop ro.debuggable 1"

pause