@echo off
del *.sdf
del *.exe
del *.VC.db
del *.log
del /s *.aps
del /a:h *.suo
rmdir /s /q .vs
rmdir /s /q ipch
rmdir /s /q build
rmdir /s /q shellcode\Win32
rmdir /s /q shellcode\x64
rmdir /s /q Ror13Calc\Win32
rmdir /s /q Ror13Calc\x64
rmdir /s /q shellcode_maker\Win32
rmdir /s /q shellcode_maker\x64
