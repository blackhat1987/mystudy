REM 清理项目垃圾文件
del *.sdf *.log 
del *.VC.db
del /s *.aps
del /a:h *.suo
rmdir /s /q .vs
rmdir /s /q ipch
rmdir /s /q build
rmdir /s /q TempMFCDll\x64
rmdir /s /q TempMFCDll\Win32