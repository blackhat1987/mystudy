REM 清理项目垃圾文件
del *.sdf *.log 
del *.VC.db
del /s *.aps
del /a:h *.suo
rmdir /s /q .vs
rmdir /s /q ipch
rmdir /s /q x64
rmdir /s /q Debug
rmdir /s /q Release
rmdir /s /q TempMFC\x64
rmdir /s /q TempMFC\Debug
rmdir /s /q TempMFC\Release