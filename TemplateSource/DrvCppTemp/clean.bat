REM 清理项目垃圾文件
del *.sdf *.log *.user *.ipch *.aps /s
del *.exe *.dll /s
del *.suo /s /a h
del *.ilk *.pdb *.tlog *.mainfest *.res /s
del *.obj *.pch *.codeanalysis *.codeanalysis/s
rmdir /s/q ipch Debug Release x64 .vs
del *.VC.db
rmdir /s /q build
rmdir /s /q DrvCppTemp\Win32
rmdir /s /q DrvCppTemp\x64
rmdir /s /q TestDrvR3\Win32
rmdir /s /q TestDrvR3\x64
