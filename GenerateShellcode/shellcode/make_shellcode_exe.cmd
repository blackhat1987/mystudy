cl.exe /O1 /Os /Oy /FD /MT /GS- /J /GR- /FAcs /W4 /Zl /c /TC shellcode.c
ml64 entry.asm /link /NODEFAULTLIB /RELEASE /MACHINE:X64 /SUBSYSTEM:CONSOLE /entry:my_hook shellcode.obj
move *.exe ..\build\entry.exe
del *.obj
del *.idb
del  mllink$.lnk