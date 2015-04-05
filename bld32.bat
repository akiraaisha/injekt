@echo off
yasm -fwin32 wow64.asm
cl /nologo /O1 injekt.cpp wow64.obj
move injekt.exe bin\x86\
del *.obj *.err