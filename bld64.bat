@echo off
yasm -f win64 wow64.asm
cl /nologo /O1 injekt.cpp wow64.obj
move injekt.exe bin\x64\
del *.obj *.err