

                injekt v0.1
                ===========

[ Introduction

Injekt is another code injection tool written for windows operating 
systems. It can injekt PIC code into a 32-bit or 64-bit from either 
native or wow64 process which some other tools aren't capable of. 

If running in wow64 mode and target process is 64-bit, injekt will 
transition to 64-bit mode in order to create thread whereas some tools 
will just bail out, complaining it can't run thread. 

I wrote this specifically for testing win32 and win64 shellcode because 
while these codes can run fine by themselves, it's when you injekt it 
into another process space that reveals lots of problems. 




[ Usage

Currently, it has basic functionality but I hope to include new features
like loading and unloading of DLL modules in future.

  code injector v0.1
  Copyright (c) 2014, 2015 Odzhan


  usage: injekt [proc name | proc id] code.bin
  
Supply a process name or process id along with PIC file.
Let's say we want to injekt code into internet explorer.

You can pass iexplore.exe

  code injector v0.1
  Copyright (c) 2014, 2015 Odzhan


  [ warning: process requires admin privileges for some process

  [ opening exports.bin
  [ getting size
  [ allocating 221 bytes of memory for file
  [ reading
  [ opening process id 1696
  [ allocating 221 bytes of RW memory in process
  [ writing 221 bytes of code to 0x03C90000
  [ changing memory attributes to RX
  [ remote process is 64-bit
  [ attach debugger now or set breakpoint on 03C90000
  [ press any key to continue . . .
  
Since testing code can corrupt a process, I normally attach debugger 
here before continuing. 

injekt will wait for thread to terminate but if for any reason the 
remote process causes exception and dies, injekt has no idea what 
happened or why. 

The next thing to add to this tool would be displaying all processes 
available to user and requesting selection since iexplore.exe can be 32 
or 64 bit. 

For now, you should obtain process id using tasklist 



  
[ Detecting Wow64

Various ways to detect Wow64 mode have surfaced over the years and most 
simple ones exploit REX prefixes. Many 32-bit op-codes with REX prefixes 
can either increment or decrement a register. So for example, I'm 
setting eax register to zero and decreasing by 1. This will execute if 
32-bit mode but if wow64 will be ignored. The negate operation will 
change -1 to 1 or leave 0 as is. TRUE or FALSE. Neat, huh? 


  ; returns TRUE or FALSE
isWow64:
_isWow64:
    bits   32
    xor    eax, eax
    dec    eax
    neg    eax
    ret
    
[ Switching to x64 mode

We can switch code selectors in order to jump into 64-bit mode.
This happens in Wow64 applications already when emulator
needs to execute some 64-bit code.

  bits 32
  ; switch to x64 mode
sw64:
    call   isWow64
    jz     ext64                 ; we're already x64
    pop    eax                   ; get return address
    push   33h                   ; x64 selector
    push   eax                   ; return address
    retf                         ; go to x64 mode
ext64:
    ret
    
    
[ Switching back to x86 mode

Again, we're simply emulating the existing code inside wow64
host process.

  ; switch to x86 mode
sw32:
    call   isWow64
    jnz    ext32                 ; we're already x86
    pop    eax
    sub    esp, 8
    mov    dword[esp], eax
    mov    dword[esp+4], 23h     ; x86 selector
    retf
ext32:
    ret
    

Some of you may be looking for a library to perform all this.
I would suggest ReWolfs library.

https://github.com/rwfpl/rewolf-wow64ext
