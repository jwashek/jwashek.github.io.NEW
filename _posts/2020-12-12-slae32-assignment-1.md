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


# What is Bind Shell?
Bind TCP opens up a port on the victim system. If an attacker could exploit a vulnerability on the victim system, she can implant a bind shell and connect to it from the remote attaking box. However, due to a firewall and detection controls, reverse TCP shell is preferrable over bind TCP shell thesedays.

![image](/assets/img/post/slae32/assignment1/01.png)






















