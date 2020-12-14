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