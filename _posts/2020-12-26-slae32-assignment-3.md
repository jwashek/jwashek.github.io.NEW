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
Personally, I have dealt with Egghunter when I was studying for the [OSCE course](https://www.offensive-security.com/offsec/retiring-ctp-intro-new-courses/) form Offensive Security. Egghunter is essentially a staged payload and is comprised with relatively short shellcode (around 32 bytes). In a situation where the first buffer space is limited, we can implement the Egghunter shellcode there, and this will search the process memory for the much bigger buffer space where we place the signature (aka "Egg") with our final reverse/bing shellcode.

The below image is a simplified version of how Egghunter works: 

![image](/assets/img/post/slae32/assignment3/01.png)

# Egghunter In Depth

![image](/assets/img/post/slae32/assignment3/02.png)

Even though I knew what Egghunter was and how to use it, I wanted to understand it in greater detail. So I read Matt Miller's [Safely Searching Process Virtual Address Space](http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf) to learn more about Egghunter. 

The following is the key take aways from the article:

1) Per the author, 8 byte egg is recommended since it can give enough uniquness that it can eaily selected without running any high risk of a collision. 

2) In Linux implementation, there are two main methods: a) SIGSEGV handler to catch invalid memory address dereferences and prevent the program from crashing; b) Using OS' system call interface to validate process VMAs in kernel mode. 



<b>This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:</b>

<b>http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/</b>

<b>Student ID: SLAE-1542</b>

[SLAE32 Assignemt#3 Github](https://github.com/bigb0sss/SLAE32)