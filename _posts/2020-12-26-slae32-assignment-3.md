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
Personally, I have dealt with Egghunter when I was taking the [OSCE course](https://www.offensive-security.com/offsec/retiring-ctp-intro-new-courses/) form Offensive Security. The Egghunter is essentially a staged payload that can redirect the execution flow to specific location in memory. The Egghunter is comprised with relatively short shellcode (around 32 bytes), so if the first buffer space is limited, we can implement the Egghunter shellcode payload there, and this will searche the process memory for the much bigger buffer space where we place the signature (aka "Egg") with our final reverse/bing shellcode.

The below image is very simplified version of how the Egghunter works: 

![image](/assets/img/post/slae32/assignment3/01.png)






<b>This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:</b>

<b>http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/</b>

<b>Student ID: SLAE-1542</b>

[SLAE32 Assignemt#3 Github](https://github.com/bigb0sss/SLAE32)