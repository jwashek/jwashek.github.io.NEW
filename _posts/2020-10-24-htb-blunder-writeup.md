---
title: HTB - Blunder Write-up
author: bigb0ss
date: 2020-10-24 23:25:00 +0800
categories: [Hack The Box, Box, Easy]
tags: [hackthebox, ]
---

![image](/assets/img/post/htb/blunder/01_infocard.png)

## Nmap

Let’s begin with an initial port scan:

```console
# nmap -Pn --open -p- -sC -sV 10.10.10.191

Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-24 14:25 EDT
Nmap scan report for 10.10.10.191
Host is up (0.081s latency).
Not shown: 65533 filtered ports, 1 closed port
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: Blunder
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Blunder | A blunder of interesting facts

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 117.15 seconds
```

### Interesting Ports to Note

