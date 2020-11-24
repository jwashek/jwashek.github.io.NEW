---
title: HTB - ServMon Write-up
author: bigb0ss
date: 2020-11-23 23:25:00 +0800
categories: [Hack The Box, Windows, Easy]
tags: [hackthebox, servmon, ]
image: /assets/img/post/htb/servmon/01_infocard.png
---

This one was an easy-difficulty Windows box. Good learning path for:
* 


# Initial Recon

## Nmap

Let’s begin with an initial port scan:

```console

```



### Interesting Ports to Note

* FTP (21/TCP) - FTP service & Anonymous login allowed
* HTTP (80/TCP) - NVMS-1000 login page

![image](/assets/img/post/htb/servmon/02.png)

* LDAP (389/TCP) 
* SMB (445/TCP)
* HTTPS (443/TCP) 
* WinRM (5985/TCP) - Can be used for PowerShell remote login






# Initial Foothold

## 


# Privilege Escalation

## 

Thanks for reading!

