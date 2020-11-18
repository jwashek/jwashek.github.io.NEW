---
title: HTB - Valentine Write-up
author: bigb0ss
date: 2020-11-16 19:36:00 +0800
categories: [Hack The Box, Linux, Easy]
tags: [hackthebox, frolic, ]
image: /assets/img/post/htb/frolic/01_infocard.png
---

This was an easy difficulty box. Good learning path for:
* 


## Initial Recon

### Nmap

Let’s begin with an initial port scan:

```console

```

<b>Interesting Ports to Note</b>

* HTTP (80/TCP) - Image file 
* HTTPS (443/TCP) - The same image file as port 80

![image](/assets/img/post/htb/valentine/02.png)


### Web Directory Enumeration (dirsearch)





## Initial Foothold

### SSH (RSA Private Key)

<b>user.txt</b>



## Privilege Escalation

### hype —> root (Tmux)



<b>root.txt</b>



Thanks for reading!