---
title: HTB - Blunder Write-up
author: bigb0ss
date: 2020-10-24 23:25:00 +0800
categories: [Hack The Box, Box, Easy]
tags: [hackthebox, ]
---

![image](/assets/img/post/htb/blunder/01_infocard.png)

## Recon

### Nmap

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

### Interesting Ports

* HTTP (80/TCP) - Blunder Web Page. 

![image](/assets/img/post/htb/blunder/02_http.png)


### Dirsearch

Used [dirsearch](https://github.com/maurosoria/dirsearch) to further enumerate the website.

```console
# python3 dirsearch.py -u http://10.10.10.191/ -e txt,php,asp,js | grep 200

[15:41:45] 200 -  563B  - /.gitignore                               
[15:41:55] 200 -    3KB - /about                               
[15:42:00] 200 -    2KB - /admin/
[15:42:51] 200 -   30B  - /install.php
[15:42:54] 200 -    1KB - /LICENSE  
[15:43:13] 200 -    3KB - /README.md
[15:43:14] 200 -   22B  - /robots.txt  
```

When I visited to `/admin`, I was promoted to the following BLUDIT login page:

![image](/assets/img/post/htb/blunder/03_bludit.png)

Additionally, `/.gitignore` had a list of BLUDIT script contents. By searching, I was able to identify the version of the BLUDIT CMS in `http://10.10.10.191/bl-plugins/version/metadata.json`

![image](/assets/img/post/htb/blunder/04_version.png)


## Initial Foothold

### Password Bruteforcing

By Google searching, I found a potential [BLUDIT CMS 3.9.2 exploit](https://www.exploit-db.com/exploits/48701). But it required valid login credentials to the `/admin` page. 







