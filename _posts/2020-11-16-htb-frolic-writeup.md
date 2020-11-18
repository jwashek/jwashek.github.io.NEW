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
$ nmap -Pn --open -sC -sV -p- 10.10.10.111

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 87:7b:91:2a:0f:11:b6:57:1e:cb:9f:77:cf:35:e2:21 (RSA)
|   256 b7:9b:06:dd:c2:5e:28:44:78:41:1e:67:7d:1e:b7:62 (ECDSA)
|_  256 21:cf:16:6d:82:a4:30:c3:c6:9c:d7:38:ba:b5:02:b0 (ED25519)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
1880/tcp open  http        Node.js (Express middleware)
|_http-title: Node-RED
9999/tcp open  http        nginx 1.10.3 (Ubuntu)
|_http-server-header: nginx/1.10.3 (Ubuntu)
|_http-title: Welcome to nginx!
Service Info: Host: FROLIC; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -1h44m59s, deviation: 3h10m31s, median: 4m59s
|_nbstat: NetBIOS name: FROLIC, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: frolic
|   NetBIOS computer name: FROLIC\x00
|   Domain name: \x00
|   FQDN: frolic
|_  System time: 2020-11-18T08:21:47+05:30
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-11-18T02:51:47
|_  start_date: N/A
```

<b>Interesting Ports to Note</b>

* SMB (445/TCP) - Samba share is always interesting. We can check for something like anonymous share access. But no anonymous access for this host.

* HTTP (1880/TCP) - Node-RED login page. Command logins like `admin : admin` did not work. 

![image](/assets/img/post/htb/frolic/02.png)

* HTTP (9999/TCP) - Default nginx page. Referring to `http://forlic.htb:1880` url. Maybe indicating a vhost routing. I added the above url to my `/etc/hosts` file to check it; however, it wasn't utilizing a vhost. 

![image](/assets/img/post/htb/frolic/03.png)


### Web Directory Enumeration (gobuster)

Let's run `gobuster` against the web service. 

```console
$ gobuster dir -u http://10.10.10.111:9999/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.111:9999/
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/11/17 21:46:17 Starting gobuster
===============================================================
/admin (Status: 301)
/test (Status: 301)
/dev (Status: 301)
/backup (Status: 301)
/loop (Status: 301)
```

It found the several interesting directories. 

`/dev` and `/loop` were forbidden pages.

`/admin` was another login page:

![image](/assets/img/post/htb/frolic/04.png)

`/test` was a `phpinfo()` page:

![image](/assets/img/post/htb/frolic/05.png)

`/backup` had some more interesting files. We can obtain a set of credentials from these files: `admin : imnothuman`. These credentials did not work for both Node-RED and c'mon i m hackable logins. 

![image](/assets/img/post/htb/frolic/06.png)


### Source Code Review (c'mon i m hackable Login)

Next, I quickly checked the source code for the c'mon i m hackable login page and found an interesting JavaScript `login.js`.

![image](/assets/img/post/htb/frolic/07.png)

I was essentially a client-side login script that disclosed the login credentials: `admin : superduperlooperpassword_lol` and the redirecting page after login: `success.html`.

![image](/assets/img/post/htb/frolic/08.png)

The `success.html` was a bunch of weird characters... indicating another puzzle game.

![image](/assets/img/post/htb/frolic/09.png)




## Initial Foothold

### SSH (RSA Private Key)

<b>user.txt</b>



## Privilege Escalation

### hype —> root (Tmux)



<b>root.txt</b>



Thanks for reading!