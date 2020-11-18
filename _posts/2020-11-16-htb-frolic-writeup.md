---
title: HTB - Valentine Write-up
author: bigb0ss
date: 2020-11-16 19:36:00 +0800
categories: [Hack The Box, Linux, Easy]
tags: [hackthebox, frolic, js, Ook!, frackzip]
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


### Decoding Ook! Programming Language

Google search found that this was an `Ook! Programing Language` so I used the online decoder to retrieve the following plain-text from it: `Nothing here check /asdiSIAJJ0QWE9JAS`.

![image](/assets/img/post/htb/frolic/10.png)


### Base64 Encoded Zip File

Next, I went to this directory `http://10.10.10.111:9999/asdiSIAJJ0QWE9JAS/`, and there was another challenge. It looked like a base64 encoded string. 

![image](/assets/img/post/htb/frolic/11.png)

First attempt to decode the base64 encode string resulted in `invalid input` error. 

```console
root@kali:~/Documents/htb/box/frolic# echo -n "UEsDBBQACQAIAMOJN00j/lsUsAAAAGkCAAAJABwAaW5kZXgucGhwVVQJAAOFfKdbhXynW3V4CwAB BAAAAAAEAAAAAF5E5hBKn3OyaIopmhuVUPBuC6m/U3PkAkp3GhHcjuWgNOL22Y9r7nrQEopVyJbs K1i6f+BQyOES4baHpOrQu+J4XxPATolb/Y2EU6rqOPKD8uIPkUoyU8cqgwNE0I19kzhkVA5RAmve EMrX4+T7al+fi/kY6ZTAJ3h/Y5DCFt2PdL6yNzVRrAuaigMOlRBrAyw0tdliKb40RrXpBgn/uoTj lurp78cmcTJviFfUnOM5UEsHCCP+WxSwAAAAaQIAAFBLAQIeAxQACQAIAMOJN00j/lsUsAAAAGkC AAAJABgAAAAAAAEAAACkgQAAAABpbmRleC5waHBVVAUAA4V8p1t1eAsAAQQAAAAABAAAAABQSwUG AAAAAAEAAQBPAAAAAwEAAAAA" | base64 -d
PK     É7M#�[�i index.phpUT     �|�[�|�[ux
                                          base64: invalid input
```

I noticed that there were some spaces within the encoded string, so I removed them and attemtped to decode it. And it decoded without any error this time.

```console
root@kali:~/Documents/htb/box/frolic# echo -n "UEsDBBQACQAIAMOJN00j/lsUsAAAAGkCAAAJABwAaW5kZXgucGhwVVQJAAOFfKdbhXynW3V4CwAB BAAAAAAEAAAAAF5E5hBKn3OyaIopmhuVUPBuC6m/U3PkAkp3GhHcjuWgNOL22Y9r7nrQEopVyJbs K1i6f+BQyOES4baHpOrQu+J4XxPATolb/Y2EU6rqOPKD8uIPkUoyU8cqgwNE0I19kzhkVA5RAmve EMrX4+T7al+fi/kY6ZTAJ3h/Y5DCFt2PdL6yNzVRrAuaigMOlRBrAyw0tdliKb40RrXpBgn/uoTj lurp78cmcTJviFfUnOM5UEsHCCP+WxSwAAAAaQIAAFBLAQIeAxQACQAIAMOJN00j/lsUsAAAAGkC AAAJABgAAAAAAAEAAACkgQAAAABpbmRleC5waHBVVAUAA4V8p1t1eAsAAQQAAAAABAAAAABQSwUG AAAAAAEAAQBPAAAAAwEAAAAA" | sed 's/ //g' | base64 -d
PK     É7M#�[�i index.phpUT     �|�[�|�[ux
                                          ^D�J�s�h�)�P�n
                                                        ��Ss�Jw▒܎��4��k�z��UȖ�+X��P��ᶇ��л�x_�N�[���S��8�����J2S�*�DЍ}�8dTQk������j_���▒���'xc��ݏt��75Q�
                                                                                                                                                       ���k,4��b)�4F��  ���������&q2o�WԜ�9P#�[�iPK É7M#�[�i ▒��index.phpUT�|�[ux
                                                    PKO
```

So, I outputed the result into a file `base64.dec`. When I `file` the file, it was a `zip` file, but it was protected with a password. 

```console
root@kali:~/Documents/htb/box/frolic# echo -n "UEsDBBQACQAIAMOJN00j/lsUsAAAAGkCAAAJABwAaW5kZXgucGhwVVQJAAOFfKdbhXynW3V4CwAB BAAAAAAEAAAAAF5E5hBKn3OyaIopmhuVUPBuC6m/U3PkAkp3GhHcjuWgNOL22Y9r7nrQEopVyJbs K1i6f+BQyOES4baHpOrQu+J4XxPATolb/Y2EU6rqOPKD8uIPkUoyU8cqgwNE0I19kzhkVA5RAmve EMrX4+T7al+fi/kY6ZTAJ3h/Y5DCFt2PdL6yNzVRrAuaigMOlRBrAyw0tdliKb40RrXpBgn/uoTj lurp78cmcTJviFfUnOM5UEsHCCP+WxSwAAAAaQIAAFBLAQIeAxQACQAIAMOJN00j/lsUsAAAAGkC AAAJABgAAAAAAAEAAACkgQAAAABpbmRleC5waHBVVAUAA4V8p1t1eAsAAQQAAAAABAAAAABQSwUG AAAAAAEAAQBPAAAAAwEAAAAA" | sed 's/ //g' | base64 -d > base64.dec

root@kali:~/Documents/htb/box/frolic# file base64.dec 
base64.dec: Zip archive data, at least v2.0 to extract

root@kali:~/Documents/htb/box/frolic# mv base64.dec base64.zip

root@kali:~/Documents/htb/box/frolic# unzip base64.zip 
Archive:  base64.zip
[base64.zip] index.php password:
```

<b>fcrackzip</b>

Then, I used `fcrackzip` to brute force the password for the `zip` file. The password was `password`.

```console
root@kali:~/Documents/htb/box/frolic# fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt base64.zip 


PASSWORD FOUND!!!!: pw == password
```

### Decoding index.php

The output file was looking like this:

```console
root@kali:~/Documents/htb/box/frolic# cat index.php 
4b7973724b7973674b7973724b7973675779302b4b7973674b7973724b7973674b79737250463067506973724b7973674b7934744c5330674c5330754b7973674b7973724b7973674c6a77720d0a4b7973675779302b4b7973674b7a78645069734b4b797375504373674b7974624c5434674c53307450463067506930744c5330674c5330754c5330674c5330744c5330674c6a77724b7973670d0a4b317374506973674b79737250463067506973724b793467504373724b3173674c5434744c53304b5046302b4c5330674c6a77724b7973675779302b4b7973674b7a7864506973674c6930740d0a4c533467504373724b3173674c5434744c5330675046302b4c5330674c5330744c533467504373724b7973675779302b4b7973674b7973385854344b4b7973754c6a776743673d3d0d0a
```

It looks like a hexdump, so when I reverse them into binary format, I can get 







## Initial Foothold

### SSH (RSA Private Key)

<b>user.txt</b>



## Privilege Escalation

### hype —> root (Tmux)



<b>root.txt</b>



Thanks for reading!