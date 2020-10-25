---
title: HTB - Cache Write-up
author: bigb0ss
date: 2020-10-25 23:25:00 +0800
categories: [Hack The Box, Linux, Medium]
tags: [hackthebox, cache, ]
---

![image](/assets/img/post/htb/cache/01_infocard.png)

## Recon

### Nmap

Let’s begin with an initial port scan:

```console
$ nmap -Pn --open -p- -sC -sV 10.10.10.188
Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-25 16:34 EDT
Nmap scan report for 10.10.10.188
Host is up (0.080s latency).
Not shown: 65533 closed ports

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a9:2d:b2:a0:c4:57:e7:7c:35:2d:45:4d:db:80:8c:f1 (RSA)
|   256 bc:e4:16:3d:2a:59:a1:3a:6a:09:28:dd:36:10:38:08 (ECDSA)
|_  256 57:d5:47:ee:07:ca:3a:c0:fd:9b:a8:7f:6b:4c:9d:7c (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Cache
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Interesting Ports

* HTTP (80/TCP) - Cache Web Page.

### Login Page

The HTTP (80/TCP) page has a menu for `Login`. 

![image](/assets/img/post/htb/cache/02_login.png)

When I inspected the source code of the login page, there was a script called `functionality.js` which was responsible for the `client-side` authentication. 

![image](/assets/img/post/htb/cache/03_source-1.png)

The following username and password (ash:H@v3_fun) found within the script:

```js
$(function(){
    
    var error_correctPassword = false;
    var error_username = false;
    
    function checkCorrectPassword(){
        var Password = $("#password").val();
        if(Password != 'H@v3_fun'){
            alert("Password didn't Match");
            error_correctPassword = true;
        }
    }
    function checkCorrectUsername(){
        var Username = $("#username").val();
        if(Username != "ash"){
            alert("Username didn't Match");
            error_username = true;
        }
    }
```

Once logged in, there was the following static page:

![image](/assets/img/post/htb/cache/04-after-login.png)



## Initial Foothold




## Privilege Escalation


