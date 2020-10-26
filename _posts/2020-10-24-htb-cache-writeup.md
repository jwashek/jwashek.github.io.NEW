---
title: HTB - Cache Write-up
author: bigb0ss
date: 2020-10-25 23:25:00 +0800
categories: [Hack The Box, Linux, Medium]
tags: [hackthebox, cache, vhost, openemr]
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

![image](/assets/img/post/htb/cache/04_after-login.png)

It was a bit of rabbit-hole. 

### VHOST

I also performed some directory brute-forceing against the `http://10.10.10.188/`; however, nothing seemed to be interesting. 

Then, I moved onto performing some of the potential subdomain enumerations, which didn't get me to far either. 

Next, I wanted to check for any potential VHOST (Virtural Hosting) for the domain. 

Modifed my `/etc/hosts` file to add `cache.htb` to `10.10.10.188`:

```bash
127.0.0.1       localhost
127.0.1.1       kali

### htb
10.10.10.188    cache.htb

### The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

Once it was done, using `FFUF`, I started to look for any potential VHOST associated with the Cache system. 

```console
# ./ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.htb" -u http://cache.htb -fw 902

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v0.12
________________________________________________

 :: Method           : GET
 :: URL              : http://cache.htb
 :: Header           : Host: FUZZ.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response words: 902
________________________________________________

hms                     [Status: 302, Size: 0, Words: 1, Lines: 1]
```

This found the permanent redirection (302) for `hms.htb`. I updated my `/etc/hosts` again to add `hms.htb` to `10.10.10.188`:

```bash
127.0.0.1       localhost
127.0.1.1       kali

### htb
10.10.10.188    cache.htb hms.htb

### The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

Then, I was able to access OpenEMR login page via `http:/hms.htb`.

![image](/assets/img/post/htb/cache/05_openemr.png)


## Initial Foothold

By Google searching about OpenEMR, I was able to discover some good amount of known vulnerabilities associated with this product. 

* Vulnerability Disclosure Report - https://www.open-emr.org/wiki/images/1/11/Openemr_insecurity.pdf

* OpenEMR Simulated Attack - https://www.youtube.com/watch?v=DJSQ8Pk_7hc

In a nutshell, the product was written in PHP and heavily vulnerable to multiple SQLi attacks because the codes were not sanitizing the user input properly, and most of the SQL syntax were not written in parameterized queries.

Additionally, the Vulnerability Disclosure Report also indicated that by browsing `/admin.php`, one can view the information about the installed OpenEMR product, such as the version info. 

![image](/assets/img/post/htb/cache/06_version.png)

### SQLi (OpenEMR)

According the the "OpenEMR Simulated Attack" video, we could bypass the authentication by visiting the `/portal` page and access pages like `add_edit_event_user.php` in order to identify the SQLi vuln. 

![image](/assets/img/post/htb/cache/07_portal.png)

![image](/assets/img/post/htb/cache/08_add-edit.png)

By adding `?eid='` at the end of the above page, we can cause the SQL error. 

![image](/assets/img/post/htb/cache/09_sql-error.png)





## Privilege Escalation


