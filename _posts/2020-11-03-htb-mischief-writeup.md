---
title: HTB - Mischief Write-up
author: bigb0ss
date: 2020-11-03 23:25:00 +0800
categories: [Hack The Box, Linux, Insance]
tags: [hackthebox, mischief]
---

![image](/assets/img/post/htb/mischief/01_infocard.png)



This box was pretty simple and easy one to fully compromise. Good learning path to:
* 
* 
* 

## Recon

### Nmap

Let’s begin with an initial port scan:

```console
$ nmap -Pn --open -p- -T4 -sC -sV 10.10.10.92

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 2a:90:a6:b1:e6:33:85:07:15:b2:ee:a7:b9:46:77:52 (RSA)
|   256 d0:d7:00:7c:3b:b0:a6:32:b2:29:17:8d:69:a6:84:3f (ECDSA)
|_  256 3f:1c:77:93:5c:c0:6c:ea:26:f4:bb:6c:59:e9:7c:b0 (ED25519)
3366/tcp open  caldav  Radicale calendar and contacts server (Python BaseHTTPServer)
| http-auth: 
| HTTP/1.0 401 Unauthorized\x0D
|_  Basic realm=Test
|_http-server-header: SimpleHTTP/0.6 Python/2.7.15rc1
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Let's also run a port scan against the UDP ports as well:

```console

```

### Interesting Ports

* HTTP (3366/TCP) - Website with Authentication Prompt. No easy credentials worked
* SNMP (161/UDP) - Simple Network Management Protocol

### SNMP (Credentials)

By using `snmpwalk`, we can see the list of the SNMP information. Especially, it reveals a set of credentials `loki : godofmischiefisloki`. 

```console
$ snmpwalk -v1 -c public 10.10.10.92

...snip...

iso.3.6.1.2.1.25.4.2.1.5.588 = STRING: "-m SimpleHTTPAuthServer 3366 loki:godofmischiefisloki --dir /home/loki/hosted/"
iso.3.6.1.2.1.25.4.2.1.5.603 = ""

...snip...
```

Using the found credentials, we could log into the `http://10.10.10.92:3366` page and find another set of credentials `loki : trickeryanddeceit`; however, it was dead-end. Using both of the credentials for `SSH` did not work either.

![image](/assets/img/post/htb/mischief/02_cred.png)

### SNMP (IPv6)

When we inspect the `snmpwalk` result again, we can see the hex-converted IPv6 address `222.173.190.239.0.0.0.0.2.80.86.255.254.185.104.27`:

```console
...snip

iso.3.6.1.2.1.4.34.1.6.1.4.10.10.10.92 = INTEGER: 2
iso.3.6.1.2.1.4.34.1.6.1.4.10.10.10.255 = INTEGER: 2
iso.3.6.1.2.1.4.34.1.6.1.4.127.0.0.1 = INTEGER: 2
iso.3.6.1.2.1.4.34.1.6.2.16.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1 = INTEGER: 2
iso.3.6.1.2.1.4.34.1.6.2.16.222.173.190.239.0.0.0.0.2.80.86.255.254.185.104.27 = INTEGER: 5
iso.3.6.1.2.1.4.34.1.6.2.16.254.128.0.0.0.0.0.0.2.80.86.255.254.185.104.27 = INTEGER: 5

...snip
```

Use the following `Python` script to covert the numbers into hex:

```python
# hexIPv6.py

import sys

hexIPv6 = sys.argv[1].split(".")

ip = ""

for i in hexIPv6:
    ip += hex(int(i))[2:].rjust(2, "0")

print ".".join(ip[i:i+4] for i in range(0, len(ip), 4))
```

```console
$ python hexIPv6.py 222.173.190.239.0.0.0.0.2.80.86.255.254.185.104.27
dead.beef.0000.0000.0250.56ff.feb9.681b
```

### Nmap (IPv6)

Let's run another scan against that IPv6 address. And this time, we can see the port 80 open.

```console
$nmap -Pn --open -6 -sC -sV dead:beef:0000:0000:0250:56ff:feb9:681b

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 2a:90:a6:b1:e6:33:85:07:15:b2:ee:a7:b9:46:77:52 (RSA)
|   256 d0:d7:00:7c:3b:b0:a6:32:b2:29:17:8d:69:a6:84:3f (ECDSA)
|_  256 3f:1c:77:93:5c:c0:6c:ea:26:f4:bb:6c:59:e9:7c:b0 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 400 Bad Request
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| address-info: 
|   IPv6 EUI-64: 
|     MAC address: 
|       address: 00:50:56:b9:68:1b
|_      manuf: VMware
```

Let's add the IPv6 address to our `/etc/hosts` in order to browse the HTTP (80/tcp) page in the browser.

```console
$ vi /etc/hosts

127.0.0.1       localhost
127.0.1.1       kali

### htb
dead:beef:0000:0000:0250:56ff:feb9:681b mischief.htb
```

Once we browser the page, we will be prompted with another login page.

![image](/assets/img/post/htb/mischief/03_login.png)









## Initial Foothold

### Password Bruteforcing


## Privilege Escalation

### www-data --> hugo (user.txt)


### hugo --> root (CVE-2019-14287)

