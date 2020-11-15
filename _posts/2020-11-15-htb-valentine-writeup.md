---
title: HTB - Valentine Write-up
author: bigb0ss
date: 2020-11-15 19:36:00 +0800
categories: [Hack The Box, Linux, Easy]
tags: [hackthebox, valentine]
image: /assets/img/post/htb/valentine/01_infocard.png
---

This was an easy difficulty box. It was pretty easy and straight-forward box. Good learning path to:
* 


## Initial Recon

### Nmap

Let’s begin with an initial port scan:

```console
$ nmap -Pn --open -sV -sC -p- 10.10.10.79

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 96:4c:51:42:3c:ba:22:49:20:4d:3e:ec:90:cc:fd:0e (DSA)
|   2048 46:bf:1f:cc:92:4f:1d:a0:42:b3:d2:16:a8:58:31:33 (RSA)
|_  256 e6:2b:25:19:cb:7e:54:cb:0a:b9:ac:16:98:c6:7d:a9 (ECDSA)
80/tcp  open  http     Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=valentine.htb/organizationName=valentine.htb/stateOrProvinceName=FL/countryName=US
| Not valid before: 2018-02-06T00:45:25
|_Not valid after:  2019-02-06T00:45:25
|_ssl-date: 2020-11-15T22:16:49+00:00; +4m58s from scanner time.
```

<b>Interesting Ports to Note</b>

* HTTP (80/TCP) - Image file 
* HTTPS (443/TCP) - The same image file as port 80

![image](/assets/img/post/htb/valentine/02.png)


### Web Directory Enumeration (dirsearch)

Since we have only web ports to work with, we can go ahead and do some web directory enumeration using `dirsearch`.

```console
$ python3 dirsearch.py -u https://10.10.10.79/ -e php,txt,html | grep 200 
                                                                               
[17:27:44] 200 -    1KB - /dev/   
[17:27:50] 200 -   38B  - /index
[17:27:50] 200 -   38B  - /index.php     
[17:27:51] 200 -   38B  - /index.php/login/
```

It found a directory called `/dev/`. 

![image](/assets/img/post/htb/valentine/03.png)

The `notes.txt` wasn't too interesting but suggesting some type of client-side encoder/decoder structure. 

```console
https://10.10.10.79/dev/notes.txt

To do:

1) Coffee.
2) Research.
3) Fix decoder/encoder before going live.
4) Make sure encoding/decoding is only done client-side.
5) Don't use the decoder/encoder until any of this is done.
6) Find a better way to take notes.
```

On the other hand, the `hype_key` file was containing a long hex value. 

![image](/assets/img/post/htb/valentine/04.png)


### RSA Private Key 

Next, downloaded the `hype_key` using the following command:

```console
$ wget https://10.10.10.79/dev/hype_key --no-check-certificate
--2020-11-15 17:32:20--  https://10.10.10.79/dev/hype_key
Connecting to 10.10.10.79:443... connected.
WARNING: The certificate of ‘10.10.10.79’ is not trusted.
WARNING: The certificate of ‘10.10.10.79’ doesn't have a known issuer.
WARNING: The certificate of ‘10.10.10.79’ has expired.
The certificate has expired
The certificate's owner does not match hostname ‘10.10.10.79’
HTTP request sent, awaiting response... 200 OK
Length: 5383 (5.3K)
Saving to: ‘hype_key’

hype_key                                   100%[========================================================================================>]   5.26K  --.-KB/s    in 0s      

2020-11-15 17:32:20 (95.7 MB/s) - ‘hype_key’ saved [5383/5383]
```

Using the following `xxd` command, we can obtain the encrypted the private key:

```console
$ cat hype_key | xxd -r -p
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,AEB88C140F69BF2074788DE24AE48D46

DbPrO78kegNuk1DAqlAN5jbjXv0PPsog3jdbMFS8iE9p3UOL0lF0xf7PzmrkDa8R
5y/b46+9nEpCMfTPhNuJRcW2U2gJcOFH+9RJDBC5UJMUS1/gjB/7/My00Mwx+aI6
0EI0SbOYUAV1W4EV7m96QsZjrwJvnjVafm6VsKaTPBHpugcASvMqz76W6abRZeXi
Ebw66hjFmAu4AzqcM/kigNRFPYuNiXrXs1w/deLCqCJ+Ea1T8zlas6fcmhM8A+8P
OXBKNe6l17hKaT6wFnp5eXOaUIHvHnvO6ScHVWRrZ70fcpcpimL1w13Tgdd2AiGd
pHLJpYUII5PuO6x+LS8n1r/GWMqSOEimNRD1j/59/4u3ROrTCKeo9DsTRqs2k1SH
QdWwFwaXbYyT1uxAMSl5Hq9OD5HJ8G0R6JI5RvCNUQjwx0FITjjMjnLIpxjvfq+E
p0gD0UcylKm6rCZqacwnSddHW8W3LxJmCxdxW5lt5dPjAkBYRUnl91ESCiD4Z+uC
Ol6jLFD2kaOLfuyee0fYCb7GTqOe7EmMB3fGIwSdW8OC8NWTkwpjc0ELblUa6ulO
t9grSosRTCsZd14OPts4bLspKxMMOsgnKloXvnlPOSwSpWy9Wp6y8XX8+F40rxl5
XqhDUBhyk1C3YPOiDuPOnMXaIpe1dgb0NdD1M9ZQSNULw1DHCGPP4JSSxX7BWdDK
aAnWJvFglA4oFBBVA8uAPMfV2XFQnjwUT5bPLC65tFstoRtTZ1uSruai27kxTnLQ
+wQ87lMadds1GQNeGsKSf8R/rsRKeeKcilDePCjeaLqtqxnhNoFtg0Mxt6r2gb1E
AloQ6jg5Tbj5J7quYXZPylBljNp9GVpinPc3KpHttvgbptfiWEEsZYn5yZPhUr9Q
r08pkOxArXE2dj7eX+bq65635OJ6TqHbAlTQ1Rs9PulrS7K4SLX7nY89/RZ5oSQe
2VWRyTZ1FfngJSsv9+Mfvz341lbzOIWmk7WfEcWcHc16n9V0IbSNALnjThvEcPky
e1BsfSbsf9FguUZkgHAnnfRKkGVG1OVyuwc/LVjmbhZzKwLhaZRNd8HEM86fNojP
09nVjTaYtWUXk0Si1W02wbu1NzL+1Tg9IpNyISFCFYjSqiyG+WU7IwK3YU5kp3CC
dYScz63Q2pQafxfSbuv4CMnNpdirVKEo5nRRfK/iaL3X1R3DxV8eSYFKFL6pqpuX
cY5YZJGAp+JxsnIQ9CFyxIt92frXznsjhlYa8svbVNNfk/9fyX6op24rL2DyESpY
pnsukBCFBkZHWNNyeN7b5GhTVCodHhzHVFehTuBrp+VuPqaqDvMCVe1DZCb4MjAj
Mslf+9xK+TXEL3icmIOBRdPyw6e/JlQlVRlmShFpI8eb/8VsTyJSe+b853zuV2qL
suLaBMxYKm3+zEDIDveKPNaaWZgEcqxylCC/wUyUXlMJ50Nw6JNVMM8LeCii3OEW
l0ln9L1b/NXpHjGa8WHHTjoIilB5qNUyywSeTBF2awRlXH9BrkZG4Fc4gdmW/IzT
RUgZkbMQZNIIfzj1QuilRVBm/F76Y/YMrmnM9k/1xSGIskwCUQ+95CGHJE8MkhD3
-----END RSA PRIVATE KEY-----
```

> **NOTE**: -r - reverse operation: convert (or patch) hexdump into binary; -p - Output in postscript continuous hexdump style. Also known as plain hexdump style


### Decrypt RSA Private Key (Heartbleed)

When we try to decrypt the private key, it will prompt you with "Enter pass phrase..." 

```console
$ cat hype_key | xxd -p -r > hype_key_enc
$ openssl rsa -in hype_key.enc -out hype_key.dec
Enter pass phrase for hype_key.enc:
unable to load Private Key
140557154002176:error:06065064:digital envelope routines:EVP_DecryptFinal_ex:bad decrypt:../crypto/evp/evp_enc.c:583:
140557154002176:error:0906A065:PEM routines:PEM_do_header:bad decrypt:../crypto/pem/pem_lib.c:461:
```

So going back to the image in the web page, that appeared to be suggesting an attack called Heartbleed. In short, Heartbleed is an OpenSSL vulnerability that allows an attacker to trick the vulnreable web server to leak a chunk of memory. 





## Initial Foothold

### LFI (Mega Hosting Website)




## Privilege Escalation

### tomcat —> ash

