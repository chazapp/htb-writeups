============================== POSTMAN =========================================
============================     HTB         ===================================
========================      By Chazapp      ==================================

Started: 11/02/2019 
Postman on HTB. The IP is 10.10.10.160, its a linux box by TheCyberGeek. Let's
dive in.

We start by standard nmap:
```
$ echo "10.10.10.160    postman.htb" >> /etc/hosts
$ nmap -sV -sC -oA nmap/initial postman.htb 
```

We then run a complete port scan
```
$ nmap -sV -sC -p- -oA nmap/initial postman.htb
``` 
Meanwhile we check the nmap file:
PORT 22 runs ssh
Port 80 runs HTTP
Port 10000  runs MiniServ 1.910 (Webmin httpd)

On http we like gobuster:
```
$gobuster dir --url http://postman.htb -t 100 -w directory-list-2.3-medium.txt 
$ cat gobuster.txt 
/images (Status: 301)
/upload (Status: 301)
/css (Status: 301)
/js (Status: 301)
/fonts (Status: 301)
```

Upload dir show a bunch of jpegs on the website

On port 10000 we find a Webmin admin login page; google says default creds are
admin:<root_password>. 
We try some hydra with no luck:

```
$ hydra -l admin -P /usr/share/wordlists/rockyou.txt "https-post-form://postman.htb:10000/session_login.cgi:user=^USER^&pass=^PASS^:Login failed. Please try again."
```

Tried metasploit exploit/unix/webapp/webmin_backdoor ; machine not vulnerable
Tried forcing with `curl -k  -X POST https://postman.htb:10000/password_change.cgi`
to avoid SSL verification, no luck either

When running a nmap -p- script, do not use use -T5 like an ape. Running nmap without
-T5 shows redis port 6379 Redis key-value store 4.0.9

We run this exploit that drops us as `redis` user:
https://github.com/Avinash-acid/Redis-Server-Exploit/ 

We upload LinEnum.sh to /tmp/, then exfiltrate the results.

We find that there is a Matt user to privesc to. This user has the user.txt flag.


Interesting thing: We find this file:
```
[-] Location and Permissions (if accessible) of .bak file(s):
-rwxr-xr-x 1 Matt Matt 1743 Aug 26 00:11 /opt/id_rsa.bak
```

We exfiltrate this file, which is an encrypted SSH key. Using john & rockyou.txt
we crack its password:
```
$ /usr/share/john/ssh2john.py id_rsa_matt.bak > id_rsa_matt.hash
$ john id_rsa_matt.hash --wordlist=/usr/share/wordlists/rockyou.txt 
...
computer2008     (id_rsa_matt.bak)
1g 0:00:00:23 DONE (2020-02-15 16:56) 0.04228g/s 606414p/s 606414c/s 606414C/sa6_123..*7¡Vamos!
```

We then use this password to connect to the box as Matt via ssh
```
$ ssh -i id_rsa_matt.bak Matt@postman.htb
Enter passphrase for key 'id_rsa_matt.bak': 
Connection closed by 10.10.10.160 port 22
root@kali:~/htb/postman# 
```

We immediately drop. Checking sshd_config could tell use why.
Still, we got Matt:computer2008 credentials match. Using those allows us access
to the Webmin admin page.
Using this metasploit module: https://www.exploit-db.com/exploits/46984 that
leverages CVE-2019-12840, We are able to obtain a root shell on the box.

We exfiltrate /home/Matt/user.txt & /root/root.txt
We owned the box.
