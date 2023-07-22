---
title: THM Intranet
author: hanhctf
date: 2023-06-17 12:22:22 +0700
categories: [Write-up, THM]
tags: []
toc: true
mermaid: true
---

# [**Intranet**](https://tryhackme.com/room/securesolacodersintra)

## NMAP

```
PORT     STATE SERVICE    REASON  VERSION
7/tcp    open  echo       syn-ack
21/tcp   open  ftp        syn-ack vsftpd 3.0.3
22/tcp   open  ssh        syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3d:0b:6f:e8:24:0d:28:91:8a:57:4d:13:b2:47:d9:44 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDCAEzEgoz8XABqBzA4NqG7tY9tmWdAzscmjgOVkCGnBhiJUH0RZKJwexacXshh7jd+SreQmh+zRzcpwvVifjplBYyGfSk8E3oa8kwgKSGBJmr1YzcG2UvFx0wCwNxzAXbiah40XEmZtybhNSO/jZZSAY9/xs7UPL05Nd2I2VBF06pPPonwfntImq//j1rpcoTCqeNIahMnkcsyNG9F9y6SxISfGjP7j7nTJ0LHctW8zcSwLt9BZxbr8Rl44t2LaH6TtciLf4DxbtOSaIxOGaymmkN4LIeEeuiwKbfLIaaeWsTP4td5lo4CQA9hjLtBbCbNV1vxi6lLGBTRuIN6Ulv2OeeyJ2EEXs2+2ZN68XxrMOSQ6xEQyDi4Qj3ipMzcnNkZdm1PCxlOTZYFPXR8v/KsZf9x09QePReUmkVyvhFtSt059wYbio1EQl8NJXt2XqbQ43eXkDOOnqAuaNZvAq8fGagW7Yw5QD4XpX0BcpUODR7aB6nVH8g7NwsKhOLKKs0=
|   256 9a:84:1c:a3:e3:7a:8f:4a:bb:6e:89:2d:f6:21:d5:f2 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCxO7ZoDPVxGbA/eW697KUh+sntYBYAxtkM5shrVbtkjhoS9RrsQhXvnjUOtt0Snvi6FiPcRsghK/ssYYsu3B2Y=
|   256 22:30:9e:17:08:45:9c:a8:73:d3:5a:3c:d7:5b:da:f3 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGii5ES9kD5kHbmntC53F2IAzqKMlaTaqSdUkzEV1aYM
23/tcp   open  telnet     syn-ack Linux telnetd
80/tcp   open  http       syn-ack Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
8080/tcp open  http-proxy syn-ack Werkzeug/2.2.2 Python/3.8.10
| http-methods: 
|_  Supported Methods: GET OPTIONS HEAD
| http-title: Site doesn't have a title (text/html; charset=utf-8).
|_Requested resource was /login
|_http-server-header: Werkzeug/2.2.2 Python/3.8.10
``` 

## Foothold


