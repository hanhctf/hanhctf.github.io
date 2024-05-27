---
title: HTB Bizness
author: hanhctf
date: 2024-05-27 12:00:00 +0700
categories: [Write-up, HTB]
tags: [CVE-2023-51467]
toc: true
mermaid: true
---

# [**Bizness**](https://app.hackthebox.com/machines/Bizness)

# Summary

> - 
> - 
> -  
> -  

## NMAP

```text
PORT      STATE SERVICE    REASON  VERSION
22/tcp    open  ssh        syn-ack OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
80/tcp    open  http       syn-ack nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to https://bizness.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST
443/tcp   open  ssl/http   syn-ack nginx 1.18.0
45465/tcp open  tcpwrapped syn-ack
```

## Web Enumeration

Add `bizness.htb` to `/etc/hosts'  


