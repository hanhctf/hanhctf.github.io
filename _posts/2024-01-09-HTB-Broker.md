---
title: HTB MonitorsTwo
author: hanhctf
date: 2024-01-09 16:22:22 +0700
categories: [Write-up, HTB]
tags: []
toc: true
mermaid: true
---

# [**MonitorsTwo**](<https://www.hackthebox.com/achievement/machine/108910/578Z>)

## NMAP

```shell
PORT      STATE SERVICE    REASON  VERSION
22/tcp    open  ssh        syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http       syn-ack nginx 1.18.0 (Ubuntu)
1331/tcp  open  http       syn-ack nginx 1.18.0 (Ubuntu)
1337/tcp  open  http       syn-ack nginx 1.18.0 (Ubuntu)
1338/tcp  open  http       syn-ack nginx 1.18.0 (Ubuntu)
1883/tcp  open  mqtt       syn-ack
5672/tcp  open  amqp?      syn-ack
8161/tcp  open  http       syn-ack Jetty 9.4.39.v20210325
33253/tcp open  tcpwrapped syn-ack
61613/tcp open  stomp      syn-ack Apache ActiveMQ
61614/tcp open  http       syn-ack Jetty 9.4.39.v20210325
61616/tcp open  apachemq   syn-ack ActiveMQ OpenWire transport
```

## Web enumeration

Open website on port 80, we get login form requirement.
![](/commons/HTB/Broker/0.login.png)

Try use default common credential **admin;admin**
We can login.

![](/commons/HTB/Broker/1.version.png)
We can see version of Apache ActiveMQ is 5.15.15 which is vulnerability CVE-2023-46604.

Quick search exploit PoC --> [github](https://github.com/sule01u/CVE-2023-46604).
