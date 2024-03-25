---
title: HTB Sandworm
author: hanhctf
#date: 2023-06-22 00:00:00 +0700
categories: [Write-up, HTB]
tags: [GPG]
toc: true
mermaid: true
---

# [**Jupiter**](https://www.hackthebox.comachievement/machine/108910/548)

## NMAP

```shell
PORT    STATE SERVICE  REASON  VERSION
22/tcp  open  ssh      syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH2y17GUe6keBxOcBGNkWsliFwTRwUtQB3NXEhTAFLziGDfCgBV7B9Hp6GQMPGQXqMk7nnveA8vUz0D7ug5n04A=
|   256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfXa+OM5/utlol5mJajysEsV4zb/L0BJ1lKxMPadPvR
80/tcp  open  http     syn-ack nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://ssa.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
443/tcp open  ssl/http syn-ack nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: HEAD GET OPTIONS
|_http-title: Secret Spy Agency | Secret Security Service
|_http-server-header: nginx/1.18.0 (Ubuntu)
| ssl-cert: Subject: commonName=SSA/organizationName=Secret Spy Agency/stateOrProvinceName=Classified/countryName=SA/localityName=Classified/organizationalUnitName=SSA/emailAddress=atlas@ssa.htb
| Issuer: commonName=SSA/organizationName=Secret Spy Agency/stateOrProvinceName=Classified/countryName=SA/localityName=Classified/organizationalUnitName=SSA/emailAddress=atlas@ssa.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-05-04T18:03:25
| Not valid after:  2050-09-19T18:03:25
| MD5:   b8b7:487e:f3e2:14a4:999e:f842:0141:59a1
| SHA-1: 80d9:2367:8d7b:43b2:526d:5d61:00bd:66e9:48dd:c223
```

## Foothold

