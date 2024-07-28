# The Five Stages of Ethical Hacking

- [Reconnaissance](#-reconnaissance)
- [Scanning and Enumeration]
- [Gaining Access]
- [Maintaining Access]
- [Covering Tracks]


# Reconnaissance

## Passive Recon

| Location Information | Job information |
| ------------- | ------------- |
| Satellite images  | Employees (name, job title, phone number, manager,etc.)  |
| Drone recon  | Pictures (badge photos, desks photos, computer photos, etc.)  |
| Building layout (badge readers, break areas, security, fencing

## Active Recon
| Steps | Tools | Explanation|
| --- | --- | --- |
| Target validation | WHOIS, nslookup, dnsrecon | Ensure correct site/ip is given to attack |
| Finding Subdomains | Google Fu, dig, Nmap, Sub list3r, Bluto, crt.sh, etc. | subdomains increases attack surface area |
| Fingerprinting | Nmap, Wapplyzer, WhatWeb, BuiltWith, Netcat | Find what version and applications are running. eg. (FTP, Apache, etc.)
| Data breaches | HaveIBeenPwned, Breach-Parse, WeLeakInfo | find leaked usernames and credentials |

## Discovering Email Addresses
https://hunter.io/  
 
![image](https://github.com/yongquan1337/PNPT-notes/assets/65943569/906bf5f4-cd47-42ea-b03d-e4a20583166d)

https://phonebook.cz/

![image](https://github.com/yongquan1337/PNPT-notes/assets/65943569/8d3dd12f-33dc-413e-aae3-0c5079c37fb0)

others:  https://www.voilanorbert.com/      https://clearbit.com/resources/tools/connect

## Email verification
https://tools.emailhippo.com/

![image](https://github.com/yongquan1337/PNPT-notes/assets/65943569/145da6e4-1268-46a0-b025-138f5e8f1ba4)

https://email-checker.net/

![image](https://github.com/yongquan1337/PNPT-notes/assets/65943569/b45243c6-95c6-4ef7-b6ea-fbef6eefb2ed)

### Bonus
Gmail checks if user exists. use password recovery to find if the account is tied to another email

![image](https://github.com/yongquan1337/PNPT-notes/assets/65943569/5ab85440-682d-4663-970b-0eb8dbb72b72)


### Typical steps to find someone
1. Google: who is in this role in this company
2. go to hunter.io/phonebook.cz and identify the formatting of email and try to guesstimate their email
3. Verify Email using emailhippo/emailchecker


https://breachdirectory.org/
https://search.0t.rocks/
# Gathering Breached Credentials with Breach-Parse

# hunting subdomains

- sublist3r
- crt.sh
  ![image](https://github.com/yongquan1337/PNPT-notes/assets/65943569/c36dbedb-d3f5-4864-bb67-80c6bd2e3be1)
- amass
- burpsuite

# identify web tech

- builtwith.com
- wappalyzer (firefox extention)
- whatweb

# Google fu (googling using syntax)

https://ahrefs.com/blog/google-advanced-search-operators/

# kioptrix

user
john
TwoCows2

arp-scan -l
nmap -T4 -p- -A 192.168.79.24

nikto -h 192.168.79.24
gobuster dir -w /wordlist.txt -u http://192.168.79.24

###on kali add to /etc/samba/smbd.conf
[global]
client min protocol = CORE﻿
client max protocol = SMB3﻿﻿

\#systemctl restart smbd.service

## test smb

smbclient -L \\\\192.168.79.24\\
smbclient \\\\192.168.79.24\\ADMIN$
smbclient \\\\192.168.79.24\\IPC$


## ssh
ssh 192.168.79.24

if too old version then
ssh 192.168.79.24 -oKexAlgorithms=+diffie-hellman-group1-sha1 -c aes128-cbc

# reverse shell
![image](https://github.com/yongquan1337/PNPT-notes/assets/65943569/ffdaf0be-f722-46f8-97a6-dac9f5f1bfde)

![image](https://github.com/yongquan1337/PNPT-notes/assets/65943569/557b15fe-e68b-451e-af8d-d207547adb79)
reverse is preferred

# staged vs non staged payloads
![image](https://github.com/yongquan1337/PNPT-notes/assets/65943569/0c3bed1d-2187-4824-ad66-a9ca0fd8cb88)
staged and non staged marked by the "/" in the payload path
if staged doesnt work, try a non staged


## Blue VM
![image](https://github.com/yongquan1337/PNPT-notes/assets/65943569/03bf6bfa-0d5b-4581-a949-7d63228eb961)
![image](https://github.com/yongquan1337/PNPT-notes/assets/65943569/f94ae98a-4b61-4d51-ac6c-7aa84023c387)
![image](https://github.com/yongquan1337/PNPT-notes/assets/65943569/5cd346f7-4deb-4c4a-ace6-3164467fdf34)
![image](https://github.com/yongquan1337/PNPT-notes/assets/65943569/ce4a34c9-f827-4553-8d1e-430401e171dc)


## Academy
![image](https://github.com/user-attachments/assets/38a42a28-b060-4588-b1df-d227dabde110)
![image](https://github.com/user-attachments/assets/c474fa1b-debc-49da-a077-599591f5af4c)

![image](https://github.com/user-attachments/assets/0f24c288-9d97-4e73-9707-0b0e63b02546)
![image](https://github.com/user-attachments/assets/3ab4c257-6516-4607-809c-94c3c3f6171b)
![image](https://github.com/user-attachments/assets/d7f46e3f-2b26-4fd3-92b4-32da0731ea11)
![image](https://github.com/user-attachments/assets/43dea204-6ebf-46ec-b3f8-95fb25ff35bc)
![image](https://github.com/user-attachments/assets/c80302c8-431b-4367-aec4-547530187642)
![image](https://github.com/user-attachments/assets/8c4a2762-3ed2-40ed-9b0d-ec72a2728058)
![image](https://github.com/user-attachments/assets/ea878a07-c091-4783-8405-0794b6ed125a)
download pentestmonkey reversephpshell
![image](https://github.com/user-attachments/assets/cee21607-c3ce-46ef-903d-80f45bff44f1)

![image](https://github.com/user-attachments/assets/f2a8f0d7-45bd-4a7d-a27b-0f152cadd19b)

![image](https://github.com/user-attachments/assets/8ae8d330-1c8a-4892-adb5-545f2f73a79d)

![image](https://github.com/user-attachments/assets/dc05e11c-1b82-4e11-8290-600b32f62a80)

![image](https://github.com/user-attachments/assets/7eaf80da-73d3-4129-98a2-b941874c67c1)

![image](https://github.com/user-attachments/assets/7521dd15-4558-4920-ae9d-f7bcf8945bec)

![image](https://github.com/user-attachments/assets/a249172c-f81b-4a60-b34f-181761e992e5)

![image](https://github.com/user-attachments/assets/d2f0cee1-0055-4734-ba89-b245a853a2e9)

![image](https://github.com/user-attachments/assets/c319760f-5f44-410d-a5bc-e00bd5e948c2)

![image](https://github.com/user-attachments/assets/a1593235-12d7-414a-9e2b-3182c0772b6d)

![image](https://github.com/user-attachments/assets/1808941f-5b6a-4988-ab68-888fc4251428)

![image](https://github.com/user-attachments/assets/c826b541-983b-4343-adf5-77ce549f4da3)

![image](https://github.com/user-attachments/assets/47331558-47ab-4308-858f-d720ce75ed82)

![image](https://github.com/user-attachments/assets/24c7b221-8dde-4020-9989-afb8bf75242d)









