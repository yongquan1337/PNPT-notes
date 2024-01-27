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

# identify web tech

- builtwith.com
- wappalyzer (firefox extention)
- whatweb
- 


