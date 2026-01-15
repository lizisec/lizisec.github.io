---
title: Acute
---

# 端口扫描
### 全端口扫描

~~~
┌──(kali㉿kali)-[~/acute]
└─$ sudo nmap -sT -p- --min-rate 1000  10.10.11.145 -oA nmap/ports                   
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-13 09:47 EST
Nmap scan report for 10.10.11.145
Host is up (0.079s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT    STATE SERVICE
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 119.98 seconds

~~~

### 默认脚本扫描

~~~
┌──(kali㉿kali)-[~/acute]
└─$ sudo nmap -sT -sC -sV -p 443 10.10.11.145  -oA nmap/sC                                       
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-13 09:49 EST
Nmap scan report for 10.10.11.145
Host is up (0.080s latency).

PORT    STATE SERVICE  VERSION
443/tcp open  ssl/http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_ssl-date: 2024-12-13T14:35:34+00:00; -14m19s from scanner time.
| ssl-cert: Subject: commonName=atsserver.acute.local
| Subject Alternative Name: DNS:atsserver.acute.local, DNS:atsserver
| Not valid before: 2022-01-06T06:34:58
|_Not valid after:  2030-01-04T06:34:58
|_http-server-header: Microsoft-HTTPAPI/2.0
| tls-alpn: 
|_  http/1.1
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -14m19s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.63 seconds

~~~

### 漏洞脚本扫描

~~~
┌──(kali㉿kali)-[~/acute]
└─$ sudo nmap -sT --script=vuln -p 443 80 10.10.11.145 -oA nmap/vuln                
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-13 09:49 EST
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Stats: 0:03:22 elapsed; 1 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.12% done; ETC: 09:53 (0:00:01 remaining)
Stats: 0:03:22 elapsed; 1 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.12% done; ETC: 09:53 (0:00:01 remaining)
Nmap scan report for 10.10.11.145
Host is up (0.079s latency).

PORT    STATE SERVICE
443/tcp open  https
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.

Nmap done: 2 IP addresses (1 host up) scanned in 1332.37 seconds

~~~

### UDP扫描

~~~
──(kali㉿kali)-[~/acute]
└─$ sudo nmap -sU --top-ports 20 10.10.11.145 -oA nmap/UDP      
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-13 09:53 EST
Nmap scan report for 10.10.11.145
Host is up (0.41s latency).

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

Nmap done: 1 IP address (1 host up) scanned in 10.02 seconds

~~~

访问是404，默认脚本有域名的信息，先改一下hosts

~~~
┌──(kali㉿kali)-[~/acute]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
10.10.11.145    atsserver.acute.local
10.10.11.145    acute.local

~~~

查找一下有没有其他子域名，没有什么发现

~~~
┌──(kali㉿kali)-[~/acute]                                                          └─$ gobuster vhost  -u https://10.10.11.145 --domain acute.local -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt   --append-domain -k -r -t 100                                                                                                                                                            
===============================================================                    Gobuster v3.6                                                                      by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)                                                                                                         ===============================================================                    [+] Url:             https://10.10.11.145                                          [+] Method:          GET                                                           [+] Threads:         100                                                           [+] Wordlist:        /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt  [+] User Agent:      gobuster/3.6                                                  [+] Timeout:         10s                                                           [+] Append Domain:   true                                                          ===============================================================                                                                                                       Starting gobuster in VHOST enumeration mode                                                                                                                           ===============================================================                    Found: -.acute.local Status: 400 [Size: 334]                                       Found: %20.acute.local Status: 400 [Size: 334]                                     Found: *checkout*.acute.local Status: 400 [Size: 334]                              Found: -1.acute.local Status: 400 [Size: 334]                                      Found: *docroot*.acute.local Status: 400 [Size: 334]                               Found: *.acute.local Status: 400 [Size: 334]                                       Found: -buy.acute.local Status: 400 [Size: 334]                                    Found: 4%20Color%2099%20IT2.acute.local Status: 400 [Size: 334]                    Found: %7Emike.acute.local Status: 400 [Size: 334]                                 Found: http%3A%2F%2Fwww.acute.local Status: 400 [Size: 334]                        Found: http%3A.acute.local Status: 400 [Size: 334]                                 Found: MSNBC%20Interactive.acute.local Status: 400 [Size: 334]                     Found: Picture%201.acute.local Status: 400 [Size: 334]                                     
~~~

在about.html中发现右上角可以下载一个文件（这也太小了）

![](Pasted%20image%2020241214004447.png)

在文件中我们发现了一个https://atsserver.acute.local/Acute_Staff_Access和admin的名字Lois以及默认密码Password1!

访问发现应该是员工的远程webshell管理后台

![](Pasted%20image%2020241214115925.png)

访问about.html同时也能发现一些员工的名字

![](Pasted%20image%2020241214140512.png)

~~~
Aileen Wallace
Charlotte Hall
Evan Davies
Ieuan Monks
Joshua Morgan
Lois Hopkins
~~~

用名字做一下字典

~~~
┌──(kali㉿kali)-[~/acute]
└─$ cat users.txt 
Aileen
Charlotte
Evan
Ieuan
Joshua
Lois
Aileen Wallace
Charlotte Hall
Evan Davies
Ieuan Monks
Joshua Morgan
Lois Hopkins
aileen
charlotte
evan
ieuan
joshua
lois
Wallace
Hall
Davies
Monks
Morgan
Hopkins
wallace
hall
davies
monks
morgan
hopkins
~~~

用bp爆破一下，结果一个都没有成功

![](Pasted%20image%2020241214151123.png)

信息搜集还是不到位，再看一眼其他的信息，下载的docx有可能有敏感信息吗

~~~
┌──(kali㉿kali)-[~/acute]
└─$ exiftool ~/Downloads/New_Starter_CheckList_v7.docx 
ExifTool Version Number         : 13.00
File Name                       : New_Starter_CheckList_v7.docx
Directory                       : /home/kali/Downloads
File Size                       : 35 kB
File Modification Date/Time     : 2024:12:13 11:43:43-05:00
File Access Date/Time           : 2024:12:13 11:43:52-05:00
File Inode Change Date/Time     : 2024:12:13 11:43:44-05:00
File Permissions                : -rw-rw-r--
File Type                       : DOCX
File Type Extension             : docx
MIME Type                       : application/vnd.openxmlformats-officedocument.wordprocessingml.document
Zip Required Version            : 20
Zip Bit Flag                    : 0x0006
Zip Compression                 : Deflated
Zip Modify Date                 : 1980:01:01 00:00:00
Zip CRC                         : 0x079b7eb2
Zip Compressed Size             : 428
Zip Uncompressed Size           : 2527
Zip File Name                   : [Content_Types].xml
Creator                         : FCastle
Description                     : Created on Acute-PC01
Last Modified By                : Daniel
Revision Number                 : 8
Last Printed                    : 2021:01:04 15:54:00Z
Create Date                     : 2021:12:08 14:21:00Z
Modify Date                     : 2021:12:22 00:39:00Z
Template                        : Normal.dotm
Total Edit Time                 : 2.6 hours
Pages                           : 3
Words                           : 886
Characters                      : 5055
Application                     : Microsoft Office Word
Doc Security                    : None
Lines                           : 42
Paragraphs                      : 11
Scale Crop                      : No
Heading Pairs                   : Title, 1
Titles Of Parts                 : 
Company                         : University of Marvel
Links Up To Date                : No
Characters With Spaces          : 5930
Shared Doc                      : No
Hyperlinks Changed              : No
App Version                     : 16.0000

~~~

可以看到创建者是FCastle，应该遵守了某种命名规则
主机名为Acute-PC01

重新做一个用户字典

~~~
┌──(kali㉿kali)-[~/acute]
└─$ cat users.txt 
AWallace
CHall
EDavies
IMonks
JMorgan
LHopkins

~~~

edavies 似乎是特殊的

![](Pasted%20image%2020241214151807.png)

成功登入

![](Pasted%20image%2020241214151912.png)

先传个nc上去弹个shell

~~~
┌──(kali㉿kali)-[~/acute]
└─$ sudo rlwrap -cAr nc -lvnp 443 
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.10.16.13] from (UNKNOWN) [10.10.11.145] 49828
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Users\edavies\Documents> clear
clear
PS C:\Users\edavies\Documents> whoami
whoami
acute\edavies
PS C:\Users\edavies\Documents> ls
ls


    Directory: C:\Users\edavies\Documents


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----        14/12/2024     07:23          45272 nc64.exe       
~~~

利用winpeas进行枚举，发现C:\windows\tasks可写，尝试添加恶意脚本进去但是失败了

![](Pasted%20image%2020241214202546.png)

枚举的时候发现存在rdp会话

~~~
PS C:\utils> qwinsta
qwinsta
 SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE 
 console           edavies                   1  Active    
~~~

利用meterpreter获取屏幕实时监控

![](Pasted%20image%2020241215150134.png)

用户为`imonks`
密码为`w3_4R3_th3_f0rce.`