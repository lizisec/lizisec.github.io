---
title: BillyMadison
---

- 下载地址-https://www.vulnhub.com/entry/billy-madison-11,161/
## 主机发现
~~~
┌──(kali㉿kali)-[~/billy]
└─$sudo nmap -sn 192.168.2.0/24
[sudo] password for kali: 
~~~

~~~
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-26 06:21 EDT
Nmap scan report for 192.168.2.1
Host is up (0.00014s latency).
MAC Address: 00:50:56:C0:00:08 (VMware)
Nmap scan report for 192.168.2.2
Host is up (0.000079s latency).
MAC Address: 00:50:56:EC:E6:0B (VMware)
Nmap scan report for 192.168.2.186
Host is up (0.00011s latency).
MAC Address: 00:0C:29:E9:87:D5 (VMware)
Nmap scan report for 192.168.2.254
Host is up (0.00012s latency).
MAC Address: 00:50:56:F9:F9:CF (VMware)
Nmap scan report for 192.168.2.163
Host is up.
Nmap done: 256 IP addresses (5 hosts up) scanned in 1.97 seconds
~~~
靶机ip:192.168.2.186
## 端口扫描
### 全端口扫描
~~~
┌──(kali㉿kali)-[~/billy]
└─$ sudo nmap -sT -sV -p- --min-rate 10000 192.168.2.186 -oA nmap/ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-26 06:24 EDT
Nmap scan report for 192.168.2.186
Host is up (0.00031s latency).
Not shown: 65526 filtered tcp ports (no-response)
PORT     STATE  SERVICE     VERSION
22/tcp   open   tcpwrapped
23/tcp   open   tcpwrapped
69/tcp   open   caldav      Radicale calendar and contacts server (Python BaseHTTPServer)
80/tcp   open   http        Apache httpd 2.4.18 ((Ubuntu))
137/tcp  closed netbios-ns
138/tcp  closed netbios-dgm
139/tcp  open   netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open   netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
2525/tcp open   smtp        SubEtha smtpd
MAC Address: 00:0C:29:E9:87:D5 (VMware)
Service Info: Host: BM

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.11 seconds

~~~
### sC默认脚本扫描
~~~
┌──(kali㉿kali)-[~/billy]
└─$ sudo nmap -sT -sV -sC -p22,23,69,80,137,138,139,445,2525 192.168.2.186 -oA nmap/sC
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-26 06:26 EDT
Nmap scan report for 192.168.2.186
Host is up (0.00029s latency).

PORT     STATE  SERVICE     VERSION
22/tcp   open   tcpwrapped
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
23/tcp   closed telnet
69/tcp   open   caldav      Radicale calendar and contacts server (Python BaseHTTPServer)
|_http-generator: WordPress 1.0
|_http-title: Welcome | Just another WordPress site
|_http-server-header: MadisonHotelsWordpress
80/tcp   open   http        Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Oh nooooooo!
137/tcp  closed netbios-ns
138/tcp  closed netbios-dgm
139/tcp  open   netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open   netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
2525/tcp open   smtp        SubEtha smtpd
| smtp-commands: BM, 8BITMIME, AUTH LOGIN, Ok
|_ SubEthaSMTP null on BM Topics: HELP HELO RCPT MAIL DATA AUTH EHLO NOOP RSET VRFY QUIT STARTTLS For more info use "HELP <topic>". End of HELP info
MAC Address: 00:0C:29:E9:87:D5 (VMware)
Service Info: Host: BM

Host script results:
|_clock-skew: mean: 1h40m01s, deviation: 2h53m15s, median: 0s
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: bm
|   NetBIOS computer name: BM\x00
|   Domain name: \x00
|   FQDN: bm
|_  System time: 2024-10-26T05:26:50-05:00
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2024-10-26T10:26:46
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 64.26 seconds

~~~

### vuln脚本扫描
~~~
┌──(kali㉿kali)-[~/billy]
└─$ sudo nmap -sT -p22,23,69,80,137,138,139,445,2525 --script=vuln 192.168.2.186 -oA nmap/vuln
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-26 06:26 EDT
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 192.168.2.186
Host is up (0.00033s latency).

PORT     STATE  SERVICE
22/tcp   open   ssh
23/tcp   closed telnet
69/tcp   open   tftp
80/tcp   open   http
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|_  /manual/: Potentially interesting folder
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_      http://ha.ckers.org/slowloris/
137/tcp  closed netbios-ns
138/tcp  closed netbios-dgm
139/tcp  open   netbios-ssn
445/tcp  open   microsoft-ds
2525/tcp open   ms-v-worlds
MAC Address: 00:0C:29:E9:87:D5 (VMware)

Host script results:
|_smb-vuln-ms10-054: false
| smb-vuln-regsvc-dos: 
|   VULNERABLE:
|   Service regsvc in Microsoft Windows systems vulnerable to denial of service
|     State: VULNERABLE
|       The service regsvc in Microsoft Windows 2000 systems is vulnerable to denial of service caused by a null deference
|       pointer. This script will crash the service if it is vulnerable. This vulnerability was discovered by Ron Bowes
|       while working on smb-enum-sessions.
|_          
|_smb-vuln-ms10-061: false

Nmap done: 1 IP address (1 host up) scanned in 345.65 seconds

~~~
## 137/445(smb服务)
### enum4linux进行枚举
~~~
[+] Enumerating users using SID S-1-5-21-4111762292-2429122530-3796655328 and logon username '', password ''

S-1-5-21-4111762292-2429122530-3796655328-501 BM\veronica (Local User)
S-1-5-21-4111762292-2429122530-3796655328-513 BM\None (Domain Group)

[+] Enumerating users using SID S-1-22-1 and logon username '', password ''

S-1-22-1-1000 Unix User\billy (Local User)
S-1-22-1-1001 Unix User\veronica (Local User)
S-1-22-1-1002 Unix User\eric (Local User)
~~~
枚举出一些用户
~~~
billy
veronica
eric
~~~
### smbclient登录
~~~
┌──(kali㉿kali)-[~/billy]
└─$ smbclient -L 192.168.2.186
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        EricsSecretStuff Disk      
        IPC$            IPC       IPC Service (BM)
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            BM
                                                                                
~~~
列出EricsSecretStuff目录下的内容
~~~
┌──(kali㉿kali)-[~/billy]
└─$ smbclient  //192.168.2.186/EricsSecretStuff 
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Oct 19 07:54:55 2024
  ..                                  D        0  Sat Aug 20 14:56:45 2016
  ._.DS_Store                        AH     4096  Wed Aug 17 10:32:07 2016
  ebd.txt                             N       35  Sat Oct 19 07:54:55 2024
  .DS_Store                          AH     6148  Wed Aug 17 10:32:12 2016

                30291996 blocks of size 1024. 24209984 blocks available
smb: \> 
~~~
下载下来查看
~~~
┌──(kali㉿kali)-[~/billy]
└─$ cat ebd.txt 
Erics backdoor is currently CLOSED
~~~
没什么有用的信息

## 69端口(web)
看起来是一个wordpress网站，version为1.0，但是wpscan无法扫到任何结果，服务状态也不稳定，可能是兔子洞，暂时搁置
## 23
~~~
┌──(kali㉿kali)-[~/billy]
└─$ telnet 192.168.2.186 23
Trying 192.168.2.186...
Connected to 192.168.2.186.
Escape character is '^]'.
***** HAHAH! You're banned for a while, Billy Boy!  By the way, I caught you trying to hack my wifi - but the joke's on you! I don't use ROTten passwords like rkfpuzrahngvat anymore! Madison Hotels is as good as MINE!!!! *****
Connection closed by foreign host.
~~~
给了一个凯撒密码rkfpuzrahngvat
解密出exschmenuating
## 80端口(web)
![](./image/Pasted image 20241026182956.png)
看起来billy的服务器被入侵了
查看源码也没有发现有用的信息
没什么信息就进行目录爆破吧！
### 目录爆破

~~~
┌──(kali㉿kali)-[~/billy] 06:49:12 [38/467]

└─$ sudo gobuster dir -u 'http://192.168.2.186' -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[sudo] password for kali:
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url: http://192.168.2.186
[+] Method: GET
[+] Threads: 10
[+] Wordlist: /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes: 404
[+] User Agent: gobuster/3.6
[+] Timeout: 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/manual (Status: 301) [Size: 315] [--> http://192.168.2.186/manual/]
/server-status (Status: 403) [Size: 278]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================
~~~
只扫出来一个manual
访问发现是默认页
试试23端口解密出的exschmenuating
![](./image/Pasted image 20241026190355.png) I put "veronica" somewhere in the file name because I bet you a million dollars she uses her name as part of her passwords
看起来需要构造字典
可以先试试利用已有的字典
~~~
┌──(kali㉿kali)-[~/billy]
└─$ cat /usr/share/wordlists/rockyou.txt| grep 'veronica' > veronica.txt
~~~
发现扫描出一个cap文件
~~~
┌──(kali㉿kali)-[~/billy]
└─$ sudo gobuster dir -u 'http://192.168.2.186/exschmenuating/' -w veronica.txt -x .html,.txt,.php,.jsp,.zip,.cap,.7z
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.2.186/exschmenuating/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                veronica.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              7z,html,txt,php,jsp,zip,cap
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/012987veronica.cap   (Status: 200) [Size: 8700]
Progress: 6184 / 6192 (99.87%)
===============================================================
Finished
===============================================================
~~~
strings提取cap中的信息，发现了五封邮件
~~~mail1
EHLO kali
MAIL FROM:<vvaughn@polyfector.edu>
RCPT TO:<eric@madisonhotels.com>
DATA
Date: Sat, 20 Aug 2016 21:57:00 -0500
To: eric@madisonhotels.com
From: vvaughn@polyfector.edu
Subject: test Sat, 20 Aug 2016 21:57:00 -0500
X-Mailer: swaks v20130209.0 jetmore.org/john/code/swaks/
RE: VIRUS ALERT!
Eric,
Thanks for your message. I tried to download that file but my antivirus blocked it.
Could you just upload it directly to us via FTP?  We keep FTP turned off unless someone connects with the "Spanish Armada" combo.
https://www.youtube.com/watch?v=z5YU7JwVy7s
-VV
.
QUIT                                                                            
~~~
可疑的视频链接https://www.youtube.com/watch?v=z5YU7JwVy7s
![](./image/Pasted image 20241026214909.png)
得到爆出的数字，可能是knock的端口号
1066,1215,1466,1467,1469,1514,1981,1986
~~~mail2                                                                  
EHLO kali
MAIL FROM:<eric@madisonhotels.com>
RCPT TO:<vvaughn@polyfector.edu>
DATA
Date: Sat, 20 Aug 2016 21:57:11 -0500
To: vvaughn@polyfector.edu
From: eric@madisonhotels.com
Subject: test Sat, 20 Aug 2016 21:57:11 -0500
X-Mailer: swaks v20130209.0 jetmore.org/john/code/swaks/
RE[2]: VIRUS ALERT!
Veronica,
Thanks that will be perfect.  Please set me up an account with username of "eric" and password "ericdoesntdrinkhisownpee."
-Eric
.
QUIT
~~~
这里有可疑的密码eric::ericdoesntdrinkhisownpee
~~~mail3
EHLO kali
MAIL FROM:<vvaughn@polyfector.edu>
RCPT TO:<eric@madisonhotels.com>
DATA
Date: Sat, 20 Aug 2016 21:57:21 -0500
To: eric@madisonhotels.com
From: vvaughn@polyfector.edu
Subject: test Sat, 20 Aug 2016 21:57:21 -0500
X-Mailer: swaks v20130209.0 jetmore.org/john/code/swaks/
RE[3]: VIRUS ALERT!
Eric,
Done.
-V
.
QUIT

~~~

~~~mail4
EHLO kali
MAIL FROM:<eric@madisonhotels.com>
RCPT TO:<vvaughn@polyfector.edu>
DATA
Date: Sat, 20 Aug 2016 21:57:31 -0500
To: vvaughn@polyfector.edu
From: eric@madisonhotels.com
Subject: test Sat, 20 Aug 2016 21:57:31 -0500
X-Mailer: swaks v20130209.0 jetmore.org/john/code/swaks/
RE[4]: VIRUS ALERT!
Veronica,
Great, the file is uploaded to the FTP server, please go to a terminal and run the file with your account - the install will be automatic and you won't get any pop-ups or anything like that.  Thanks!
-Eric
.
QUIT
~~~

~~~mail5
EHLO kali
MAIL FROM:<vvaughn@polyfector.edu>
RCPT TO:<eric@madisonhotels.com>
DATA
Date: Sat, 20 Aug 2016 21:57:41 -0500
To: eric@madisonhotels.com
From: vvaughn@polyfector.edu
Subject: test Sat, 20 Aug 2016 21:57:41 -0500
X-Mailer: swaks v20130209.0 jetmore.org/john/code/swaks/
RE[5]: VIRUS ALERT!
Eric,
I clicked the link and now this computer is acting really weird.  The antivirus program is popping up alerts, my mouse started to move on its own, my background changed color and other weird stuff.  I'm going to send this email to you and then shut the computer down.  I have some important files I'm worried about, and Billy's working on his big 12th grade final.  I don't want anything to happen to that!
-V
.
QUIT
~~~

其他的就没有什么有价值的信息了，先试一下knock
~~~
knock 192.168.2.186 -v 1066 1215 1466 67 1467 1469 1514 1981 1986 
~~~