---
title: FTP(21)渗透利用思路
date: 2026-01-17
slug: ftp-21-pentest-guide
tags: [FTP, Pentest, 渗透测试]
---

# FTP
常规登录，默认端口21
~~~
sudo ftp 192.168.2.140
~~~
<!-- truncate -->
指定端口登录
~~~
sudo ftp 192.168.2.140 2121
~~~
### 匿名登录
可以尝试用anonymous+空密码匿名登录
进去后先切换binary mode防止下载文件发生乱码

### 历史漏洞

 **ProFTPD 1.3.5** 的 `mod_copy` 漏洞：允许远程代码执行（RCE）
 
 **vsftpd 2.3.4** 笑脸后门：如果在用户名后面输入 `:)`，服务器会直接在 6200 端口开启一个 Shell。

### 配置错误

../../../etc/passwd 可能存在目录穿越
