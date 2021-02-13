---
title: "Recovery : TryHackMe"
last_modified_at: 2021-02-13
categories:
  - TryHackMe
author_profile: false
tags:
  - reversing
  - recovery
  - linux
  - TryHackMe
---

Here is a hint if you want to try it on your own. Reverse engineer the fixutil binary. It modifies a library file. Reverse engineer that library file as well.

## Introduction

![](https://cdn-images-1.medium.com/max/2126/1*hhG05IHR2bDRHoKjzSh7Rw.png)

What it says is, Alex works at Recoverysoft. He and his colleague got an email with a binary file. The email said that the binary fixes the vulnerability that has been recently discovered and affects the webserver.

Here, Alex did a mistake by running the binary. The binary named ***fixutil*** was a targeted malware built to destroy the webserver. Alex wants us to fix the binary.

Alex has provided us the ssh credentials.

In order to get the flags, we need to repair the damage.

## Getting Past the “You DIDN’T SAY THE MAGIC WORD!”

As alex mentioned we get

![](https://cdn-images-1.medium.com/max/2000/1*OeCC9S81FTRXLSYmQYeRdA.png)

And the connection closes after a certain time

![](https://cdn-images-1.medium.com/max/2000/1*--DzF0DR4WgD5nrPXPXkOA.png)

This clearly mentions there is an infinite while loop that echoes “YOU DIDN’T SAY THE MAGIC WORD!”

As you hit CTRL+c we can see a glimpse of

alex@recoveryserver$

Now if we try to start **/bin/sh** the output stops after a while and we get a sh shell.

## Flag 0

![](https://cdn-images-1.medium.com/max/2000/1*4Gqmsj_AB1DPq41v5JxS4g.png)

The last line of .bashrc has the following code

![](https://cdn-images-1.medium.com/max/2000/1*vJs7Iqv8h4ZM1z0A6mLPBQ.png)

Which means that when we log in as alex, the while loop from .bashrc file is executed as the login shell for the user alex is /bin/bash

alex:x:1000:1000::/home/alex:/bin/bash

Delete the while loop from the .bashrc and check port 1337 for the first flag.

## Flag 1

After removing the while loop, change the shell to /bin/bash.

alex@recoveryserver:~$

After a certain time exit command automatically runs

alex@recoveryserver:~$ exit

And exits the bash shell. So there must be a cron job running that does this. After enumerating, I found a file evil on /etc/cron.d

![](https://cdn-images-1.medium.com/max/2000/1*Fz7ByWKQ_9aP6yTe3ELi0A.png)

A bash script on /opt/brilliant_script.sh is running and the output is sent to /tmp/testlog.

The brilliant_script.sh has code to close all the bash shell running

![](https://cdn-images-1.medium.com/max/2000/1*oVgNaznBLedR8bEEseciNw.png)

On removing the code, we get the flag.

## Flag 2

Now we have a stable bash shell.

The cron job runs the bash script as root and the file brilliant_script.sh is writeable by any user, so we can escalate our privileges.

![](https://cdn-images-1.medium.com/max/2000/1*RXvdPbRBJ7xjWmlZp2lBuA.png)

Changed the code in the brilliant_script.sh to provide user alex all the permissions by adding entry in /etc/sudoers file

![](https://cdn-images-1.medium.com/max/2000/1*BgonK42W3JichDRbq3dRWQ.png)

![](https://cdn-images-1.medium.com/max/2000/1*HGfZVlLnAM17Cc4bMjWU_g.png)

Flag 2

## Reversing the fixutil binary

First copied the binary to my computer using SC

![](https://cdn-images-1.medium.com/max/2000/1*Hl0Zd4ynXzt158yMEJdskg.png)

Used ghidra to reverse engineer the binary.

Main function

![](https://cdn-images-1.medium.com/max/2000/1*kh-m7S5Fjx960V75Q-K9Ng.png)

Here it opens the .bashrc file and writes the while loop. And writes code to the library file liblogging.so

![](https://cdn-images-1.medium.com/max/2000/1*KhIo8aUS4h-cNJfduIiCIw.png)

Reverse engineering the liblogging.so file

We can see functions implemented in the file

![](https://cdn-images-1.medium.com/max/2000/1*LSX2l6jVuI7P-p3XorZ8Eg.png)

![](https://cdn-images-1.medium.com/max/2000/1*Uy7AFv-g8vnenKkQTwNuRA.png)

It copies /tmp/logging.so to /lib/x86_64-linux-gnu/oldliblogging.so . Since the fixutil binary copied the original libloggin.so to /tmp/logging.so . So, the original liblogging is the oldliblogging.so.

Moving the oldliblogging.so to liblogging.so in directory /lib/x86_64-linux-gnu/

![](https://cdn-images-1.medium.com/max/2000/1*yZF31-Nhm51Qw9T-6AbM8Q.png)

Get the flag.

## Flag 3

![Part of incorrect LogIncorrectAttempt function in liblogging.so](https://cdn-images-1.medium.com/max/2000/1*-60Zx97uFVoyaZAdmzE26A.png)*Part of incorrect LogIncorrectAttempt function in liblogging.so*

Since it added keys to /root/.ssh/authorized_keys. We need to remove this.

![](https://cdn-images-1.medium.com/max/2000/1*Jvqu1NVvz1uiWBgiaICaMA.png)

Get the flag.

## Flag 4

![Part of incorrect LogIncorrectAttempt function in liblogging.so](https://cdn-images-1.medium.com/max/2000/1*P8kImrjE2pQpqAktiK6NDA.png)*Part of incorrect LogIncorrectAttempt function in liblogging.so*

As a backup it created user with username security and added password. We can remove this by removing entry in /etc/passwd and /etc/shadow file.

Get the flag.

## Flag 5

XOREncryptWebFiles function decompiled using ghidra

![](https://cdn-images-1.medium.com/max/2000/1*bPgjMe4qk_jGHDxV3OebbA.png)

Here it first creates a random string using rand_string function and stores the string is /opt/.fixutil/backup.txt file. Then finds the webfiles using GetWebFiles function and XOR’s the content using XORFile function.

GetWebFiles function

![](https://cdn-images-1.medium.com/max/2000/1*CE4_TaQSnb_Elq5hDjXqxg.png)

Opens the directory web_location and returns the files in that directory.

![](https://cdn-images-1.medium.com/max/2000/1*bmsxJJKy25VHD9Yr_pvp8g.png)

Web location is the /usr/local/apache2/htdocs directory.

After getting the files in that directory, it calls the function XORFile with parameters the filename returned by the GetWebFiles function and the random generated string stored in /opt/.fixutil/backup.txt

Contents of XORFile function

![](https://cdn-images-1.medium.com/max/2000/1*Lvm0X5SL_x9OTvVLjh1ZeA.png)

Reads the file in binary format, and XORs the file with the encryption key. Downloaded the files in the /usr/local/apache2/htdocs folder using scp

![](https://cdn-images-1.medium.com/max/2000/1*wm9Zf_nvrhdj9dA_4WPC-w.png)

![](https://cdn-images-1.medium.com/max/2000/1*UReOjdVilq7tXh9cSkYZ2w.png)

The content of backup.txt

![](https://cdn-images-1.medium.com/max/2000/1*iaCi3Vfx3jpnFzgbtbh99g.png)

Wrote a python code to decode the files in the directory

    key=b"AdsipPewFlfkmll"
    fil="index.html"
    f=open(fil,"rb")
    contents=f.read()
    for i in range(0,len(contents)):
          print(chr(contents[i]^key[i%len(key)]),end='')

Wrote the decoded file

    roshan@kali:/tmp/ro$ python3 ro.py > ./upload/index.html

Changed the fil in the code and decoded the two other files and uploaded to the /home/alex directory. Since the files in /usr/local/apache2/htdocs/* are owned by root.

![](https://cdn-images-1.medium.com/max/2000/1*C412-2lURgtJJ4OzCFzLNg.png)

Moved the files to htdocs directory

![](https://cdn-images-1.medium.com/max/2000/1*SLuMg6wUBYdwgt1sp48UQA.png)

And get the flag.

If you have any suggestions or you did it different than my approach, feel free to comment.
