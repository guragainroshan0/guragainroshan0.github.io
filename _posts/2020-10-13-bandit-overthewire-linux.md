---
title: "Bandit : OverTheWire"
last_modified_at: 2020-10-13T14:40:02-05:00
categories:
  - OverTheWire
author_profile: false
tags:
  - OverTheWire
  - Bandit 
  - Linux
---
# Bandit
This is my solution to the bandit war game on over the wire. Bandit tests your linux skills. Feel free to try it yourself [here](https://overthewire.org/wargames/bandit/).

### Level 0 : SSH

![/assets/images/OverTheWire/Bandit/Untitled.png](/assets/images/OverTheWire/Bandit/Untitled.png)

![/assets/images/OverTheWire/Bandit/Untitled%201.png](/assets/images/OverTheWire/Bandit/Untitled%201.png)

The authenticity of host can't be established : This is because my computer does not have the public key to verify the server. 

![/assets/images/OverTheWire/Bandit/Untitled%202.png](/assets/images/OverTheWire/Bandit/Untitled%202.png)

boJ9jbbUNNfktd78OOpsqOltutMc3MY1

### Level 1 : - (read file whose name starts with - )

![/assets/images/OverTheWire/Bandit/Untitled%203.png](/assets/images/OverTheWire/Bandit/Untitled%203.png)

![/assets/images/OverTheWire/Bandit/Untitled%204.png](/assets/images/OverTheWire/Bandit/Untitled%204.png)

![/assets/images/OverTheWire/Bandit/Untitled%205.png](/assets/images/OverTheWire/Bandit/Untitled%205.png)

CV1DtqXWVFXTvM2F0k09SHz0YwRINYA9

### Level 2 : Spaces in filename ( Escape Character)

![/assets/images/OverTheWire/Bandit/Untitled%206.png](/assets/images/OverTheWire/Bandit/Untitled%206.png)

Escape characters are used to remove the special meaning from a single character. **A non-quoted backslash, \,** is used as an escape character in Bash. It preserves the literal value of the next character that follows, with the exception of newline.

![/assets/images/OverTheWire/Bandit/Untitled%207.png](/assets/images/OverTheWire/Bandit/Untitled%207.png)

UmHadQclWmgdLOKQ3YNgjWxGoRMb5luK

### Level 3 : Hidden file

![/assets/images/OverTheWire/Bandit/Untitled%208.png](/assets/images/OverTheWire/Bandit/Untitled%208.png)

![/assets/images/OverTheWire/Bandit/Untitled%209.png](/assets/images/OverTheWire/Bandit/Untitled%209.png)

Files and folder starting with . represet hidden files and folders. ls -la lists all the files and directories including hidden files and directories.

pIwrPrtPN36QITSp3EQaw936yaFoFgAB

### Level 4 : Human readable file

![/assets/images/OverTheWire/Bandit/Untitled%2010.png](/assets/images/OverTheWire/Bandit/Untitled%2010.png)

![/assets/images/OverTheWire/Bandit/Untitled%2011.png](/assets/images/OverTheWire/Bandit/Untitled%2011.png)

Used a for loop to cat all the files. 

koReBOKuIDDepwhWk7jZC0RTdopnAYKh

### Level 5 : Find file with the given properties

![/assets/images/OverTheWire/Bandit/Untitled%2012.png](/assets/images/OverTheWire/Bandit/Untitled%2012.png)

![/assets/images/OverTheWire/Bandit/Untitled%2013.png](/assets/images/OverTheWire/Bandit/Untitled%2013.png)

Many folders were in the inhere directory. One of them had the password to next level.

Used find command

```bash
find  . -size 1033c | xargs cat
```

- . for current directory
- -size 1033c : find by size where size = 1033 bytes
- xargs : takes the output of first command and sends as argument to second

DXjZPULLxYr17uwoI01bNLQbtFemEgo7

### Level 6 : Find file by given properties

![/assets/images/OverTheWire/Bandit/Untitled%2014.png](/assets/images/OverTheWire/Bandit/Untitled%2014.png)

![/assets/images/OverTheWire/Bandit/Untitled%2015.png](/assets/images/OverTheWire/Bandit/Untitled%2015.png)

```bash
find / -user bandit7 -group bandit6 -size 33c 2>/dev/null | xargs cat
```

- -user : user who own the file
- -group : group which own the file
- -size : size of file (33c); c represents bytes
- / : to use root directory
- 2>/dev/null : since bandit6 was not root access to all files were denied. STDERR was sent to /dev/null to prevent displaying of error

HKBPTKQnIay4Fw76bEy8PVxKEDQRKTzs

### Level 7 : Extract data from a file. ( grep )

![/assets/images/OverTheWire/Bandit/Untitled%2016.png](/assets/images/OverTheWire/Bandit/Untitled%2016.png)

![/assets/images/OverTheWire/Bandit/Untitled%2017.png](/assets/images/OverTheWire/Bandit/Untitled%2017.png)

Cat shows the content of the files. 

Grep finds the given text and displays the line containing the text in console.

cvX2JJa4CFALtqS87jk27qwqGhBM9plV

### Level 8 : Extract unique text from a file (sort,uniq)

![/assets/images/OverTheWire/Bandit/Untitled%2018.png](/assets/images/OverTheWire/Bandit/Untitled%2018.png)

![/assets/images/OverTheWire/Bandit/Untitled%2019.png](/assets/images/OverTheWire/Bandit/Untitled%2019.png)

- sort data.txt : sorts the texts as a result same line will be adjacent to each other
- uniq -u : displays only unique lines

first tried using uniq -u data.txt. This did not work as uniq looks for adjacent lines. So, first the lines are sorted in order to make the same text adjacent to each other and uniq -u to get only the unique line.

UsvVyFSfZZWbi6wgC7dAFyFuR6jQQUhR

### Level 9 : Extract data from a file (strings)

![/assets/images/OverTheWire/Bandit/Untitled%2020.png](/assets/images/OverTheWire/Bandit/Untitled%2020.png)

![/assets/images/OverTheWire/Bandit/Untitled%2021.png](/assets/images/OverTheWire/Bandit/Untitled%2021.png)

Strings command prints the printable character sequences that are at least 4 characters long.

truKLdjsbJ5g7yyJ2X2R0o3a5HQJFuLk

### Level 10 : Decode base64 encoded data (base64)

![/assets/images/OverTheWire/Bandit/Untitled%2022.png](/assets/images/OverTheWire/Bandit/Untitled%2022.png)

![/assets/images/OverTheWire/Bandit/Untitled%2023.png](/assets/images/OverTheWire/Bandit/Untitled%2023.png)

base64 -d : decodes the base64 encoded string

IFukwKGsFW8MOq3IRFqrxE1hxTNEbUPR

### Level 11 : Decode rotated text ( tr )

![/assets/images/OverTheWire/Bandit/Untitled%2024.png](/assets/images/OverTheWire/Bandit/Untitled%2024.png)

![/assets/images/OverTheWire/Bandit/Untitled%2025.png](/assets/images/OverTheWire/Bandit/Untitled%2025.png)

tr : translates text 

'A-Xa-z' : if the text is in here

'N-ZA-Mn-za-m' : translate to this format

5Te8Y4drgCRfCx8ugdwuEX8KFC6k2EUu

### Level 12 : Extract compressed file ( xxd , tar ,gzip , bzip2 , file )

![/assets/images/OverTheWire/Bandit/Untitled%2026.png](/assets/images/OverTheWire/Bandit/Untitled%2026.png)

Since the given file is a hex dump which has been repeatedly compressed so, xxd -r was used to get the reverse hex dump to get the compressed file. file command provided the information about the file. According to the compression type the files were extracted

![/assets/images/OverTheWire/Bandit/Untitled%2027.png](/assets/images/OverTheWire/Bandit/Untitled%2027.png)

![/assets/images/OverTheWire/Bandit/Untitled%2028.png](/assets/images/OverTheWire/Bandit/Untitled%2028.png)

![/assets/images/OverTheWire/Bandit/Untitled%2029.png](/assets/images/OverTheWire/Bandit/Untitled%2029.png)

![/assets/images/OverTheWire/Bandit/Untitled%2030.png](/assets/images/OverTheWire/Bandit/Untitled%2030.png)

After multiple decompression the password was found

8ZjyCRiBWFYkneahHwxCv3wb2a1ORpYL

### Level 13 : Using SSH key

![/assets/images/OverTheWire/Bandit/Untitled%2031.png](/assets/images/OverTheWire/Bandit/Untitled%2031.png)

![/assets/images/OverTheWire/Bandit/Untitled%2032.png](/assets/images/OverTheWire/Bandit/Untitled%2032.png)

Private ssh key was given, which was used to SSH into the same machine with user bandit14.\

![/assets/images/OverTheWire/Bandit/Untitled%2033.png](/assets/images/OverTheWire/Bandit/Untitled%2033.png)

The password was read as read permission was given to user bandit14 [only.](http://only.cd)

![/assets/images/OverTheWire/Bandit/Untitled%2034.png](/assets/images/OverTheWire/Bandit/Untitled%2034.png)

4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e

### Level 14 : Send data to a certain port ( nc )

![/assets/images/OverTheWire/Bandit/Untitled%2035.png](/assets/images/OverTheWire/Bandit/Untitled%2035.png)

![/assets/images/OverTheWire/Bandit/Untitled%2036.png](/assets/images/OverTheWire/Bandit/Untitled%2036.png)

BfMYroe26WYalil77FoDi9qh59eK5xNr

### Level 15 : Send data using OpenSSL ( openssl , s_client)

![/assets/images/OverTheWire/Bandit/Untitled%2037.png](/assets/images/OverTheWire/Bandit/Untitled%2037.png)

![/assets/images/OverTheWire/Bandit/Untitled%2038.png](/assets/images/OverTheWire/Bandit/Untitled%2038.png)

![/assets/images/OverTheWire/Bandit/Untitled%2039.png](/assets/images/OverTheWire/Bandit/Untitled%2039.png)

![/assets/images/OverTheWire/Bandit/Untitled%2040.png](/assets/images/OverTheWire/Bandit/Untitled%2040.png)

cluFn7wTiGryunymYOu4RcffSxQluehd

### Level 16 : Scanning ports ( nmap )

![/assets/images/OverTheWire/Bandit/Untitled%2041.png](/assets/images/OverTheWire/Bandit/Untitled%2041.png)

Used nmap to scan the ports

![/assets/images/OverTheWire/Bandit/Untitled%2042.png](/assets/images/OverTheWire/Bandit/Untitled%2042.png)

This scan was fast but didn't gave information about ssl service.

So added -A flag to get more information

![/assets/images/OverTheWire/Bandit/Untitled%2043.png](/assets/images/OverTheWire/Bandit/Untitled%2043.png)

![/assets/images/OverTheWire/Bandit/Untitled%2044.png](/assets/images/OverTheWire/Bandit/Untitled%2044.png)

Port 31790 was not a echo service.

![/assets/images/OverTheWire/Bandit/Untitled%2045.png](/assets/images/OverTheWire/Bandit/Untitled%2045.png)

![/assets/images/OverTheWire/Bandit/Untitled%2046.png](/assets/images/OverTheWire/Bandit/Untitled%2046.png)

Got ssh private key.

-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvmOkuifmMg6HL2YPIOjon6iWfbp7c3jx34YkYWqUH57SUdyJ
imZzeyGC0gtZPGujUSxiJSWI/oTqexh+cAMTSMlOJf7+BrJObArnxd9Y7YT2bRPQ
Ja6Lzb558YW3FZl87ORiO+rW4LCDCNd2lUvLE/GL2GWyuKN0K5iCd5TbtJzEkQTu
DSt2mcNn4rhAL+JFr56o4T6z8WWAW18BR6yGrMq7Q/kALHYW3OekePQAzL0VUYbW
JGTi65CxbCnzc/w4+mqQyvmzpWtMAzJTzAzQxNbkR2MBGySxDLrjg0LWN6sK7wNX
x0YVztz/zbIkPjfkU1jHS+9EbVNj+D1XFOJuaQIDAQABAoIBABagpxpM1aoLWfvD
KHcj10nqcoBc4oE11aFYQwik7xfW+24pRNuDE6SFthOar69jp5RlLwD1NhPx3iBl
J9nOM8OJ0VToum43UOS8YxF8WwhXriYGnc1sskbwpXOUDc9uX4+UESzH22P29ovd
d8WErY0gPxun8pbJLmxkAtWNhpMvfe0050vk9TL5wqbu9AlbssgTcCXkMQnPw9nC
YNN6DDP2lbcBrvgT9YCNL6C+ZKufD52yOQ9qOkwFTEQpjtF4uNtJom+asvlpmS8A
vLY9r60wYSvmZhNqBUrj7lyCtXMIu1kkd4w7F77k+DjHoAXyxcUp1DGL51sOmama
+TOWWgECgYEA8JtPxP0GRJ+IQkX262jM3dEIkza8ky5moIwUqYdsx0NxHgRRhORT
8c8hAuRBb2G82so8vUHk/fur85OEfc9TncnCY2crpoqsghifKLxrLgtT+qDpfZnx
SatLdt8GfQ85yA7hnWWJ2MxF3NaeSDm75Lsm+tBbAiyc9P2jGRNtMSkCgYEAypHd
HCctNi/FwjulhttFx/rHYKhLidZDFYeiE/v45bN4yFm8x7R/b0iE7KaszX+Exdvt
SghaTdcG0Knyw1bpJVyusavPzpaJMjdJ6tcFhVAbAjm7enCIvGCSx+X3l5SiWg0A
R57hJglezIiVjv3aGwHwvlZvtszK6zV6oXFAu0ECgYAbjo46T4hyP5tJi93V5HDi
Ttiek7xRVxUl+iU7rWkGAXFpMLFteQEsRr7PJ/lemmEY5eTDAFMLy9FL2m9oQWCg
R8VdwSk8r9FGLS+9aKcV5PI/WEKlwgXinB3OhYimtiG2Cg5JCqIZFHxD6MjEGOiu
L8ktHMPvodBwNsSBULpG0QKBgBAplTfC1HOnWiMGOU3KPwYWt0O6CdTkmJOmL8Ni
blh9elyZ9FsGxsgtRBXRsqXuz7wtsQAgLHxbdLq/ZJQ7YfzOKU4ZxEnabvXnvWkU
YOdjHdSOoKvDQNWu6ucyLRAWFuISeXw9a/9p7ftpxm0TSgyvmfLF2MIAEwyzRqaM
77pBAoGAMmjmIJdjp+Ez8duyn3ieo36yrttF5NSsJLAbxFpdlc1gvtGCWW+9Cq0b
dxviW8+TFVEBl1O4f7HVm6EpTscdDxU+bCXWkfjuRb7Dy9GOtt9JPsX8MBTakzh3
vBgsyi/sN3RqRBcGU40fOoZyfAMT8s1m/uYv52O6IgeuZ/ujbjY=
-----END RSA PRIVATE KEY---—

Logging as bandit17 using private key shows 

![/assets/images/OverTheWire/Bandit/Untitled%2047.png](/assets/images/OverTheWire/Bandit/Untitled%2047.png)

chmod 400 a 

Changes the permission such that only owner can read.

### Level 17 : Difference in two files ( diff )

![/assets/images/OverTheWire/Bandit/Untitled%2048.png](/assets/images/OverTheWire/Bandit/Untitled%2048.png)

![/assets/images/OverTheWire/Bandit/Untitled%2049.png](/assets/images/OverTheWire/Bandit/Untitled%2049.png)

diff : compare files line by line. The difference is shown in terminal.

kfBf3eYk5BPBRzwjqutbbfE887SVc5Yd

### Level 18 : Running Commands using SSH

![/assets/images/OverTheWire/Bandit/Untitled%2050.png](/assets/images/OverTheWire/Bandit/Untitled%2050.png)

![/assets/images/OverTheWire/Bandit/Untitled%2051.png](/assets/images/OverTheWire/Bandit/Untitled%2051.png)

IueksS7Ubh8G3DCwVzrTd8rAVOwq3M5x

### Level 19 : Use SUID binary

![/assets/images/OverTheWire/Bandit/Untitled%2052.png](/assets/images/OverTheWire/Bandit/Untitled%2052.png)

![/assets/images/OverTheWire/Bandit/Untitled%2053.png](/assets/images/OverTheWire/Bandit/Untitled%2053.png)

GbKksEFF4yrVs6il55v6gwY5aVje5f0j

Level 20 : Netcat to listen ( nc )

![/assets/images/OverTheWire/Bandit/Untitled%2054.png](/assets/images/OverTheWire/Bandit/Untitled%2054.png)

![/assets/images/OverTheWire/Bandit/Untitled%2055.png](/assets/images/OverTheWire/Bandit/Untitled%2055.png)

using & runs the program in background

![/assets/images/OverTheWire/Bandit/Untitled%2056.png](/assets/images/OverTheWire/Bandit/Untitled%2056.png)

gE269g2h3mw3pwgrj0Ha9Uoqen1c9DGr

### Level 21 : cron ( /etc/cron.d )

![/assets/images/OverTheWire/Bandit/Untitled%2057.png](/assets/images/OverTheWire/Bandit/Untitled%2057.png)

![/assets/images/OverTheWire/Bandit/Untitled%2058.png](/assets/images/OverTheWire/Bandit/Untitled%2058.png)

Yk7owGAcWjwMVRwrTesJEwB7WVOiILLI

### Level 22 : Cron

![/assets/images/OverTheWire/Bandit/Untitled%2059.png](/assets/images/OverTheWire/Bandit/Untitled%2059.png)

![/assets/images/OverTheWire/Bandit/Untitled%2060.png](/assets/images/OverTheWire/Bandit/Untitled%2060.png)

jc1udXuA1tiHqjIsL8yaapX5XIAI6i0n

### Level 23 : Writing bash script

![/assets/images/OverTheWire/Bandit/Untitled%2061.png](/assets/images/OverTheWire/Bandit/Untitled%2061.png)

![/assets/images/OverTheWire/Bandit/Untitled%2062.png](/assets/images/OverTheWire/Bandit/Untitled%2062.png)

Script inside /var/spool/bandit24 would run as bandit24 so

![/assets/images/OverTheWire/Bandit/Untitled%2063.png](/assets/images/OverTheWire/Bandit/Untitled%2063.png)

![/assets/images/OverTheWire/Bandit/Untitled%2064.png](/assets/images/OverTheWire/Bandit/Untitled%2064.png)

UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ

### Level 24 : Bruteforcing

![/assets/images/OverTheWire/Bandit/Untitled%2065.png](/assets/images/OverTheWire/Bandit/Untitled%2065.png)

![/assets/images/OverTheWire/Bandit/Untitled%2066.png](/assets/images/OverTheWire/Bandit/Untitled%2066.png)

uNG9O58gUE7snukf3bvZ0rxhtnjzSGzG

### Level 25 : More command exploits

![/assets/images/OverTheWire/Bandit/Untitled%2067.png](/assets/images/OverTheWire/Bandit/Untitled%2067.png)

![/assets/images/OverTheWire/Bandit/Untitled%2068.png](/assets/images/OverTheWire/Bandit/Untitled%2068.png)

Used the hints to get vi to edit the files 

[https://medium.com/@coturnix97/overthewires-bandit-25-26-shell-355d78fd2f4d](https://medium.com/@coturnix97/overthewires-bandit-25-26-shell-355d78fd2f4d)

used :e /etc/bandit_pass/bandit26

![/assets/images/OverTheWire/Bandit/Untitled%2069.png](/assets/images/OverTheWire/Bandit/Untitled%2069.png)

5czgV9L3Xx8JPOyRbXh6lQbmIOWvPT6Z

### Level 26 : Getting a SHELL using VIM

![/assets/images/OverTheWire/Bandit/Untitled%2070.png](/assets/images/OverTheWire/Bandit/Untitled%2070.png)

Used same as above to get to vi editor.

Changed the shell to bash using :

:set shell=/bin/bash

used :shell to get shell

![/assets/images/OverTheWire/Bandit/Untitled%2071.png](/assets/images/OverTheWire/Bandit/Untitled%2071.png)

3ba3118a22e93127a4ed485be72ef5ea

### Level 27 : Clone git repo using ssh

![/assets/images/OverTheWire/Bandit/Untitled%2072.png](/assets/images/OverTheWire/Bandit/Untitled%2072.png)

```bash
git clone ssh://bandit27-git@localhost/home/bandit27-git/repo
```

Cloned the repo using the above command

![/assets/images/OverTheWire/Bandit/Untitled%2073.png](/assets/images/OverTheWire/Bandit/Untitled%2073.png)

0ef186ac70e04ea33b4c1853d2526fa2

### Level 28 : Extract Data from git repo using commit  information

![/assets/images/OverTheWire/Bandit/Untitled%2074.png](/assets/images/OverTheWire/Bandit/Untitled%2074.png)

Clone the repo

```bash
git clone ssh://bandit28-git@localhost/home/bandit28-git/repo
```

Viewed the logs

![/assets/images/OverTheWire/Bandit/Untitled%2075.png](/assets/images/OverTheWire/Bandit/Untitled%2075.png)

Checked out to second commit

```bash
git checkout c086d11a00c0648d095d04c089786efef5e01264
```

![/assets/images/OverTheWire/Bandit/Untitled%2076.png](/assets/images/OverTheWire/Bandit/Untitled%2076.png)

bbc96594b4e001778eee9975372716b2

### Level 29 : Extract information using git braches

![/assets/images/OverTheWire/Bandit/Untitled%2077.png](/assets/images/OverTheWire/Bandit/Untitled%2077.png)

Viewed the branches

![/assets/images/OverTheWire/Bandit/Untitled%2078.png](/assets/images/OverTheWire/Bandit/Untitled%2078.png)

Checkout to dev

```bash
git checkout remotes/origin/dev
```

![/assets/images/OverTheWire/Bandit/Untitled%2079.png](/assets/images/OverTheWire/Bandit/Untitled%2079.png)

5b90576bedb2cc04c86a9e924ce42faf

### Level 30 : Extract information from git tags

![/assets/images/OverTheWire/Bandit/Untitled%2080.png](/assets/images/OverTheWire/Bandit/Untitled%2080.png)

Viewed tags 

```bash
git tags
```

![/assets/images/OverTheWire/Bandit/Untitled%2081.png](/assets/images/OverTheWire/Bandit/Untitled%2081.png)

47e603bb428404d265f59c42920d81e5

### Level 31 : Pushing file to a git repo

![/assets/images/OverTheWire/Bandit/Untitled%2082.png](/assets/images/OverTheWire/Bandit/Untitled%2082.png)

Created a file:

```bash
bandit28@bandit:/tmp/31/repo$ echo "May I come in?" > key.txt
```

Got warning while adding the file

![/assets/images/OverTheWire/Bandit/Untitled%2083.png](/assets/images/OverTheWire/Bandit/Untitled%2083.png)

This is because .gitignore file had *.txt entry

![/assets/images/OverTheWire/Bandit/Untitled%2084.png](/assets/images/OverTheWire/Bandit/Untitled%2084.png)

Added using -f flag , committed and pushed

```bash
bandit28@bandit:/tmp/31/repo$ git add -f key.txt 
bandit28@bandit:/tmp/31/repo$ git commit -m "dafas"
bandit28@bandit:/tmp/31/repo$ git push
```

![/assets/images/OverTheWire/Bandit/Untitled%2085.png](/assets/images/OverTheWire/Bandit/Untitled%2085.png)

56a9bf19c63d650ce78e6ec0354ee45e

### Level 32 : $0

![/assets/images/OverTheWire/Bandit/Untitled%2086.png](/assets/images/OverTheWire/Bandit/Untitled%2086.png)

$0 is used to escape the shell.

Detailed explanation is here : 

[https://www.reddit.com/r/hacking/comments/dxe2c2/bandit_level_32_explained_pls_overthewire/](https://www.reddit.com/r/hacking/comments/dxe2c2/bandit_level_32_explained_pls_overthewire/)

![/assets/images/OverTheWire/Bandit/Untitled%2087.png](/assets/images/OverTheWire/Bandit/Untitled%2087.png)