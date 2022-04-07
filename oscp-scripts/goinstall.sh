##Author: Christian Galvan
##Date written: 4/6/2022 

#!/bin/bash

echo "   ,_---~~~~~----._         
  _,,_,*^____      _____``*g*\"*, 
 / __/ /'     ^.  /      \ ^@q   f 
[  @f | @))    |  | @))   l  0 _/  
 \`/   \~____ / __ \_____/    \   
  |           _l__l_           I   
  }          [______]           I  
  ]            | | |            |  
  ]             ~ ~             |  
  |                            |   
   |                           | "
#efficiently download golang for kali linux machine
echo "downloading go tar file.."
echo "downloading go tar file..."

axel -a -n 2 -o go18.linux-amd64.tar.gz  https://go.dev/dl/go1.18.linux-amd64.tar.gz

#remove any previous go installs

echo "removing prior installations...."
rm -rf /usr/local/go 
cd /usr/local

tar -xzf /home/kali/Downloads/go18.linux-amd64.tar.gz

#Path default path variables
export PATH=$PATH:/usr/local/go/bin

#export path to users profile
echo "export PATH=$PATH:/usr/local/go/bin" >> /etc/profile

source /etc/profile

#Check go version to test installation
go version