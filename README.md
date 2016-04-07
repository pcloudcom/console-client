# pCloud Console Client

This is a simple linux console client for pCloud cloud storage. 

## Required libraries 
[Zlib](http://zlib.net/)  A Massively Spiffy Yet Delicately Unobtrusive Compression Library.  
[Boost](http://www.boost.org/) Boost system and boost program options libraries used.  
[Pthread](http://www.gnu.org/)   
[Fuse](https://github.com/libfuse/libfuse) Filesystem in Userspace.  
  
Also requires   
[CMake](https://cmake.org/) build system.  

On Ubuntu you can run the following command:  
> sudo apt-get install cmake zlib1g-dev libboost-system-dev libboost-program-options-dev libpthread-stubs0-dev libfuse-dev  

## Usage
./pcloudcc -h  
  pCloud console client v.2.0.1  
Allowed options:  
-  -h [ --help ]             produce help message.
-  -u [ --username ] arg     pCloud account name.
-  -p [ --password ] arg     pCloud account password.
-  -c [ --crypto ] arg       Crypto password.
-  -s [ --passascrypto ] arg Use user password as crypto password also.
-  -d [ --daemonize ]        Daemonize the process.
-  -o [ --commands  ]        Parent stays alive and processes commands. 
-  -m [ --mountpoint ] arg   Mount point where drive to be mounted.
-  -k [ --commands_only ]    Daemon already started pass only commands.
  
If you whant to be able to mount the files system as non root user you will have to create file   
/etc/fuse.conf   
and put user_allow_other in it.  

## Debian
To create a debian package form the source use:  
> debuild -i -us -uc -b  

## Other distributions
- Binary packages  
  [pcloudcc-2.0.1-Linux.sh](https://my.pcloud.com/publink/show?code=XZJnzQZCFLB8o9PGEF4wG4sHCWGHHhUw4aV)   
  [pcloudcc-2.0.1-Linux.tar.gz](https://my.pcloud.com/publink/show?code=XZ0nzQZCzi5PmcxoNhf8b7jR8cnwflRRJlV)  
  [pcloudcc-2.0.1-Linux.tar.Z](https://my.pcloud.com/publink/show?code=XZoezQZxMTJDHe7LSXy7Xqzzme7ThrQcDly)  
  [pcloudcc_2.0.1-1_amd64.deb](https://my.pcloud.com/publink/show?code=XZ4nzQZOOG10GPkUSBbHWzgBzdHxVj18E4y)  
- Source  
  [pcloudcc_2.0.1_Source.tar.gz](https://my.pcloud.com/publink/show?code=XZFnzQZlcxeTHPnqahzlYd0V3oCIXygETq7)  
