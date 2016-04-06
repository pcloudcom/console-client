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
-  -h [ --help ]             produce help message
-  -u [ --username ] arg     pCloud account name
-  -p [ --password ] arg     pCloud account password
-  -c [ --crypto ] arg       Crypto password
-  -s [ --passascrypto ] arg Use user password as crypto password also.
-  -d [ --daemonize ]        Daemonize the process.
-  -o [ --commands  ]        Parent stays alive and processes commands. 
-  -m [ --mountpoint ] arg   Mount point where drive to be mounted.
-  -k [ --commands_only ]    Daemon already started pass only commands
  
If you whant to be able to mount the files system as non root user you will have to create file   
/etc/fuse.conf   
and put user_allow_other in it.  

## Debian
To create a debian package form the source use:  
> debuild -i -us -uc -b  

## Other distributions
- Binary packages  
  [pcloudcc-2.0.1-Linux.sh](https://my.pcloud.com/publink/show?code=XZO7zQZ78ctjSJYvzkhz2mpXjpYMYR3JwjV)   
  [pcloudcc-2.0.1-Linux.tar.gz](https://my.pcloud.com/publink/show?code=XZ67zQZ0g2x2gBY4HBi5PmjTRairHiblMmk)  
  [pcloudcc-2.0.1-Linux.tar.Z](https://my.pcloud.com/publink/show?code=XZq7zQZ1glJyYog7L7X1ef8o54GtmjXJT57)  
  [pcloudcc_2.0.1-1_amd64.deb](https://my.pcloud.com/publink/show?code=XZA7zQZrSgwBshWrl8UryJRIGE6o4ljHAi7)  
- Source  
  [pcloudcc_2.0.1_Source.tar.gz](https://my.pcloud.com/publink/show?code=XZI7zQZrxhTlHgqi0YEodNz1l0upmwcSJik)  
