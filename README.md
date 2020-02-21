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
> sudo apt-get install cmake zlib1g-dev libboost-system-dev libboost-program-options-dev libpthread-stubs0-dev libfuse-dev libudev-dev 

## Build steps

> sudo apt-get install cmake zlib1g-dev libboost-system-dev libboost-program-options-dev libpthread-stubs0-dev libfuse-dev libudev-dev git  
> mkdir console-client   
> git clone https://github.com/pcloudcom/console-client.git ./console-client/  
> cd ./console-client/pCloudCC/   
> cd lib/pclsync/        
> make clean    
> make fs     
> cd ../mbedtls/   
> cmake .      
> make clean     
> make       
> cd ../..      
> cmake .    
> make      
> sudo make install     
> ldconfig     
> pcloudcc -u username -p       

## Usage
Terminal command is pcloudcc and -h option prints short options description.
> ./pcloudcc -h  
>  pCloud console client v.2.1.0
>Allowed options:  
>  -h [ --help ]             produce help message  
>  -u [ --username ] arg     pCloud account name  
>  -p [ --password ]         pCloud account password  
>  -c [ --crypto ] arg       Crypto password  
>  -y [ --passascrypto ] arg Use user password as crypto password also.
>  -t [ --trust ]            Trust this device.
>  -d [ --daemonize ]        Daemonize the process.  
>  -o [ --commands  ]        Parent stays alive and processes commands.   
>  -m [ --mountpoint ] arg   Mount point where drive to be mounted.  
>  -k [ --commands_only ]    Daemon already started pass only commands.  
>  -n [ --newuser ]          Switch if this is a new user to be registered.  
>  -s [ --savepassword ]     Save password in database.  


Also there are several commands that the running service can execute. Commands are passed using 
> pcloudcc -k 

or  starting the daemon with -o. 

Available commands are : startcrypto <crypto pass>, stopcrypto, finalize, q, quit  
- startcrypto <crypto pass> - starts cripto using given password.
-  stopcrypto – stops the crypto.
-   finalize – stops the running daemon.
- quit, q  - exits the current client. Daemon stays alive.


Example usage scenario:  
- Start the service manually

> pcloudcc -u example@myemail.com -p -s   

Enter password and  use -s switch to save the password. 

- Verify that file system starts and mounts normally. If you don't have existing user use -n switch to register new user:  

> pcloudcc -u example@myemail.com -p -s -n

Notice that a new user may take a while to mount. Please, be patient.   

- Start the daemon service:

> pcloudcc -u example@myemail.com -d  

- Verify file system is mounted.  

- At that point you can test passing some commands.

> pcloudcc -u example@myemail.com -k  

Or starting the daemon with -o. Test unlocking and locking crypto if you have subscription for it.   

- Quit the client. Congratulations, your pcloud console client works properly.  You can now add “pcloudcc -u example@myemail.com -d” command in you startup scripts  and thous mount the file system on startup.  


## Debian
To create a debian package form the source use:  
> debuild -i -us -uc -b  

## Pre-built packages
- Ubunutu 18.04 64 bit
  [pcloudcc_2.1.0-1_amd64_ubuntu.18.04.deb](https://my.pcloud.com/publink/show?code=XZvLyi7Zsz7t1H0aYIFiawL4LSgN3uxLBUJX)
- Debian 9.9 64 bit
  [pcloudcc_2.1.0-1_amd64_debian.9.9.deb](https://my.pcloud.com/publink/show?code=XZYVyi7ZseHyB89XXK0lVAdyy0AwQYl7osU7)
- Debian 9.9 32 bit
  [pcloudcc_2.1.0-1_i386_debian.9.9.deb](https://my.pcloud.com/publink/show?code=XZuVyi7ZLevxTwQKGrSrxp8uIrQodBwDfX67)

## Older pre-built packages
- Binary package 64 bit
  [pcloudcc_2.0.1-1_amd64.deb](https://my.pcloud.com/publink/show?code=XZv1aQ7ZkEd1Vr0gj3hTteoDtujd481o7amk)
- Ubunutu 17.10 64 bit
  [pcloudcc_2.0.1-1_amd64_ubuntu.17.10.deb](https://my.pcloud.com/publink/show?code=XZFeaQ7ZH1nHUfK4MLzGdeCvmmJywBUFANyy)
- Ubunutu 14.04 64 bit
  [pcloudcc_2.0.1-1_amd64_ubuntu.14.04.deb](https://my.pcloud.com/publink/show?code=XZSeaQ7ZFPq1g8oowJXyXap7KKzTtSKoACHy)


