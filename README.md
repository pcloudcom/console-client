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
Terminal command is pcloudcc and -h option prints short options description.
> ./pcloudcc -h  
>  pCloud console client v.2.0.1  
>Allowed options:  
>  -h [ --help ]             produce help message  
>  -u [ --username ] arg     pCloud account name  
>  -p [ --password ]         pCloud account password  
>  -c [ --crypto ] arg       Crypto password  
>  -y [ --passascrypto ] arg Use user password as crypto password also.  
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
- quit, q  - exits the current client. Daemon sties  alive.

Example usage scenario:  
- Start the service manually  
> pcloudcc -u example@myemail.com -p -s   
Enter password and  use -s switch to save the password. Verify that file system starts and mounts normally. If you don't have existing user use -n switch to register new user:  
> pcloudcc -u example@myemail.com -p -s -n  
Notice that a new user may take a while to mount. Please, be patient.   
- Start the daemon service:   
> pcloudcc -u example@myemail.com -d  
Verify file system is mounted.  
- At that point you can test passing some commands.  
> pcloudcc -u example@myemail.com -k  
Or starting the daemon with -o. Test unlocking and locking crypto if you have subscription for it.   
- Quit the client. Congratulations, your pcloud console client works properly.  You can now add “pcloudcc -u example@myemail.com -d” command in you startup scripts  and thous mount the file system on startup.  


## Debian
To create a debian package form the source use:  
> debuild -i -us -uc -b  

## Other distributions
- Binary packages 64 bit   
  [pcloudcc-2.0.1-Linux.sh](https://my.pcloud.com/publink/show?code=XZSJfQZ8WLwavzS3mBd3hL2XRF4EH0KNKTX)   
  [pcloudcc-2.0.1-Linux.tar.gz](https://my.pcloud.com/publink/show?code=XZhJfQZFEVhUfCloBbnxcHq3MBishd2reIy)  
  [pcloudcc-2.0.1-Linux.tar.Z](https://my.pcloud.com/publink/show?code=XZmJfQZHwRI0Fje0vX3LVndD9EPSXhkwoNk)  
  [pcloudcc_2.0.1-1_amd64.deb](https://my.pcloud.com/publink/show?code=XZyJfQZtehgkk6mzTuG9zYK5D6skfbo2eS7)  
- Binary packages 32 bit   
  [pcloudcc-2.0.1-Linux_i386.sh](https://my.pcloud.com/publink/show?code=XZzJfQZj1uph6VKtgVWWNFUfuUAN8NeIpE7)   
  [pcloudcc-2.0.1-Linux_i386.tar.gz](https://my.pcloud.com/publink/show?code=XZpJfQZa1T9rIiIvRyppo78dDcmkSfbSJry)  
  [pcloudcc-2.0.1-Linux_i386.tar.Z](https://my.pcloud.com/publink/show?code=XZJJfQZEoEjfYVTiDhBxahTgOB6BYSGmKlX)  
  [pcloudcc_2.0.1-1_i386.deb](https://my.pcloud.com/publink/show?code=XZv5fQZLq6o3mXJjvLkLEjWvFUkLQijEsJy)  
- Source  
  [pcloudcc_2.0.1_Source.tar.gz](https://my.pcloud.com/publink/show?code=XZkJfQZRtCdmBOOkR4fKrbvxqKxujzmM6w7)  


pcloudcc_2.0.1-1_amd64.deb





pcloudcc-2.0.1-Linux.sh


pcloudcc-2.0.1-Linux.tar.gz


pcloudcc-2.0.1-Linux.tar.Z





pcloudcc-2.0.1-Linux_i386.tar.gz





pcloudcc-2.0.1-Source.tar.gz


