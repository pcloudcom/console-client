# pCloud Console Client

This is a simple linux console client for pCloud cloud storage. 

## Required libraries 
[Zlib](http://zlib.net/)  A Massively Spiffy Yet Delicately Unobtrusive Compression Library
[Boost](http://www.boost.org/) Boost system and boost program options libraries used.
[Pthread](http://www.gnu.org/) 
[Fuse](https://github.com/libfuse/libfuse) Filesystem in Userspace.

Also requires 
[CMake](https://cmake.org/) build system.

On ubuntu you can run the following command:
> sudo apt-get install cmake zlib1g-dev libboost-system-dev libboost-program-options-dev libpthread-stubs0-dev libfuse-dev

## Usage
- ./pcl_client -h
- pCloud console client v.2.0.1
- Allowed options:
-   -h [ --help ]             produce help message
-  -u [ --username ] arg     pCloud account name
-  -p [ --password ] arg     pCloud account password
-  -c [ --crypto ] arg       Crypto password
-  -s [ --passascrypto ] arg Use user password as crypto password also.
-  -d [ --damonize ]        Daemonize the process.
-  -o [ --commands  ]        Parent stays alive and processes command after 
-                            daemoziation. 
-  -m [ --mountpoint ] arg   Mount point where drive to be mounted.
-  -k [ --commands_only ]    Demon already started pass only commands

- If you whant to be able to mount the files system as non root user you will have to create file 
- /etc/fuse.conf 
- and put user_allow_other in it.




