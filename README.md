# pCloud Console Client

A simple Linux console client for [pCloud](https://pcloud.com) cloud storage.

## Prerequisites

To build pCloud Console Client you'll need the following requirements:

- [Zlib](http://zlib.net/) >= 1.1.4: A software library used for data compression
- [Boost](http://www.boost.org/) >= 1.58: Boost system and boost program options libraries used for console client
- [Pthread](https://www.gnu.org/software/pth/): The GNU Portable Threads
- [Fuse](https://github.com/libfuse/libfuse) >= 2.6, < 3.0: Filesystem in Userspace
- [SQLite](https://www.sqlite.org/index.html) >= 3.0

Also, you'll need the following build tools:

- A C99/C++11 compatible compiler such as
  [GCC](https://gcc.gnu.org),
  [Intel C++ Compiler](https://software.intel.com/content/www/us/en/develop/tools/oneapi/components/dpc-compiler.html),
  [Clang](https://clang.llvm.org) or
  [Apple Clang](https://apps.apple.com/us/app/xcode/id497799835)
- [CMake](https://cmake.org/) >= 2.6
- [GNU Make](https://www.gnu.org/software/make)

**Note:** Some parts of the client use GNU extensions to ISO C99 standard,
thus your compiler should support `-std=gnu99`.

On Debian and its derivatives you can install the required packages this way:

```shell
$ sudo apt install \
    build-essential \
    cmake \
    fuse \
    gcc \
    libboost-program-options-dev \
    libboost-system-dev \
    libfuse-dev \
    libpthread-stubs0-dev \
    libudev-dev \
    zlib1g-dev
```
On macOS, you most likely have a bundled with Xcode compiler as well as pthread:

```shell
$ brew install \
    cmake \
    macfuse \
    boost \
    zlib
```

## Build steps

First you'll need clone the project:

```shell
$ git clone https://github.com/pcloudcom/console-client.git
$ cd console-client
```

Finally, configure and build project as follows:

```shell
$ cd pCloudCC/lib/pclsync
$ make clean fs

$ cd ../mbedtls
$ cmake .
$ make clean
$ make

$ cd ../..
$ cmake .
$ make

$ sudo make install
$ sudo ldconfig

$ pcloudcc -u username -p
```

## Usage

Terminal command is `pcloudcc` and `-h` option prints short options description.

```
$ pcloudcc -h
pCloud console client v.2.0.1
Allowed options:
  -h [ --help ]             produce help message
  -u [ --username ] arg     pCloud account name
  -p [ --password ]         pCloud account password
  -c [ --crypto ] arg       Crypto password
  -y [ --passascrypto ] arg Use user password as crypto password also.
  -d [ --daemonize ]        Daemonize the process.
  -o [ --commands  ]        Parent stays alive and processes commands.
  -m [ --mountpoint ] arg   Mount point where drive to be mounted.
  -k [ --commands_only ]    Daemon already started pass only commands.
  -n [ --newuser ]          Switch if this is a new user to be registered.
  -s [ --savepassword ]     Save password in database.
```

Also, there are several commands that the running service can execute. Commands are passed using

```shell
$ pcloudcc -k
```

or  starting the daemon with `-o`. Available commands are:
- `startcrypto <crypto pass>` - starts crypto using given password.
- `stopcrypto` – stops the crypto.
- `finalize` – stops the running daemon.
- `quit`, `q` - exits the current client. Daemon stays alive.

### Example usage scenario

1. Start the service manually
   ```shell
   $ pcloudcc -u example@myemail.com -p -s
   ```
2. Enter password and use `-s` switch to save the password.
3. Verify that file system starts and mounts normally. If you don't have
   existing user use `-n` switch to register new user:
   ```shell
   $ pcloudcc -u example@myemail.com -p -s -n
   ```
   Notice that a new user may take a while to mount. Please, be patient.
4. Start the daemon service:
   ```shell
   $ pcloudcc -u example@myemail.com -d
   ```
5. Verify the file system is mounted.
6. At that point you can test passing some commands.
   ```shell
   $ pcloudcc -u example@myemail.com -k
   ```
   Or starting the daemon with `-o`. Test unlocking and locking crypto if you
   have subscription for it.
7. Quit the client. Congratulations, your pCloud Console Client works properly.
   You can now add `pcloudcc -u example@myemail.com -d` command in you startup
   scripts  and thous mount the file system on startup.

**Note:** Stopping daemon will break pending background transfers.
Current version of `pcloudcc` doesn't support command to check if there are
pending transfers. Locally cached files are located under `~/.pcloud/Cache`
directory. When there is only one file `~/.pcloud/Cache/cached` (usually big sized)
this mean that all transfers are completed.

## Autostart on system boot

It's probably easiet to just follow
[these instructions](https://www.howtogeek.com/228467/how-to-make-a-program-run-at-startup-on-any-computer/)
for setting up autostart. Alternatively, you can try following the instructions below.

### Linux (systemd)

Create `~/.config/systemd/user/pcloudcc.service` file with the following contents:

```ini
[Unit]
Description=Console client for pCloud cloud storage
Documentation=https://github.com/pcloudcom/console-client
After=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/pcloudcc -u example@myemail.com
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Then run:
```shell
$ systemctl enable --user pcloudcc
```

followed by:
```shell
$ systemctl start --user pcloudcc
```

Remember to initialize you account first by running:

```shell
$ pcloudcc -u example@myemail.com -p -s
```

## Packages

### Current stable packages

- Ubuntu 18.04 64 bit
  [pcloudcc_2.1.0-1_amd64_ubuntu.18.04.deb](https://my.pcloud.com/publink/show?code=XZvLyi7Zsz7t1H0aYIFiawL4LSgN3uxLBUJX)
- Debian 9.9 64 bit
  [pcloudcc_2.1.0-1_amd64_debian.9.9.deb](https://my.pcloud.com/publink/show?code=XZYVyi7ZseHyB89XXK0lVAdyy0AwQYl7osU7)
- Debian 9.9 32 bit
  [pcloudcc_2.1.0-1_i386_debian.9.9.deb](https://my.pcloud.com/publink/show?code=XZuVyi7ZLevxTwQKGrSrxp8uIrQodBwDfX67)

### Older pre-built packages

- Binary package 64 bit
  [pcloudcc_2.0.1-1_amd64.deb](https://my.pcloud.com/publink/show?code=XZv1aQ7ZkEd1Vr0gj3hTteoDtujd481o7amk)
- Ubuntu 17.10 64 bit
  [pcloudcc_2.0.1-1_amd64_ubuntu.17.10.deb](https://my.pcloud.com/publink/show?code=XZFeaQ7ZH1nHUfK4MLzGdeCvmmJywBUFANyy)
- Ubuntu 14.04 64 bit
  [pcloudcc_2.0.1-1_amd64_ubuntu.14.04.deb](https://my.pcloud.com/publink/show?code=XZSeaQ7ZFPq1g8oowJXyXap7KKzTtSKoACHy)

### Build package

To create a Debian package form the source use:

```shell
$ debuild -i -us -uc -b
```
