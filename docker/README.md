## pCloud Docker Container

The Dockerfile downloads and builds the simple linux client for pCloud cloud storage into a tiny
alpine Linux container. 

### Build instruction

```
docker build -f Dockerfile -t pcloud .
```

Use 'docker images' to show the created container image:

```
core@m1 ~/pcloud $ docker images
REPOSITORY                   TAG                 IMAGE ID            CREATED              SIZE
pcloud                       latest              c1a2d69d3699        About a minute ago   19.02 MB
```

### Usage

The container requires privileged mode in order to expose the Fuse based file system to the host.
The default path of the mount point within the container is /root/pCloudDrive with supporting 
files in /root/.pcloud (which contains e.g. the saved password). In order to gain persistency 
between reboots and container restarts, the /root directory must be exposed and shared with the host.
This is done via the docker run '-v' option combined with ':shared'. 

Because the pcloudcc client doesn't offer a command line option to set the password or read from a file, the container must be launched once in interactive mode to set and save the password. 

Launch the pcloud container with your pcloud username and options to set and save the password.
Once the message 'status is READY' is shown, you can stop the container with Ctrl-C (to relaunch it later as a daemon).

```
/usr/bin/docker run --name pcloud -ti --rm --privileged -v /pCloud:/root:shared pcloud -u <username> -p -s
pCloud console client v.2.0.1
Please, enter password
<enter-password-here>
sh: lsb_release: not found
Down: Everything Downloaded| Up: Everything Uploaded, status is LOGIN_REQUIRED
logging in
Down: Everything Downloaded| Up: Everything Uploaded, status is CONNECTING
Down: Everything Downloaded| Up: Everything Uploaded, status is SCANNING
event1073741824
event1073741825
Down: Everything Downloaded| Up: Everything Uploaded, status is READY
^C
```

This initial run created the directory /pCloud on the host with the .pcloud pCloudDriver directories, though the latter is empty without a running container:

```
$ ls -la /pCloud/
total 16
drwxr-xr-x  4 root root 4096 Jan  2 13:53 .
drwxr-xr-x 26 root root 4096 Jan  2 13:53 ..
drwxr-xr-x  3 root root 4096 Jan  2 13:53 .pcloud
drwxr-xr-x  2 root root 4096 Jan  2 13:53 pCloudDrive
```

Launch the container as daemon:

```
docker run --name pcloud -d --privileged -v /pCloud:/root:shared pcloud -u <username>
```

Verify the content of pCloudDrive:

```
$ ls /pCloud/pCloudDrive/
Crypto Folder  My Pictures  Screenshots  pCloud Sync
My Music       My Videos    Shared       pCloud Help  
```

### Systemd 

Once an initial password has been set, the container can be managed automatically via systemd using the following service file:

```
$ cat /etc/systemd/system/pcloud.service
[Unit]
Description=pCloud
After=docker.service
Requires=docker.service

[Service]
TimeoutStartSec=0
ExecStartPre=-/usr/bin/docker kill pcloud
ExecStartPre=-/usr/bin/docker rm pcloud
ExecStart=/usr/bin/docker run --name pcloud -i --rm --privileged -v /pCloud:/root:shared pcloud -u <username>

[Install]
WantedBy=multi-user.target
```

Enable and run the pcloud service with

```
sudo systemctl enable /etc/systemd/system/pcloud.service
sudo systemctl start pcloud.service
```


