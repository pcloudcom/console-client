// Must be run by root lol! Just datagram, no payload/data
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
 
// The packet length
#define HEADERS_LEN 8192

#include "pipheader.h"
#include "pudpheader.h"