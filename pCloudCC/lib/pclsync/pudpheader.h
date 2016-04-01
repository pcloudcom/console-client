#ifndef PUDPHEADER_H
#define PUDPHEADER_H
// UDP header's structure
struct udpheader {
 unsigned short int udph_srcport;
 unsigned short int udph_destport;
 unsigned short int udph_len;
 unsigned short int udph_chksum;
};
// total udp header length: 8 bytes (=64 bits)
#endif //PUDPHEADER_H