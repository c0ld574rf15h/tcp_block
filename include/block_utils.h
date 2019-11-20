#pragma once
#include "packet.h"

#define SET_FIN     0
#define SET_RST     1
#define FWD         0
#define BWD         1

#define URG  0x20
#define ACK  0X10
#define PSH  0X08
#define RST  0X04
#define SYN  0X02
#define FIN  0X01

struct pseudo_hdr {
    BYTE src_ip[HW_ADDR_LEN], dst_ip[HW_ADDR_LEN];
    BYTE reserved, protocol;
    WORD tcp_len;
};

WORD tcp_checksum(tcp_hdr *tcp, ip_hdr *ip);
WORD ip_checksum(tcp_hdr *ip);
void reverse_src_dst(eth_hdr *eth, ip_hdr *ip, tcp_hdr *tcp);
bool send_block(pcap_t *handle, const BYTE *data, BYTE flag, BYTE direction);