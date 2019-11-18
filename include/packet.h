#pragma once

#include <pcap.h>
#include <string>
using namespace std;

#define HW_ADDR_LEN         6
#define PROTO_ADDR_LEN      4

#define ETH_SZ              14
#define PROTO_IP            0x0800
#define PROTO_TCP           6
#define HTTP_METHODS_NUM    6

// Maximum Transmission Units through Ethernet
#define MTU     1500

// For extract_host
#define EXT_THRESHOLD   100
#define HOSTNAME_SZ     100

typedef u_int8_t    BYTE;
typedef u_int16_t   WORD;
typedef u_int32_t   DWORD;

// Ethernet Header
struct eth_hdr {
    BYTE dst_hw_addr[HW_ADDR_LEN];
    BYTE src_hw_addr[HW_ADDR_LEN];
    WORD ether_type;
};

// IP Header
struct ip_hdr {
    BYTE ver_hlen, tos;
    WORD total_len;
    WORD ident, frag_offset;
    BYTE ttl, protocol;
    WORD checksum;
    BYTE src_addr[PROTO_ADDR_LEN], dst_addr[PROTO_ADDR_LEN];
};

// TCP Header
struct tcp_hdr {
    WORD src_port, dst_port;
    DWORD seq_num, ack_num;
    BYTE hlen, flags;
    WORD window;
    WORD checksum, urg_ptr;
};

string extract_host(const BYTE *http_field);
bool is_HTTP(const BYTE *data, BYTE *hostname);
bool check_host(const BYTE *data, const BYTE* host, int host_len);