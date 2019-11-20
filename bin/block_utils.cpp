#include "block_utils.h"
#include <algorithm>
#include <string.h>
using namespace std;

WORD tcp_checksum(tcp_hdr *tcp, ip_hdr *ip) {
    WORD tcp_hlen = ((tcp->hlen) & 0xF0) >> 2;
    tcp->checksum = 0;
    DWORD checksum = 0;

    pseudo_hdr *p_hdr;
    memcpy(p_hdr->src_ip, ip->src_addr, sizeof(PROTO_ADDR_LEN));
    memcpy(p_hdr->dst_ip, ip->dst_addr, sizeof(PROTO_ADDR_LEN));
    p_hdr->reserved = 0x00;
    p_hdr->protocol = PROTO_TCP;
    p_hdr->tcp_len = tcp_hlen;
    
    for(int i=0;i<sizeof(pseudo_hdr);i+=sizeof(WORD))
        checksum += *(const WORD*)(p_hdr+i);
    for(int i=0;i<tcp_hlen;i+=sizeof(WORD))
        checksum += *(const WORD*)(tcp+i);
    while(checksum>>16)
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    return (WORD)(~checksum);
}

WORD ip_checksum(ip_hdr *ip, DWORD hlen) {
    ip->checksum = 0;
    DWORD checksum = 0;
    for(int i=0;i<hlen;i+=sizeof(WORD))
        checksum += *(const WORD*)(ip+i);
    while(checksum >> 16)
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    return (WORD)(~checksum);
}

void reverse_src_dst(eth_hdr *eth, ip_hdr *ip, tcp_hdr *tcp) {
    //swap_ranges(eth->dst_hw_addr, eth->src_hw_addr, eth->src_hw_addr);
    //swap_ranges(ip->src_addr, ip->dst_addr, ip->dst_addr);
    //swap_ranges(tcp->src_port, tcp->dst_port, tcp->dst_port);
}

bool send_block(pcap_t *handle, BYTE *data, BYTE flag, BYTE direction) {
    eth_hdr *eth = (eth_hdr*)data;

    ip_hdr *ip = (ip_hdr*)(data + ETH_SZ);
    DWORD ip_hlen = ((ip->ver_hlen) & 0x0F) << 2;
    
    tcp_hdr *tcp = (tcp_hdr*)(data + ETH_SZ + ip_hlen);
    DWORD tcp_hlen = ((tcp->hlen) & 0xF0) >> 2;
    
    DWORD payload_len = ip->total_len-(ip_hlen+tcp_hlen);
    
    switch(direction) {
        case FWD:
            switch(flag) {
                case RST:
                    tcp->flags &= 0x00;
                    tcp->flags |= (ACK | RST);
                    tcp->seq_num += payload_len;
                    tcp_checksum(tcp, ip);
                    ip->total_len -= payload_len;
                    ip_checksum(ip, ip_hlen);
                    return pcap_sendpacket(handle, data, ETH_SZ + ip_hlen + tcp_hlen);
                case FIN:
                    break;
                default:
                    return false;
            }
            break;
        case BWD:
            //reverse_src_dst(eth, ip, tcp);
            switch(flag) {
                case RST:
                    break;
                case FIN:
                    break;
                default:
                    return false;
            }
            break;
        default:
            return false;
    }
    return true;
}