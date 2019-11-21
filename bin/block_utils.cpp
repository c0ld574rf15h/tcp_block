#include "block_utils.h"
#include <cstring>
#include <cstdlib>
#include <arpa/inet.h>
#include <iostream>
using namespace std;

void swap_range(BYTE *first, BYTE *second, DWORD size) {
    BYTE *tmp = (BYTE*)malloc(size);
    memcpy(tmp, first, size);
    memcpy(first, second, size);
    memcpy(second, tmp, size);
    free(tmp);
}

WORD tcp_checksum(tcp_hdr *tcp, ip_hdr *ip) {
    WORD tcp_hlen = ((tcp->hlen) & 0xF0) >> 2;
    tcp->checksum = 0;
    DWORD checksum = 0;

    pseudo_hdr *p_hdr;
    memcpy(p_hdr->src_ip, ip->src_addr, sizeof(PROTO_ADDR_LEN));
    memcpy(p_hdr->dst_ip, ip->dst_addr, sizeof(PROTO_ADDR_LEN));
    p_hdr->reserved = 0x00;
    p_hdr->protocol = PROTO_TCP;
    p_hdr->tcp_len = htons(tcp_hlen);
    
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

bool send_block(pcap_t *handle, BYTE *data, BYTE flag, BYTE direction) {
    // 1. Segment Ethernet Header
    eth_hdr *eth = (eth_hdr*)data;
    // 2. Segment IP Header
    ip_hdr *ip = (ip_hdr*)(data + ETH_SZ);
    DWORD ip_hlen = ((ip->ver_hlen) & 0x0F) << 2;
    // 3. Segment TCP Header
    tcp_hdr *tcp = (tcp_hdr*)(data + ETH_SZ + ip_hlen);
    DWORD tcp_hlen = ((tcp->hlen) & 0xF0) >> 2;
    // 4. Get Length of TCP Payload
    DWORD payload_len = ntohs(ip->total_len)-(ip_hlen+tcp_hlen);

    // Compute New Sequence Number
    tcp->seq_num = htonl(ntohl(tcp->seq_num)+payload_len);
    // Our packet won't contain any payload within
    ip->total_len = htons(ntohs(ip->total_len)-payload_len);

    if(direction == FWD) {
        if(flag == RST) {   
            // 1. Set the flags
            tcp->flags = (ACK | RST);
            // 2. Compute the new checksum value; TCP and IP
            tcp->checksum = htons(tcp_checksum(tcp, ip));
            ip->checksum = htons(ip_checksum(ip, ip_hlen));
            return pcap_sendpacket(handle, data, ETH_SZ+ntohs(ip->total_len)) == SEND_SUCCESS;
        } else if(flag == FIN) {
            tcp->flags = (ACK | FIN);
            tcp->checksum = htons(tcp_checksum(tcp, ip));
            ip->checksum = htons(ip_checksum(ip, ip_hlen));
            return pcap_sendpacket(handle, data, ETH_SZ+ntohs(ip->total_len)) == SEND_SUCCESS;
        } else {
            return false;
        }
    } else if(direction == BWD) {
        swap_range(eth->dst_hw_addr, eth->src_hw_addr, HW_ADDR_LEN);                    // Swap hardware addresses
        swap_range(ip->src_addr, ip->dst_addr, PROTO_ADDR_LEN);                         // Swap protocol addresses
        swap_range((BYTE*)&(tcp->src_port), (BYTE*)&(tcp->dst_port), sizeof(WORD));     // Swap port numbers
        swap_range((BYTE*)&(tcp->seq_num), (BYTE*)&(tcp->ack_num), sizeof(DWORD));      // Swap seq & ack numbers
        if(flag==RST) {
            tcp->flags = (ACK | RST);
            tcp->checksum = htons(tcp_checksum(tcp, ip));
            ip->checksum = htons(ip_checksum(ip, ip_hlen));
            return pcap_sendpacket(handle, data, ETH_SZ+ntohs(ip->total_len)) == SEND_SUCCESS;
        } else if(flag==FIN) {
            tcp->flags = (ACK | FIN);
            tcp->checksum = htons(tcp_checksum(tcp, ip));
            ip->checksum = htons(ip_checksum(ip, ip_hlen));
            return pcap_sendpacket(handle, data, ETH_SZ+ntohs(ip->total_len)) == SEND_SUCCESS;
        } else {
            return false;
        }
    }
    // By default, return false
    return false;
}