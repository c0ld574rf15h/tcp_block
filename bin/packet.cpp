#include <arpa/inet.h>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include "packet.h"
using namespace std;

string extract_host(const BYTE *http_field) {
    string ret = "";
    int idx = 0;
    while(true) {
        if(!memcmp(http_field+idx, "Host: ", strlen("Host: "))) {
            idx += 6;
            for(int i=0;memcmp(http_field+idx+i, "\x0D\x0A", 2);++i)
                ret += (unsigned char)http_field[idx+i];
        }
        idx += 1;
        if(idx > EXT_THRESHOLD) break;
    }
    return ret;
}

bool is_HTTP(const BYTE *data, BYTE *hostname) {
    const char* http_methods[HTTP_METHODS_NUM] = {
        "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"
    };

    const eth_hdr *eth = (const eth_hdr*)data;
    if(eth->ether_type == htons(PROTO_IP)) {
        const ip_hdr *ip = (const ip_hdr*)(data + ETH_SZ);
        BYTE ip_hlen = ((ip->ver_hlen) & 0x0F) << 2;
        if(ip -> protocol == PROTO_TCP) {
            const tcp_hdr *tcp = (const tcp_hdr*)(data + ETH_SZ + ip_hlen);
            WORD tcp_hlen = ((tcp -> hlen) & 0xF0) >> 2;
            const BYTE *app_layer = (const BYTE*)(data + ETH_SZ + ip_hlen + tcp_hlen);
            for(int i=0;i<HTTP_METHODS_NUM;++i) {
                if(!memcmp(app_layer, http_methods[i], strlen(http_methods[i]))) {
                    string host = extract_host(app_layer);
                    memcpy(hostname, host.c_str(), host.length());
                    return true;
                }
            }
        }
    }
    return false;
}

bool check_host(const BYTE *data, const BYTE *host, int host_len) {
    BYTE *hostname = (BYTE*)malloc(HOSTNAME_SZ);
    if(is_HTTP(data, hostname)) {
        if(!memcmp(hostname, host, host_len))
            return true;
    }
    free(hostname);
    return false;
}