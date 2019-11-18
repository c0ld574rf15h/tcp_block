#include <glog/logging.h>
#include <arpa/inet.h>
#include <cstring>

#include "packet.h"

bool is_HTTP(const BYTE *data) {
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
                    return true;
                }
            }
        }
    }
    return false;
}

bool check_host(const BYTE *data, const BYTE *host) {
    if(is_HTTP(data))
        return true;
    return false;
}