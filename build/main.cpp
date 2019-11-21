#include <glog/logging.h>
#include <pcap.h>
#include <iostream>
#include <cstdlib>

#include "packet.h"
#include "block_utils.h"

using namespace std;

int main(int argc, char* argv[]) {
    google::InitGoogleLogging(argv[0]);
    google::LogToStderr();

    if(argc != 3) {
        LOG(ERROR) << "Usage: " << argv[0] << " <interface> <host>";
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = argv[1];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 10, errbuf);
    if(handle == NULL) {
        LOG(ERROR) << "Couldn't open device " << errbuf;
    } else {
        LOG(INFO) << "Opened handle";
    }

    struct pcap_pkthdr *header;
    BYTE *data = (BYTE *)malloc(MTU);
    while(true) {
        // 1. Receive packet from host
        if(pcap_next_ex(handle, &header, (const u_char**)&data) == -1) {
            LOG(ERROR) << "Error during pcap_next_ex()";
            continue;
        }
        // 2. Analyze whether block is required
        if(check_host((const BYTE*)data, (const BYTE*)argv[2], strlen((const char*)argv[2]))) {
            LOG(WARNING) << "Block signal sent";
            // Log an error if any of the two fails
            if(!send_block(handle, data, FIN, FWD) ||
               !send_block(handle, data, FIN, BWD)) {
                LOG(ERROR) << "Something got wrong while sending block packets";
            }
        }
    }
    
    free(data); pcap_close(handle);
    return 0;
}