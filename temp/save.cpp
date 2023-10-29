#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <vector>

std::vector<std::vector<u_char>> captured_packets;
std::vector<struct pcap_pkthdr> pkthdrs;
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *)packet;
    int ether_type=ntohs(eth_header->ether_type);
    if(!(ether_type==0x86dd||ether_type==0x0800)){
    }else if(ether_type==0x0800){
        struct ip *ip_header = (struct ip *)(packet + ETHER_HDR_LEN);
        int protocol=ip_header->ip_p;
        if(protocol==1||protocol==6||protocol==17){
            // 将捕获的数据包存储在Vector中
            std::vector<u_char> captured_packet(packet, packet + pkthdr->len);
            pkthdrs.push_back(*pkthdr);
            captured_packets.push_back(captured_packet);
        }
    }
}
void savepacp(pcap_t *handle){
    pcap_dumper_t *pcap_dumper = NULL;
    // 打开一个用于保存pcap文件的文件
    const char* output_filename = "out.pcap";
    pcap_dumper = pcap_dump_open(handle,output_filename);
    if(pcap_dumper==nullptr){
        printf("Can not open pcapfile\n");
        return;
    }
    // 写入文件
    for(int i=0;i<pkthdrs.size();++i){
        pcap_dump((u_char *)pcap_dumper, &pkthdrs[i], &captured_packets[i][0]);
    }
    // 关闭pcap文件
    if (pcap_dumper != NULL) {
        pcap_dump_close(pcap_dumper);
    }
}
int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live("wlan0\0", BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Error opening device: %s\n", errbuf);
        return 1;
    }

    // 指定要捕获的数据包数量，这里设置为5
    int num_packets_to_capture = 10;
    pcap_loop(handle, num_packets_to_capture, packet_handler,nullptr);
    savepacp(handle);
    pcap_close(handle);
    return 0;
}
