#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <pcap.h>
#include <netinet/ether.h>

long int tv_usec0;
long int tv_sec0;

void printTimestamp(const struct pcap_pkthdr *pkthdr) {
    long int tv_sec = pkthdr->ts.tv_sec;
    long int tv_usec = pkthdr->ts.tv_usec;
    if (tv_sec0 == 0 && tv_usec0 == 0) {
        tv_sec0 = tv_sec;
        tv_usec0 = tv_usec;
    }
    if (tv_usec0 > tv_usec) {
        tv_sec -= 1;
        tv_usec += 1000000;
    }
    printf("Timestamp: %ld.%06ld seconds\n", tv_sec - tv_sec0, tv_usec - tv_usec0);
}

void printIpv4Flags(unsigned short flags) {
    printf("Flags: %s %s %s\n",
           (flags & IP_RF) ? "Reserved" : "",
           (flags & IP_DF) ? "Don't Fragment" : "",
           (flags & IP_MF) ? "More Fragments" : "");
}

int printFrame(const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    printf("-----------以太网帧-----------\n");
    printTimestamp(pkthdr);
    printf("Packet Length: %d\n",pkthdr->len);
    // 解析以太网帧
    struct ether_header *eth_header = (struct ether_header *)packet;
    // 打印目标MAC地址
    printf("Destination MAC Address: %s\n", ether_ntoa((struct ether_addr *)&eth_header->ether_dhost));
    // 打印源MAC地址
    printf("Source MAC Address: %s\n", ether_ntoa((struct ether_addr *)&eth_header->ether_shost));
    // 打印以太网帧类型或长度
    if (ntohs(eth_header->ether_type) <= 1500) {
        printf("Frame Length/Type: %u (IEEE 802.3 Ethernet)\n", ntohs(eth_header->ether_type));
    } else {
        if (ntohs(eth_header->ether_type) == 0x86dd) {
            printf("Frame Type: IPv6 (0x86dd)\n");
        } else if (ntohs(eth_header->ether_type) == 0x0800) {
            printf("Frame Type: IPv4 (0x0800)\n");
            return 1;
        } else {
            printf("Frame Type: Not support (0x%04x)\n", ntohs(eth_header->ether_type));
        }
    }
    return 0;
}

int printIPHead(const u_char *packet) {
    printf("-----------IP数据报-----------\n");
    // IPv4帧
    struct ip *ip_header = (struct ip *)(packet + ETHER_HDR_LEN);
    // 打印第一部分：版本，首部长度，区分服务，总长度
    printf("Version: %d\n", ip_header->ip_v);
    printf("Header Length: %d bytes\n", ip_header->ip_hl * 4);
    printf("Differentiated Services: 0x%02X\n", ip_header->ip_tos);
    printf("Total Length: %d bytes\n", ntohs(ip_header->ip_len));

    // 打印第二部分：标识，标志，偏移
    printf("Identification: %d\n", ntohs(ip_header->ip_id));
    printIpv4Flags(ntohs(ip_header->ip_off));
    printf("Fragment Offset: %d\n", ntohs(ip_header->ip_off) & IP_OFFMASK);

    // 打印第三部分：生存时间，协议，首部校验和
    printf("Time to Live: %d\n", ip_header->ip_ttl);
    switch (ip_header->ip_p){
    case 1:
        printf("Protocol: ICMP (1)\n");
        break;
    case 6:
        printf("Protocol: TCP (6)\n");
        break;
    case 17:
        printf("Protocol: UDP (17)\n");
        break;
    default:
        printf("Protocol: Not support(%d)\n",ip_header->ip_p);
        break;
    }
    printf("Header Checksum: 0x%04X\n", ntohs(ip_header->ip_sum));

    // 打印第四部分：源地址，目的地址
    printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
    printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));

    // 返回协议类型（6表示TCP）
    return ip_header->ip_p;
}

void printTCPHead(const u_char *packet) {
    printf("-----------TCP报头-----------\n");
    
    // 解析IP头部，获取首部长度，然后计算TCP头部的位置
    struct ip *ip_header = (struct ip *)(packet + ETHER_HDR_LEN);
    int ip_header_len = ip_header->ip_hl * 4;
    const u_char *tcp_packet = packet + ETHER_HDR_LEN + ip_header_len;

    struct tcphdr *tcp_header = (struct tcphdr *)(tcp_packet);

    printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
    printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));
    printf("Sequence Number: %u\n", ntohl(tcp_header->th_seq));
    printf("Acknowledgment Number: %u\n", ntohl(tcp_header->th_ack));
    printf("Data Offset: %d bytes\n", tcp_header->th_off * 4);
    printf("Flags: ");
    if (tcp_header->th_flags & TH_FIN) printf("FIN ");
    if (tcp_header->th_flags & TH_SYN) printf("SYN ");
    if (tcp_header->th_flags & TH_RST) printf("RST ");
    if (tcp_header->th_flags & TH_PUSH) printf("PSH ");
    if (tcp_header->th_flags & TH_ACK) printf("ACK ");
    if (tcp_header->th_flags & TH_URG) printf("URG ");
    printf("\n");
    printf("Window Size: %d\n", ntohs(tcp_header->th_win));
    printf("Checksum: 0x%04X\n", ntohs(tcp_header->th_sum));
    printf("Urgent Pointer: %d\n", ntohs(tcp_header->th_urp));
}

void printUDPHead(const u_char *packet) {
    printf("-----------UDP头-----------\n");
    
    // 解析IP头部，获取首部长度，然后计算UDP头部的位置
    struct ip *ip_header = (struct ip *)(packet + ETHER_HDR_LEN);
    int ip_header_len = ip_header->ip_hl * 4;
    const u_char *udp_packet = packet + ETHER_HDR_LEN + ip_header_len;

    struct udphdr *udp_header = (struct udphdr *)(udp_packet);

    printf("Source Port: %d\n", ntohs(udp_header->uh_sport));
    printf("Destination Port: %d\n", ntohs(udp_header->uh_dport));
    printf("Length: %d bytes\n", ntohs(udp_header->uh_ulen));
    printf("Checksum: 0x%04X\n", ntohs(udp_header->uh_sum));
}

void printICMP(const u_char *packet) {
    printf("-----------ICMP数据报-----------\n");
    
    // 解析IP头部，获取首部长度，然后计算ICMP数据报的位置
    struct ip *ip_header = (struct ip *)(packet + ETHER_HDR_LEN);
    int ip_header_len = ip_header->ip_hl * 4;
    const u_char *icmp_packet = packet + ETHER_HDR_LEN + ip_header_len;

    // ICMP头部没有特定的结构，您可以根据需要解析各个字段
    // 下面只是一个示例，解析了类型和代码字段
    printf("Type: %d\n", icmp_packet[0]);
    printf("Code: %d\n", icmp_packet[1]);
    printf("Checksum: 0x%04X\n", ntohs(*(uint16_t *)(icmp_packet + 2)));
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    int analyzable = printFrame(pkthdr, packet);
    int protocol=-1;
    if (analyzable) {
        protocol = printIPHead(packet);
    }
    switch (protocol){
    case 1:
        printICMP(packet);
        break;
    case 6:
        printTCPHead(packet);
        break;
    case 17:
        printUDPHead(packet);
        break;
    default:
        break;
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <file.pcap>\n", argv[0]);
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(argv[1], errbuf);

    if (handle == NULL) {
        printf("Error opening file: %s\n", errbuf);
        return 1;
    }

    printf("Reading packets from file: %s\n", argv[1]);

    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}
