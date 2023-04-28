#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct {
    char* dev_; // 사용할 네트워크 인터페이스
} Param;

Param param = {
    .dev_ = NULL // 초기화
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1]; // 사용자 입력으로부터 네트워크 인터페이스 이름 받아오기
    return true;
}


int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf); // pcap 라이브러리를 사용하여 네트워크 인터페이스 열기
    if (pcap == NULL) { // 에러 처리
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) { // 패킷 수신
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet); // 다음 패킷 수신

        if (res == 0) continue; // 패킷 수신이 아직 안 된 경우 계속 수신 대기
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) { // 에러 처리
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        // Parse Ethernet header
        struct libnet_ethernet_hdr *eth_hdr = (struct libnet_ethernet_hdr *) packet; // 이더넷 헤더 구조체
        uint16_t type = ntohs(eth_hdr->ether_type);
        // 프로토콜 타입
        // ntohs(): TCP/IP 네트워크 바이트 순서에서 16비트 숫자를 사용하고 호스트 바이트 순서로 16비트 숫자를 반환
        // 호스트 바이트 순서 : big-endian or little-endian
        // 네트워크 바이트 순서 : only big-endian
        int offset = sizeof(struct libnet_ethernet_hdr); // 오프셋 초기화

        if(type == ETHERTYPE_IP) { // IP 프로토콜인 경우에만 수행

            // Parse IP header (IP 헤더 파싱)
            struct libnet_ipv4_hdr *ip_hdr = (struct libnet_ipv4_hdr *)(packet + offset); // IP 헤더 구조체
            offset += (ip_hdr->ip_hl * 4); // IP 헤더 크기만큼 오프셋 증가

            // Parse TCP header (TCP 헤더 파싱)
            struct libnet_tcp_hdr *tcp_hdr = (struct libnet_tcp_hdr *)(packet + offset); // TCP 헤더 구조체
            offset += (tcp_hdr->th_off * 4); // TCP 헤더 크기만큼 오프셋 증가

            // Print the source and destination addresses and ports
            printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr->ether_shost[0], eth_hdr->ether_shost[1],
                   eth_hdr->ether_shost[2], eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);
            printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1],
                   eth_hdr->ether_dhost[2], eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5]);
            printf("Source IP: %s\n", inet_ntoa(ip_hdr->ip_src));
            printf("Destination IP: %s\n", inet_ntoa(ip_hdr->ip_dst));
            printf("Source port: %d\n", ntohs(tcp_hdr->th_sport));
            printf("Destination port: %d\n", ntohs(tcp_hdr->th_dport));

            // Print payload (data)
            int payload_size = header->caplen - offset;
            if (payload_size > 0) {
                printf("Payload: ");
                for (int i = 0; i < payload_size && i < 10; i++) {
                    printf("%02x ", *(packet + offset + i));
                }
                printf("\n");
            }
        }
    }

    pcap_close(pcap);
    return 0;
}
