#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

/* 이더넷 헤더 */
struct ethheader {
    u_char  ether_dhost[6]; /* 목적지 MAC 주소 */
    u_char  ether_shost[6]; /* 출발지 MAC 주소 */
    u_short ether_type;     /* 프로토콜 유형 (IP, ARP, RARP 등) */
};

/* IP 헤더 */
struct ipheader {
    unsigned char      iph_ihl:4, // IP 헤더 길이
                       iph_ver:4; // IP 버전
    unsigned char      iph_tos; // 서비스 타입
    unsigned short int iph_len; // IP 패킷 길이 (데이터 + 헤더)
    unsigned short int iph_ident; // 식별자
    unsigned short int iph_flag:3, // 단편화 플래그
                       iph_offset:13; // 플래그 오프셋
    unsigned char      iph_ttl; // TTL
    unsigned char      iph_protocol; // 프로토콜 유형
    unsigned short int iph_chksum; // IP 데이터그램 체크섬
    struct  in_addr    iph_sourceip; // 출발지 IP 주소
    struct  in_addr    iph_destip;   // 목적지 IP 주소
};

/* TCP 헤더 */
struct tcpheader {
    u_short tcph_srcport; // 출발지 포트
    u_short tcph_destport; // 목적지 포트
    u_int tcph_seqnum; // 순서 번호
    u_int tcph_acknum; // 확인 번호
    u_char tcph_offset:4, tcph_reserved:4; // 데이터 오프셋, 예약
    u_char tcph_flags; // 플래그 (FIN, SYN, RST, PSH, ACK, URG)
    u_short tcph_win; // 윈도우
    u_short tcph_chksum; // 체크섬
    u_short tcph_urgptr; // 긴급 포인터
};

/* 패킷 처리 함수 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800은 IP 유형
        struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        if (ip->iph_protocol == IPPROTO_TCP) {
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + (ip->iph_ihl * 4));
            printf("\n이더넷 헤더\n");
            printf("   출발지 MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
            printf("   목적지 MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
            
            printf("\nIP 헤더\n");
            printf("   출발지 IP: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("   목적지 IP: %s\n", inet_ntoa(ip->iph_destip));
            
            printf("\nTCP 헤더\n");
            printf("   출발지 포트: %u\n", ntohs(tcp->tcph_srcport));
            printf("   목적지 포트: %u\n", ntohs(tcp->tcph_destport));
        }
    }
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    // Step 1: NIC 이름이 enp0s3인 장치에서 라이브 pcap 세션 열기
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

    // Step 2: filter_exp를 BPF 의사 코드로 컴파일
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) !=0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    // Step 3: 패킷 캡처
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);   // 핸들 닫기
    return 0;
}
