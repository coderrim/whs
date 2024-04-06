#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

/* 이더넷 헤더 */
struct ethheader {
  u_char  ether_dhost[6]; /* 목적지 호스트 주소 */
  u_char  ether_shost[6]; /* 출발지 호스트 주소 */
  u_short ether_type;     /* 프로토콜 타입 (IP, ARP, RARP 등) */
};

/* IP 헤더 */
struct ipheader {
  unsigned char      iph_ihl:4, // IP 헤더 길이
                     iph_ver:4; // IP 버전
  unsigned char      iph_tos; // 서비스 유형
  unsigned short int iph_len; // IP 패킷 길이 (데이터 + 헤더)
  unsigned short int iph_ident; // 식별자
  unsigned short int iph_flag:3, // 단편화 플래그
                     iph_offset:13; // 플래그 오프셋
  unsigned char      iph_ttl; // 생존 시간
  unsigned char      iph_protocol; // 프로토콜 타입
  unsigned short int iph_chksum; // IP 데이터그램 체크섬
  struct  in_addr    iph_sourceip; // 출발지 IP 주소
  struct  in_addr    iph_destip;   // 목적지 IP 주소
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800은 IP 타입
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 

    printf("From: %s\n", inet_ntoa(ip->iph_sourceip));   
    printf("To: %s\n", inet_ntoa(ip->iph_destip));    

    /* 프로토콜 결정 */
    switch(ip->iph_protocol) {                                 
        case IPPROTO_TCP:
            printf("Protocol: TCP\n");
            return;
        case IPPROTO_UDP:
            printf("Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("Protocol: ICMP\n");
            return;
        default:
            printf("Protocol: others\n");
            return;
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

  // STEP 1: NIC 이름이 enp0s3인 NIC에서 라이브 pcap 세션 열기
  handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
      fprintf(stderr, "장치 %s 열기에 실패했습니다: %s\n", "ens33", errbuf);
      return EXIT_FAILURE;
  }

  // STEP 2: filter_exp를 BPF 가상 코드로 컴파일하기
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
      fprintf(stderr, "필터 %s를 파싱하는 데 실패했습니다: %s\n", filter_exp, pcap_geterr(handle));
      return EXIT_FAILURE;
  }
  if (pcap_setfilter(handle, &fp) == -1) {
      fprintf(stderr, "필터 %s를 설치하는 데 실패했습니다: %s\n", filter_exp, pcap_geterr(handle));
      return EXIT_FAILURE;
  }

  // STEP 3: 패킷 캡처하기
  if (pcap_loop(handle, -1, got_packet, NULL) == -1) {
      fprintf(stderr, "pcap 루프 오류: %s\n", pcap_geterr(handle));
      return EXIT_FAILURE;
  }

  pcap_close(handle);   // 핸들 닫기
  return EXIT_SUCCESS;
}
