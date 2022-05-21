#include "udp.h"
#include "ether.h"
#include "ip.h"

void print_udp_header(const u_char* packet_data) {
	u_int* null_loopback = (u_int*)packet_data;
	int offset = ((*null_loopback == 0x02) || (*null_loopback == 0x18) ? 4 : sizeof(ether2_header)) + sizeof(ip_header);
	udp_header* udph = (udp_header*)(packet_data + offset);
	u_short sport = ntohs(udph->sport);
	u_short dport = ntohs(udph->dport);
	u_short datalen = ntohs(udph->len);

	printf("Դ�˿�: %5d --> Ŀ��˿�: %5d --> ��С: %5d \n", sport, dport, datalen);
}