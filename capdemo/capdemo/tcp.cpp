#include "tcp.h"
#include "ether.h"
#include "ip.h"

void print_tcp_header(const u_char* packet_data) {
	std::uint32_t* null_loopback = (std::uint32_t*)packet_data;
	int offset = ((*null_loopback == 0x02) || (*null_loopback == 0x18) ? 4 : sizeof(ether2_header)) + sizeof(ip_header);
	tcp_header* tcph = (tcp_header*)(packet_data + offset);
	u_short sp = ntohs(tcph->src_port);
	u_short dp = ntohs(tcph->dst_port);

	int window = tcph->window_size;
	int flags = tcph->flags;

	printf("Դ�˿�: %6d --> Ŀ��˿�: %6d --> ���ڴ�С: %7d --> ��־: (%d)", sp, dp, window, flags);

	if (flags & 0x08) printf("PSH ���ݴ���\n");
	else if (flags & 0x10) printf("ACK ��Ӧ\n");
	else if (flags & 0x02) printf("SYN ��������\n");
	else if (flags & 0x20) printf("URG \n");
	else if (flags & 0x01) printf("FIN �ر�����\n");
	else if (flags & 0x04) printf("RST ��������\n");
	else printf("None δ֪\n");
}