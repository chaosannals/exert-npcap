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

	printf("源端口: %6d --> 目标端口: %6d --> 窗口大小: %7d --> 标志: (%d)", sp, dp, window, flags);

	if (flags & 0x08) printf("PSH 数据传输\n");
	else if (flags & 0x10) printf("ACK 响应\n");
	else if (flags & 0x02) printf("SYN 建立连接\n");
	else if (flags & 0x20) printf("URG \n");
	else if (flags & 0x01) printf("FIN 关闭连接\n");
	else if (flags & 0x04) printf("RST 连接重置\n");
	else printf("None 未知\n");
}