#include "icmp.h"
#include "ether.h"
#include "ip.h"

void print_icmp_header(const u_char* packet_data) {
	u_int* null_loopback = (u_int*)packet_data;
	int offset = ((*null_loopback == 0x02) || (*null_loopback == 0x18) ? 4 : sizeof(ether2_header)) + sizeof(ip_header);
	icmp_header* icmph = (icmp_header*)(packet_data + offset);

	int type = icmph->type;
	int init_time = icmph->init_time;
	int send_time = icmph->send_time;
	int recv_time = icmph->recv_time;
	if (type == 8)
	{
		printf("发起时间戳: %d --> 传输时间戳: %d --> 接收时间戳: %d 方向: ",
			init_time, send_time, recv_time);

		switch (type)
		{
		case 0: printf("回显应答报文 \n"); break;
		case 8: printf("回显请求报文 \n"); break;
		default:break;
		}
	}
}