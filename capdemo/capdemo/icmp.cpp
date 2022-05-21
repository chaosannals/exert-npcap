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
		printf("����ʱ���: %d --> ����ʱ���: %d --> ����ʱ���: %d ����: ",
			init_time, send_time, recv_time);

		switch (type)
		{
		case 0: printf("����Ӧ���� \n"); break;
		case 8: printf("���������� \n"); break;
		default:break;
		}
	}
}