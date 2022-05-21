#include "ip.h"
#include "ether.h"
#include "tcp.h"
#include "udp.h"
#include "icmp.h"
#include <iostream>

void print_ip_header(const std::uint8_t* packet_data) {
	std::uint32_t *null_loopback = (std::uint32_t *)packet_data;
	std::cout << "null loopback: " << *null_loopback << std::endl;
	int offset = (* null_loopback == 0x02) || (*null_loopback == 0x18) ? 4 : sizeof(ether2_header);
	ip_header* iph = (ip_header*)(packet_data + offset);
	//ip_header* iph = (ip_header*)(packet_data + 4); // NULL LOOPBACK
	//ip_header* iph = (ip_header*)(packet_data + sizeof(ether2_header)); // ��̫�� II
	std::uint16_t check_sum = ntohs(iph->check_sum);
	char src_ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &iph->src_addr, src_ip, sizeof(src_ip));
	char dst_ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &iph->dst_addr, dst_ip, sizeof(dst_ip));
	std::cout << "Դ��ַ�� " << src_ip << " ";
	std::cout << "Ŀ���ַ��" << dst_ip << " ";
	printf("У��ͣ� %5X --> TTL: %4d ", check_sum, iph->tiem_to_live);
	switch (iph->protocol) {
	case 1:
		std::cout << "ICMP " << std::endl;
		print_icmp_header(packet_data);
		break;
	case 2:
		std::cout << "IGMP " << std::endl;
		break;
	case 6:
		std::cout << "TCP: " << std::endl;
		print_tcp_header(packet_data);
		break;
	case 17:
		std::cout << "UDP " << std::endl;
		print_udp_header(packet_data);
		break;
	case 89:
		std::cout << "OSPF " << std::endl;
		break;
	default:
		std::cout << "Unknown: " << (int)iph->protocol << std::endl;
		break;
	}
	std::cout << std::endl;
}