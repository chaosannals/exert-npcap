#pragma once

#include <pcap/pcap.h>

#pragma pack(1)
struct icmp_header {
	u_char type;        // ICMP����
	uint8_t code;        // ����
	uint16_t checksum;   // У���

	// ��������ݲ�ͬ���Ͳ�ͬ��TODO ��
	uint16_t identification; // ��ʶ
	uint16_t sequence;       // ���к�
	uint32_t init_time;      // ����ʱ���
	uint16_t recv_time;      // ����ʱ���
	uint16_t send_time;      // ����ʱ���
};
#pragma pack()

void print_icmp_header(const u_char* packet_data);
