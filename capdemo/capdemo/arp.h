#pragma once

#include <pcap/pcap.h>

#pragma pack(1)
struct arp_header {
	u_short hd_type;    // Ӳ������
	u_short pro_type;   // Э������
	u_char hd_size;     // Ӳ����ַ����
	u_char pro_size;    // Э���ַ����
	u_short op;        // �������ͣ�ARP����1����ARPӦ��2����RARP����3����RARPӦ��4����
	u_char smac[6];           // ԴMAC��ַ
	u_char sip[4];            // ԴIP��ַ
	u_char dmac[6];           // Ŀ��MAC��ַ
	u_char dip[4];            // Ŀ��IP��ַ
};
#pragma pack()

void print_arp_header(const u_char* packet_data);
