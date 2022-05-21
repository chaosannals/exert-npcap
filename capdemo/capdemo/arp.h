#pragma once

#include <pcap/pcap.h>

#pragma pack(1)
struct arp_header {
	u_short hd_type;    // 硬件类型
	u_short pro_type;   // 协议类型
	u_char hd_size;     // 硬件地址长度
	u_char pro_size;    // 协议地址长度
	u_short op;        // 操作类型，ARP请求（1），ARP应答（2），RARP请求（3），RARP应答（4）。
	u_char smac[6];           // 源MAC地址
	u_char sip[4];            // 源IP地址
	u_char dmac[6];           // 目的MAC地址
	u_char dip[4];            // 目的IP地址
};
#pragma pack()

void print_arp_header(const u_char* packet_data);
