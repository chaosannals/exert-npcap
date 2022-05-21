#pragma once

#include <pcap/pcap.h>

#pragma pack(1)
struct icmp_header {
	u_char type;        // ICMP类型
	uint8_t code;        // 代码
	uint16_t checksum;   // 校验和

	// 下面的数据不同类型不同，TODO 查
	uint16_t identification; // 标识
	uint16_t sequence;       // 序列号
	uint32_t init_time;      // 发起时间戳
	uint16_t recv_time;      // 接受时间戳
	uint16_t send_time;      // 传输时间戳
};
#pragma pack()

void print_icmp_header(const u_char* packet_data);
