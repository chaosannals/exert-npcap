#pragma once
#include <pcap/pcap.h>

#pragma pack(1)
struct tcp_header {
	u_short src_port;
	u_short dst_port;
	u_int sequ_num;
	u_int ack_num;
	u_char reserved : 4, offset: 4;
	u_char flags;
	u_short window_size;
	u_short check_sum;
	u_short surgent_offset;
};
#pragma pack()

void print_tcp_header(const u_char* packet_data);
