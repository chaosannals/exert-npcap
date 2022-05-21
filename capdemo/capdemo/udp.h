#pragma once
#include <pcap/pcap.h>

#pragma pack(1)
struct udp_header {
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
};
#pragma pack()

void print_udp_header(const u_char* packet_data);
