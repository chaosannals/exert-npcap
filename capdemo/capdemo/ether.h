#pragma once

#include <pcap/pcap.h>
#include <cstdint>

#pragma pack(1)
// ��̫�� II
struct ether2_header {
	std::uint8_t ether_dhost[6]; // Ŀ�� MAC ��ַ
	std::uint8_t ether_shost[6]; // Դ MAC ��ַ
	std::uint16_t ether_type;	// ��̫������
};
#pragma pack()

ether2_header* print_ether_header(const std::uint8_t* packet_data);
