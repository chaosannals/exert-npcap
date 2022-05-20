#pragma once

#include <pcap/pcap.h>
#include <cstdint>

#pragma pack(1)
// 以太网 II
struct ether2_header {
	std::uint8_t ether_dhost[6]; // 目标 MAC 地址
	std::uint8_t ether_shost[6]; // 源 MAC 地址
	std::uint16_t ether_type;	// 以太网类型
};
#pragma pack()

ether2_header* print_ether_header(const std::uint8_t* packet_data);
