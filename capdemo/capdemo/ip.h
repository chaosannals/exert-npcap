#pragma once

#include <cstdint>

#pragma pack(1)
struct ip_header {
	std::uint8_t version : 4;
	std::uint8_t header_length : 4;
	std::uint8_t type_of_service;
	std::uint16_t totla_length;
	std::uint16_t identification;
	std::uint16_t flags_offset;
	std::uint8_t tiem_to_live;
	std::uint8_t protocol;
	std::uint16_t check_sum;
	std::uint32_t src_addr;
	std::uint32_t dst_addr;
};
#pragma pack()

void print_ip_header(const std::uint8_t* packet_data);
