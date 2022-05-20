#include "ether.h"
#include <iostream>

#define hcons(A) (((WORD)(A)&0xFF00)>>8) | (((WORD)(A)&0x00FF)<<8)

ether2_header* print_ether_header(const std::uint8_t* packet_data) {
	ether2_header* eh = (ether2_header*)(packet_data);
	printf("类型： 0x%x \t", hcons(eh->ether_type));
	printf("原 MAC 地址： %02X:%02X:%02X:%02X:%02X:%02X \t"
		, eh->ether_shost[0]
		, eh->ether_shost[1]
		, eh->ether_shost[2]
		, eh->ether_shost[3]
		, eh->ether_shost[4]
		, eh->ether_shost[5]);
	printf("目标 MAC 地址： %02X:%02X:%02X:%02X:%02X:%02X"
		, eh->ether_dhost[0]
		, eh->ether_dhost[1]
		, eh->ether_dhost[2]
		, eh->ether_dhost[3]
		, eh->ether_dhost[4]
		, eh->ether_dhost[5]);
	return eh;
}