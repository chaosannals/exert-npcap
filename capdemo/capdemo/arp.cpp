#include "arp.h"
#include "ether.h"

void print_arp_header(const u_char* packet_data) {
	u_int* null_loopback = (u_int*)packet_data;
	int offset = ((*null_loopback == 0x02) || (*null_loopback == 0x18) ? 4 : sizeof(ether2_header));
	arp_header* arph = (arp_header*)(packet_data + offset);

}