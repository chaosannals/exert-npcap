#include <WinSock2.h>
#include <Windows.h>
#include <pcap/pcap.h>
#include <iostream>
#include "ether.h"
#include "ip.h"

void print_tcp_header() {

}

int enum_adapters() {
	pcap_if_t* all_adapters;
	int index = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &all_adapters, errbuf) != -1) {
		for (pcap_if_t* ptr = all_adapters; ptr != NULL; ptr = ptr->next) {
			if (ptr->description) {
				std::cout << "ID : " << index
					<< " Description: " << ptr->description
					<< " Name: " << ptr->name
					<< std::endl;
			}
			++index;
		}
		pcap_freealldevs(all_adapters);
	}
	return index;
}

void handle_packet(u_char* param,const pcap_pkthdr* packet_header, const u_char* packet_data) {
	std::cout << "pack len: " << packet_header->len << " " << packet_header->ts.tv_sec << "ms" << std::endl;
	ether2_header* eh = print_ether_header(packet_data);

	std::cout << std::endl;

	// 0x0800, 由于本地是小头
	if (eh->ether_type == 0x0008) {
		print_ip_header(packet_data);
	}

	// 0x0806, 由于本地是小头
	if (eh->ether_type == 0x0608) {

	}
}

void monitor_adapter(int index) {
	pcap_if_t* all_adapters;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs(&all_adapters, errbuf) != -1) {
		pcap_if_t* adapters = all_adapters;
		for (int x = 0; x < index; ++x) {
			adapters = adapters->next;
		}

		if (adapters == NULL) {
			std::cout << "err: " << errbuf << std::endl;
			return;
		}

		std::cout << "monitor: " << adapters->description << std::endl;

		pcap_t* handle = pcap_open_live(adapters->name, 65536, 1, 1000, errbuf);

		pcap_freealldevs(all_adapters);

		if (handle == nullptr) {
			std::cout << "err: " << errbuf << std::endl;
			return;
		}
		pcap_loop(handle, 0, handle_packet, NULL);
		pcap_close(handle);
	}
	else {
		std::cout << "err: " << errbuf << std::endl;
	}
}

int main(int argc, char* argv[]) {
	std::cout << "ether_header size: " << sizeof(ether2_header) << std::endl;
	std::cout << "ip_header size: " << sizeof(ip_header) << std::endl;
	int network = enum_adapters();
	int index;
	std::cout << "输入ID: ";
	std::cin >> index;
	monitor_adapter(index);
	system("pause");
	return 0;
}