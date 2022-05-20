#include <WinSock2.h>
#include <Windows.h>
#include <pcap/pcap.h>
#include <iostream>

#pragma pack(1)
struct ether_header {
	u_char ether_dhost[6]; // 目标 MAC 地址
	u_char ether_shost[6]; // 源 MAC 地址
	u_short ether_type;	// 以太网类型
};

struct ip_header {
	char version : 4;
	char header_length : 4;
	char type_of_service;
	u_short totla_length;
	u_short identification;
	u_short flags_offset;
	char tiem_to_live;
	char protocol;
	u_short check_sum;
	u_int src_addr;
	u_int dst_addr;
};
#pragma pack()

void print_ether_header(const u_char* packet_data) {
	ether_header *eh = (ether_header*)(packet_data);
	printf("类型： 0x%x \t", eh->ether_type);
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
}

void print_ip_header(const u_char* packet_data) {
	ip_header* iph = (ip_header*)(packet_data + sizeof(ether_header));
	/*SOCKADDR_IN src_addr, dst_addr;
	src_addr.sin_addr.s_addr = iph->src_addr;
	dst_addr.sin_addr.s_addr = iph->dst_addr;*/
	u_short check_sum = ntohs(iph->check_sum);
	char src_ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET,&iph->src_addr, src_ip, sizeof(src_ip));
	char dst_ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &iph->dst_addr, dst_ip, sizeof(dst_ip));
	std::cout << "源地址： " << src_ip << " ";
	std::cout << "目标地址：" << dst_ip << " ";
	printf("校验和： %5X --> TTL: %4d ", check_sum, iph->tiem_to_live);
	switch (iph->protocol) {
	case 1:
		std::cout << "ICMP ";
		break;
	case 2:
		std::cout << "IGMP ";
		break;
	case 6:
		std::cout << "TCP ";
		break;
	case 17:
		std::cout << "UDP ";
		break;
	case 89:
		std::cout << "OSPF ";
		break;
	default:
		std::cout << "Unknown: " << (int)iph->protocol << " ";
		break;
	}
	std::cout << std::endl;
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
	}
	return index;
}

void monitor_adapter(int index) {
	pcap_if_t* adapters;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &adapters, errbuf) != -1) {
		for (int x = 0; x < index; ++x) {
			adapters = adapters->next;
		}

		std::cout << "monitor: " << adapters->description << std::endl;

		pcap_t* handle = pcap_open(adapters->name, 65534, 1, PCAP_OPENFLAG_PROMISCUOUS, NULL, errbuf);

		if (adapters == NULL) {
			std::cout << "err: " << errbuf << std::endl;
			return;
		}

		pcap_pkthdr* packet_header;
		const u_char* packet_data;
		int ret_value = 0;
		while ((ret_value = pcap_next_ex(handle, &packet_header, &packet_data)) >= 0) {
			if (ret_value == 0) {
				continue;
			}
			std::cout << "pack len: " << packet_header->len << " " << packet_header->ts.tv_usec << "ms" << std::endl;
			print_ether_header(packet_data);
			std::cout << std::endl;
			print_ip_header(packet_data);
		}
	}
	else {
		std::cout << "err: " << errbuf << std::endl;
	}
}

int main(int argc, char* argv[]) {
	std::cout << "ether_header size: " << sizeof(ether_header) << std::endl;
	std::cout << "ip_header size: " << sizeof(ip_header) << std::endl;
	int network = enum_adapters();
	int index;
	std::cout << "输入ID: ";
	std::cin >> index;
	monitor_adapter(index);
	system("pause");
	return 0;
}