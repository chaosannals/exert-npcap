#include <iostream>
#include <stdlib.h>
#include <pcap/pcap.h>
#include "IPv4Layer.h"
#include "Packet.h"
#include "PcapFileDevice.h"
#include "PcapLiveDeviceList.h"
#include "SystemUtils.h"
#include <PcapLiveDevice.h>

#pragma comment(lib, "ws2_32.lib")


int enum_adapters() {
	pcap_if_t* all_adapters;
	int index = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &all_adapters, errbuf) != -1) {
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

void handle_packet(u_char* param, const pcap_pkthdr* packet_header, const u_char* packet_data) {
	
	std::cout << "pack len: " << packet_header->len << " " << packet_header->ts.tv_usec << "ms" << std::endl;
	
	// read the first (and only) packet from the file

	pcpp::RawPacket rawPacket(packet_data, packet_header->len, packet_header->ts, false);


	// parse the raw packet into a parsed packet
	pcpp::Packet parsedPacket(&rawPacket);

	// verify the packet is IPv4
	if (parsedPacket.isPacketOfType(pcpp::IPv4))
	{
		// extract source and dest IPs
		pcpp::IPv4Address srcIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIPv4Address();
		pcpp::IPv4Address destIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIPv4Address();

		// print source and dest IPs
		std::cout << "Source IP is '" << srcIP << "'; Dest IP is '" << destIP << "'" << std::endl;
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

int main(int argc, char* argv[])
{

	//std::string interfaceIPAddr = "192.168.0.129";
	//pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIp(interfaceIPAddr);
	//if (dev == NULL)
	//{
	//	std::cerr << "Cannot find interface with IPv4 address of '" << interfaceIPAddr << "'" << std::endl;
	//	return 1;
	//}

	//// Get device info
	//// ~~~~~~~~~~~~~~~

	//// before capturing packets let's print some info about this interface
	//std::cout
	//	<< "Interface info:" << std::endl
	//	<< "   Interface name:        " << dev->getName() << std::endl // get interface name
	//	<< "   Interface description: " << dev->getDesc() << std::endl // get interface description
	//	<< "   MAC address:           " << dev->getMacAddress() << std::endl // get interface MAC address
	//	<< "   Default gateway:       " << dev->getDefaultGateway() << std::endl // get default gateway
	//	<< "   Interface MTU:         " << dev->getMtu() << std::endl; // get interface MTU


	//// open the device before start capturing/sending packets
	//if (!dev->open())
	//{
	//	std::cerr << "Cannot open device" << std::endl;
	//	return 1;
	//}



	int network = enum_adapters();
	int index;
	std::cout << "输入ID: ";
	std::cin >> index;
	monitor_adapter(index);
	system("pause");
	return 0;
}