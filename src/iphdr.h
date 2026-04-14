#pragma once

#include <cstdint>

#pragma pack(push, 1)
typedef struct ipv4_header_t {
	uint8_t ver_ihl;
	uint8_t tos;
	uint16_t total_length;
	uint16_t identification;
	uint16_t flags_fragment;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t header_checksum;
	uint32_t src_ip;
	uint32_t dest_ip;
} ipv4_header_t;
#pragma pack(pop)
