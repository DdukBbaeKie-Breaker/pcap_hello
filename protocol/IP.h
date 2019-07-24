#pragma once
#include <stdint.h>

#define ARPHRD_ETHER 1
#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2
#define ARPOP_RREQUEST 3
#define ARPOP_RREPLY 4
#define ARPOP_InREQUEST 8
#define ARPOP_InREPLY 9
#define ARPOP_NAK 10
#define ARPPRO_IPV4 0x0800
#define IPV4_LENGRH 4
#define IP_RE 0x80000
#define IP_DF 0x40000
#define IP_MF 0x20000
#define IP_OFFMASK 0x1fff


struct ip_addr
{
	uint8_t a;
	uint8_t b;
	uint8_t c;
	uint8_t d;
};

struct ip_header
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint32_t ip_hl : 4;
	uint32_t ip_v : 4;
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
	uint32_t ip_v : 4;
	uint32_t ip_hl : 4;
#endif
	uint8_t ip_tos;
	uint16_t ip_len;
	uint16_t ip_id;
	uint16_t ip_off;

	uint8_t ip_ttl;
	uint8_t ip_p;
	uint16_t ip_sum;
	ip_addr ip_src;
	ip_addr ip_dst;
};