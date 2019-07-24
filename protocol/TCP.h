#pragma once
#include <stdint.h>

typedef uint32_t tcp_seq; 
struct tcp_header
{
	__extension__ union
	{
	  struct
		{
			uint16_t th_sport;
			uint16_t th_dport;
			tcp_seq th_seq;
			tcp_seq th_ack;
		#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t th_2x:4;
			uint8_t th_off:4;
		#endif
		#if __BYTE_ORDER == __BIG_ENDIAN
			uint8_t th_off:4;
			uint8_t th_x2:4;
		#endif
			uint8_t th_flags;
#define TH_FIN 0x01
#define TH_SYN 0X02
#define TH_RST 0X04
#define TH_PUSH 0X08
#define TH_ACK 0X10
#define TH_URG 0X20
	uint16_t th_win;
	uint16_t th_sum;
	uint16_t th_urp;
		};
struct
{
	uint16_t source;
	uint16_t dest;
	uint32_t seq;
	uint32_t ack_seq;
#if __BYTE_ORDER == __LITTE_ENDIAN
	uint16_t resl:4;
	uint16_t doff:4;
	uint16_t fin:1;
	uint16_t syn:1;
	uint16_t rst:1;void printIPAddress(ip_addr ipAddr){
	printf("%d %d %d %d",ipAddr.a, ipAddr.b, ipAddr.c, ipAddr.d);
}

	uint16_t psh:1;
	uint16_t ack:1;
	uint16_t urg:1;
	uint16_t res2:2;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint16_t doff:4;
	uint16_t resl:4;
	uint16_t res2:2;
	uint16_t urg:1;
	uint16_t ack:1;
	uint16_t psh:1;
	uint16_t rst:1;
	uint16_t syn:1;
	uint16_t fin:1;
#else
#endif
	uint16_t window;
	uint16_t check;
	uint16_t urg_ptr;
		};
	};
};

