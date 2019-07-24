#pragma once
#include <stdint.h>

struct udp_header
{
	uint16_t src;
        uint16_t dst;
        uint16_t len;
        uint16_t check;

	#ifndef _UAPI_LINUX_UDP_H
	#define _UAPI_LINUX_UDP_H

	#define UDP_CORK	1	
	#define UDP_ENCAP	100	
	#define UDP_NO_CHECK6_TX 101	
	#define UDP_NO_CHECK6_RX 102	
	#define UDP_SEGMENT	103	
	#define UDP_GRO		104	

	#define UDP_ENCAP_ESPINUDP_NON_IKE	1 
	#define UDP_ENCAP_ESPINUDP	2 
	#define UDP_ENCAP_L2TPINUDP	3 
	#define UDP_ENCAP_GTP0		4 
	#define UDP_ENCAP_GTP1U		5 
	#define UDP_ENCAP_RXRPC		6
	#endif
};