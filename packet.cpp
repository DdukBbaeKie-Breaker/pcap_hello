#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include "protocol/all.h"
#include "packet.h"

void printTCPPort(uint16_t port){
	printf("%d",port);
}

void printPacket(const unsigned char *p, uint32_t size)
{
	int len;
	for (len = 0; len < size; )
	{
		printf("%02X ", p[len]);
		if(!(++len % 16))
		{
			printf("\n");
		}
	}
	if(size % 16) {
		printf("\n");
	}
    printf("--------------------\n");
	for (len = 0; len < size; )
	{
		printf("%c", p[len] >= 32 && p[len] <= 126 ? p[len] : '.');
		if(!(++len % 16))
		{
			printf("\n");
		}
	}
	if(size % 16) {
		printf("\n");
	}
}

void printMACAddress(mac_addr mac)
{
	printf("%02X:%02X:%02X:%02X:%02X:%02X:", mac.oui[0], mac.oui[1], mac.oui[2], mac.oui[0], mac.oui[1], mac.oui[2]);
}

void printIPAddress(ip_addr ipAddr){
	printf("%d %d %d %d",ipAddr.a, ipAddr.b, ipAddr.c, ipAddr.d);
}
