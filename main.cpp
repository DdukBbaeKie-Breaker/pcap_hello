#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "packet.h"
#include "protocol/all.h"

void usage(){
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcapether_heade_test wlan0\n");
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
	if (handle == NULL) {
		fprintf(stderr,"couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}
	while (true) {
		int packetIndex = 0;
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;

		const ether_header *eth = (ether_header *)packet;
		packetIndex += sizeof(ether_header);

		printMACAddress(eth->src);
		printMACAddress(eth->dst);
		if (ntohs(eth->ether_type)==ETHERTYPE_ARP) {
			printf("ARP\n");

			const arp_header *ip = (arp_header *)(packet + sizeof(ether_header));
			packetIndex += sizeof(arp_header);
			printMACAddress(eth->dst);


		}
		else if (ntohs(eth->ether_type)==ETHERTYPE_IP) {
			printf("IPv4\n");
			const ip_header *ip = (ip_header *)(packet + sizeof(ether_header));
			packetIndex += sizeof(ip_header);
			printf("%d.%d.%d.%d\n", ip->ip_src.a, ip->ip_src.b, ip->ip_src.c, ip->ip_src.d);
			printf("%d.%d.%d.%d\n", ip->ip_dst.a, ip->ip_dst.b, ip->ip_dst.c, ip->ip_dst.d);
			printf("\n");
			if(ip->ip_p == IPPROTO_TCP){
				const tcp_header *tcp = (tcp_header *)(packet + packetIndex);
				packetIndex += sizeof(tcp_header);
	                	printf("TCP SRC PORT : ");
        	        	printTCPPort(ntohs(tcp->th_sport));
                		printf("\n");
                		printf("TCP DEST PORT : ");
                		printTCPPort(ntohs(tcp->th_dport));
                		printf("\n");


                		uint32_t tcp_size = (ntohs(ip->ip_len) - ((ip->ip_hl + tcp->th_off)*4));

                		if(tcp_size > 0)
                		{
                        		printf("--------------------\n");
                        		printPacket(packet + packetIndex, tcp_size);
                        		printf("--------------------\n");
                		}
			}
			else if (ip->ip_p == 17)
			{
				const udp_header *udp = (udp_header *)(packet + sizeof(ether_header) + sizeof(ip_header));

				packetIndex += sizeof(udp_header);

				printf("udp src: %d\n", ntohs(udp->src));
				printf("udp drc: %d\n", ntohs(udp->dst));

				uint32_t udp_size = (ntohs(ip->ip_len) - sizeof(udp_header));

                		if(udp_size > 0)
                		{
                        		printf("--------------------\n");
                        		printPacket(packet + packetIndex, udp_size);
                        		printf("--------------------\n");
                		}

			}

		}
		else if (ntohs(eth->ether_type)==ETHERTYPE_IPV6) {
			printf("IPv6\n");
		}

	}
	pcap_close(handle);
	return 0;
}
