#pragma once
#include <stdio.h>
#include <stdint.h>
#include "protocol/all.h"

void printPacket(const unsigned char *p, uint32_t size);

void printTCPPort(uint16_t port);

void printMACAddress(mac_addr mac);

void printIPAddress(ip_addr ipAddr);