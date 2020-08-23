#!/bin/bash

make PTHREAD=1 TCP=1 UDP=1 VDE=1 \
	RTOS=0 \
	DHCP_CLIENT=0 \
	DHCP_SERVER=0 \
	DNS_CLIENT=0 \
    PPP=0 \
	MDNS=0 \
	DNS_SD=0 \
	SNTP_CLIENT=0 \
	IPFILTER=1 \
	CRC=1 \
	OLSR=0 \
	SLAACV4=0 \
	TFTP=0 \
	AODV=0 \
	MEMORY_MANAGER=0 \
	MEMORY_MANAGER_PROFILING=0 \
	TUN=1 \
	TAP=1 \
	PCAP=0 \
	IEEE802154=0 \
	IPC=0 \
	CYASSL=0 \
	WOLFSSL=0 \
	POLARSSL=0 \
	TICKLESS=0 \
	RAW=1 \
    PACKET_SOCKET=1 \
    6LOWPAN=0 \
    PLATFORM_CFLAGS="-fPIC -shared"

gcc -shared -Wl,-soname,libpicotcp.so.${SONAME} -o build/lib/libpicotcp.so build/modules/*.o build/lib/*.o -lvdeplug -pthread
