/**********************************************************\
 *               -== Xif Network project ==-
 *                      ioslaves-master
 *          Wake On Lan/Wan sender implementation
 * *********************************************************
 * Copyright © Félix Faisant 2015. All rights reserved
 * This software is under the GNU General Public License
 \**********************************************************/

	// Common
#include "common.hpp"
#include "master.hpp"

	// Net/sys
#include <net/ethernet.h>
#define MAGIC_HEADER 6
#define MAGIC_MAC_TIMES 16
#define MACSTR_LEN 17
#ifdef __linux__
	#define octet ether_addr_octet
#endif

void ioslaves::wol::magic_send (const char* mac_addr, bool wan, in_addr_t ip, in_port_t port) {
	int r;
	
		// Parse MAC addr
	struct ether_addr mac = {{0}};
	
	for (size_t i = 0; mac_addr[i] != '\0'; i++) {
		char c = mac_addr[i];
		if (i%3 <= 1) mac.octet[i/3] += 
			(u_char)((c >='0' and c <='9')? c-'0' : 
						((c >='A' and c <='F')? c-'A'+0xA : 
						 ((c >='a' and c <='f')? c-'a'+0xA : 
						  throw std::runtime_error("wol: mac addr: bad format")) )
						) << (!(i%3))*4;
		if (i%3 == 2 and c != ':') 
			throw std::runtime_error("wol: mac addr: bad format");
	}
	
		// Fill packet
	uint8_t* pkt = new uint8_t[MAGIC_HEADER+ETHER_ADDR_LEN*MAGIC_MAC_TIMES];
	RAII_AT_END_N(pkt, {
		delete[] pkt;
	});
	
	::memset(pkt, 0xFF, MAGIC_HEADER);
	for (uint8_t i = 0; i < MAGIC_MAC_TIMES; i++)
		for (uint8_t j = 0; j < ETHER_ADDR_LEN; j++)
			pkt[MAGIC_HEADER+i*ETHER_ADDR_LEN+j] = mac.octet[j];
	
		// Create socket and set in broadcast mode
	fd_t udps = ::socket(PF_INET, SOCK_DGRAM, 0);
	if (udps == -1)
		throw xif::sys_error("wol: can't create udp sock");
	RAII_AT_END_N(sock, {
		::close(udps);
	});
	
	if (not wan) {
		int opt = 1;
		r = ::setsockopt(udps, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(int));
		if (r == -1)
			throw xif::sys_error("wol: can't set broadcast opt");
	}
	
		// Send address
	if (not wan) {
		port = 9;
		ip = "255.255.255.255"_IP.s_addr;
	}
	struct sockaddr_in sendaddr = {
		.sin_family = AF_INET, 
		.sin_port = htons(port), 
		.sin_addr = {ip}
	};
	
		// Send
	ssize_t rs = ::sendto(udps, pkt, MAGIC_HEADER+ETHER_ADDR_LEN*MAGIC_MAC_TIMES, 0,
								 (const sockaddr*)&sendaddr, sizeof (sockaddr_in));
	if (rs <= 0)
		throw xif::sys_error("wol: can't send magic packet");
}
