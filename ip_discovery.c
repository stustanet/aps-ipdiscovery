#define __USE_BSD

#include <time.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct ether_header ether_header;
typedef struct ether_arp ether_arp;
typedef struct ip ip;
typedef struct icmphdr icmphdr;

/* BEWARE: The eth1 interface has to be up for this to work */

/* Checksum function */
uint16_t checksum(uint16_t *addr, int len) {
	int nleft = len;
	int sum = 0;
	uint16_t *w = addr;
	uint16_t answer = 0;
	while(nleft > 1) {
		sum += *w++;
		nleft -= sizeof(uint16_t);
	}
	if(nleft == 1) {
		*(uint8_t*)(&answer) = *(uint8_t*)w;
		sum += answer;
	}
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	return ~sum;
}

int main(int argc, char* argv[]) {
	int sock;
	int i, j;
	time_t start;
	uint8_t subnet_id = 0;
	uint8_t dorm_id = 0;
	uint8_t ether_frame[ETH_FRAME_LEN];
	ether_header* eth_header = (ether_header*)ether_frame;
	ether_arp* arp_header = (ether_arp*)(ether_frame +
	    sizeof(ether_header));
	ip* ip_header = (ip*)(ether_frame + sizeof(ether_header));
	icmphdr* icmp_header = (icmphdr*)(ether_frame + sizeof(ether_header) +
	    sizeof(ip));
	uint8_t* icmp_payload = (uint8_t*)(ether_frame + sizeof(ether_header) +
	    sizeof(ip) + sizeof(icmphdr));
	char* payload_data = "Get on your knees to honor the StuStaNet "
	    "analdildos entrance!!!!";
	int payload_len = strlen(payload_data);
	int ifindex = 0;
	struct ifreq ifr;
	struct sockaddr_ll socket_address;
	uint8_t src_mac[ETH_ALEN];
	uint8_t dst_mac[ETH_ALEN];
	uint8_t sw_mac[ETH_ALEN];
	uint8_t radv_mac[ETH_ALEN];
	    /* MAC from StuSta GW we see */
	uint8_t src_ip[4] = {10, 150, 0, 240};
	uint8_t src_radv[4] = {0, 0, 0, 0};
	uint8_t sw_ip[4] = {10, 150, 0, 254};

	/* Open raw socket (needs root) to listen for arp */
	if((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		perror("socket() failed");
		return EXIT_FAILURE;
	}

	/*
	 * TODO
	 * bind socket to interface mentioned in
	 * /etc/config/ip_discovery or via flag
	 */

	/*
	 * Step 1: Get the subnet id from the first received ARP packet.
	 * NEW: We listen for ICMP Router advertisements!
	 * We listen passively on all interfaces (only the upstream eth1 port
	 * should be up to ensure, we only get meaningful ARPs. From the first
	 * received ARP packet we take the subnet id x and from there on assume
	 * we are operating in 10.150.x.0
	 */

	do {
		memset(ether_frame, 0, ETH_FRAME_LEN);
		if(recv(sock, ether_frame, ETH_FRAME_LEN, 0) == -1) {
			if(errno == EINTR) {
				continue;
			} else {
				perror("recv() failed");
				goto fail;
			}
		}
	} while(!(ntohs(eth_header->ether_type) == ETHERTYPE_IP &&
		ip_header->ip_p == IPPROTO_ICMP &&
		icmp_header->type == ICMP_ROUTERADVERT));

	memcpy(src_radv,&(ip_header->ip_src), 4);
	memcpy(radv_mac, eth_header->ether_shost, ETH_ALEN);
	fprintf(stderr, "Got ICMP-RADV from: "
	    "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX\n", radv_mac[0],
	    radv_mac[1], radv_mac[2], radv_mac[3], radv_mac[4], radv_mac[5]);

	/*
	 * TODO: What do we do, when the sender is wrong?
	 * Abort, Retry, Proactive DOS on attacker ;)
	 */
	dorm_id = src_radv[1];
	subnet_id = src_radv[2];
	fprintf(stderr, "Got ICMP-RADV from %hhu.%hhu.%hhu.%hhu assuming "
	    "%hhu.%hhu.%hhu.0/24 subnet.\n", src_radv[0], src_radv[1],
	    src_radv[2], src_radv[3], src_radv[0], dorm_id, subnet_id);

	/*
	 * StuSta and MB67 have different Gateways
	 * check for non StuSta and change GW
	 */
	if ((dorm_id != 150) || (subnet_id > 127))
		sw_ip[3] = 1;


	/* Step 2: Get the next gateways MAC address.
	 * We send an ARP from 10.150.x.240 to the gateway at 10.150.x.254
	 * to get it's MAC. The ARP-caches of all neighbours from 10.150.x.0
	 * get a wrong entry for 10.150.x.240, but this address is not used
	 * and Wolfi approved using it.
	 */
	memset(ether_frame, 0, ETH_FRAME_LEN);
	src_ip[2] = sw_ip[2] = subnet_id;
	src_ip[1] = sw_ip[1] = dorm_id;
	src_ip[0] = sw_ip[0] = src_radv[0];

	/* retrieve ethernet interface index */
	strncpy(ifr.ifr_name, "eth1", IFNAMSIZ); /* XXX read from flag */
	if(ioctl(sock, SIOCGIFINDEX, &ifr) == -1) {
		perror("SIOCGIFINDEX");
		goto fail;
	}
	ifindex = ifr.ifr_ifindex;
	fprintf(stderr, "Own interface index: %i\n", ifindex);

	/* retrieve corresponding MAC */
	if(ioctl(sock, SIOCGIFHWADDR, &ifr) == -1) {
		perror("SIOCGIFHWADDR");
		goto fail;
	}
	memcpy(src_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	memset(dst_mac, 0xFF, ETH_ALEN);
	fprintf(stderr, "Own MAC address: "
	    "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX\n", src_mac[0],
	    src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);

	/* prepare sockaddr_ll */
	socket_address.sll_family = AF_PACKET;
	socket_address.sll_protocol = htons(ETH_P_IP);
	socket_address.sll_ifindex = ifindex;
	socket_address.sll_hatype = ARPHRD_ETHER;
	socket_address.sll_pkttype = PACKET_OTHERHOST;
	socket_address.sll_halen = ETH_ALEN;
	memcpy(socket_address.sll_addr, dst_mac, ETH_ALEN);
	socket_address.sll_addr[6] = 0x00;
	socket_address.sll_addr[7] = 0x00;

	/* fill ethernet header */
	memcpy(eth_header->ether_shost, src_mac, ETH_ALEN);
	memcpy(eth_header->ether_dhost, dst_mac, ETH_ALEN);
	eth_header->ether_type = htons(ETHERTYPE_ARP);

	/* fill ARP header */
	arp_header->arp_hrd = htons(ARPHRD_ETHER);
	arp_header->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
	arp_header->ea_hdr.ar_hln = ETH_ALEN;
	arp_header->ea_hdr.ar_pln = 4;
	arp_header->ea_hdr.ar_op = htons(ARPOP_REQUEST);
	memcpy(arp_header->arp_tha, dst_mac, ETH_ALEN);
	memcpy(arp_header->arp_tpa, sw_ip, 4);
	memcpy(arp_header->arp_sha, src_mac, ETH_ALEN);
	memcpy(arp_header->arp_spa, src_ip, 4);

	/*
	 * finally send our manually crafted, black-magic
	 * containing ARP request
	 */
	if(sendto(sock, ether_frame, 60, 0,
	    (const struct sockaddr*)&socket_address,
	    sizeof(socket_address)) == -1) {
		perror("sendto() failed");
		goto fail;
	}
	fprintf(stderr, "Sent ARP request to gateway, waiting for reply...\n");

	/* Get the gateways MAC address from its ARP reply */
	do {
		memset(ether_frame, 0, ETH_FRAME_LEN);
		if(recv(sock, ether_frame, ETH_FRAME_LEN, 0) == -1) {
			if(errno == EINTR) {
				continue;
			} else {
				perror("recv() failed");
				goto fail;
			}
		}
	} while(ntohs(eth_header->ether_type) != ETHERTYPE_ARP ||
	     ntohs(arp_header->ea_hdr.ar_op) != ARPOP_REPLY ||
	     memcmp(arp_header->arp_spa, sw_ip, 4) != 0);

	memcpy(sw_mac, arp_header->arp_sha, ETH_ALEN);
	fprintf(stderr, "Got ARP reply from gateway at "
	    "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX\n", sw_mac[0],
	    sw_mac[1], sw_mac[2], sw_mac[3], sw_mac[4], sw_mac[5]);

	/*
	 * Step 3: send a ping from each valid /29 to determine the right one.
	 * The switch will only pass IP packets with the correct source IP
	 * through to the gateway. Therefore we can identify the correct /29
	 * subnet with the one reply, we should get.
	 */
	memset(ether_frame, 0, ETH_FRAME_LEN);

	/* fill icmp payload */
	memcpy(icmp_payload, payload_data, payload_len);

	/* fill icmp header */
	icmp_header->type = ICMP_ECHO;
	icmp_header->code = 0;

	/* fill ip header */
	ip_header->ip_hl = sizeof(ip) / sizeof(uint32_t);
	ip_header->ip_v = 4;
	ip_header->ip_tos = 0;
	ip_header->ip_len = htons(sizeof(ip) + sizeof(icmphdr) +
	    payload_len);
	ip_header->ip_off = 0;
	ip_header->ip_ttl = 255;
	ip_header->ip_p = IPPROTO_ICMP;
	memcpy(&(ip_header->ip_dst), sw_ip, 4);

	/* fill ethernet header */
	memcpy(eth_header->ether_shost, src_mac, ETH_ALEN);
	memcpy(eth_header->ether_dhost, sw_mac, ETH_ALEN);
	eth_header->ether_type = htons(ETH_P_IP);

	/* fix socket_address content */
	memcpy(socket_address.sll_addr, sw_mac, ETH_ALEN);

	/* generate 29 icmp echo requests */
	srand(time(NULL)); /* consider getrandom(2) */
	for(i = 0; i < 8; i++) {
		for(j = 0; j < 29; j++) {
			/* fill icmp header */
			icmp_header->un.echo.id = rand() & 0xFFFF;
			icmp_header->un.echo.sequence = rand() & 0xFFFF;
			memset(&(icmp_header->checksum), 0, 2);
			icmp_header->checksum = checksum((uint16_t*)icmp_header,
			    payload_len + sizeof(icmphdr));

			/* fill ip header */
			ip_header->ip_id = rand() & 0xFFFF;
			src_ip[3] = 8 + i + 8 * j;
			memcpy(&(ip_header->ip_src), src_ip, 4);
			memset(&(ip_header->ip_sum), 0, 2);
			ip_header->ip_sum = checksum((uint16_t*)ip_header,
			    sizeof(ip));

			/* send our carefully crafted ping packet */
			if(sendto(sock, ether_frame, sizeof(ether_header) +
			    sizeof(ip) + sizeof(icmphdr) + payload_len, 0,
			    (const struct sockaddr*)&socket_address,
			    sizeof(socket_address)) == -1) {
				perror("sendto() failed");
				continue;
			}
		}
		fprintf(stderr, "Sent pings to gateway, "
		    "waiting for reply...\n");

		start = time(NULL);

		/* Get the subnet id from the first received arp packet */
		do {
			memset(ether_frame, 0, ETH_FRAME_LEN);
			if(recv(sock, ether_frame, ETH_FRAME_LEN, 0) == -1) {
				if(errno == EINTR) {
					continue;
				} else {
					perror("recv() failed");
					goto fail;
				}
			}
			if((double)(time(NULL)-start) >= 0.5)
			    break;
		} while(ntohs(eth_header->ether_type) != ETHERTYPE_ARP ||
		    ntohs(arp_header->ea_hdr.ar_op) != ARPOP_REQUEST ||
		    memcmp(arp_header->arp_spa, sw_ip, 4) != 0 ||
		    memcmp(arp_header->arp_sha, sw_mac, ETH_ALEN) != 0);

		if ((double)(time(NULL)-start) <= 0.4)
			break;

		fprintf(stderr, "Got NO ARP reply from gateway. "
		    "Trying next IP sequence\n");
	}

	memcpy(src_ip, arp_header->arp_tpa, 4);
	fprintf(stderr, "Got ARP reply from gateway for working IP:\n");
	fprintf(stdout, "%hhu.%hhu.%hhu.%hhu\n",
	    src_ip[0], src_ip[1], src_ip[2], src_ip[3]);

	close(sock);
	return EXIT_SUCCESS;
fail:
	close(sock);
	return EXIT_FAILURE;
}
