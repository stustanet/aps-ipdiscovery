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
	uint8_t my_mac[ETH_ALEN];
	uint8_t radv_mac[ETH_ALEN];
	uint8_t radv_ip[4] = {0, 0, 0, 0};
	uint8_t my_ip[4] = {10, 150, 0, 240};

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

	memcpy(radv_ip,&(ip_header->ip_src), 4);
	memcpy(radv_mac, eth_header->ether_shost, ETH_ALEN);
	fprintf(stderr, "Got ICMP-RADV from: "
	    "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX\n", radv_mac[0],
	    radv_mac[1], radv_mac[2], radv_mac[3], radv_mac[4], radv_mac[5]);

	/*
	 * TODO: What do we do, when the sender is wrong?
	 * Abort, Retry, Proactive DOS on attacker ;)
	 */
	fprintf(stderr, "Got ICMP-RADV from %hhu.%hhu.%hhu.%hhu assuming "
	    "%hhu.%hhu.%hhu.0/24 subnet.\n", radv_ip[0], radv_ip[1],
	    radv_ip[2], radv_ip[3], radv_ip[0], radv_ip[1], radv_ip[2]);

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
	memcpy(my_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	fprintf(stderr, "Own MAC address: "
	    "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX\n", my_mac[0],
	    my_mac[1], my_mac[2], my_mac[3], my_mac[4], my_mac[5]);

	/* prepare sockaddr_ll */
	socket_address.sll_family = AF_PACKET;
	socket_address.sll_protocol = htons(ETH_P_IP);
	socket_address.sll_ifindex = ifindex;
	socket_address.sll_hatype = ARPHRD_ETHER;
	socket_address.sll_pkttype = PACKET_OTHERHOST;
	socket_address.sll_halen = ETH_ALEN;
	memset(socket_address.sll_addr, 0xFF, ETH_ALEN);
	socket_address.sll_addr[6] = 0x00;
	socket_address.sll_addr[7] = 0x00;

	/*
	 * Step 2: send a ping from each valid /29 to determine the right one.
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
	memcpy(&(ip_header->ip_dst), radv_ip, 4);

	/* fill ethernet header */
	memcpy(eth_header->ether_shost, my_mac, ETH_ALEN);
	memcpy(eth_header->ether_dhost, radv_mac, ETH_ALEN);
	eth_header->ether_type = htons(ETH_P_IP);

	/* fix socket_address content */
	memcpy(socket_address.sll_addr, radv_mac, ETH_ALEN);

	memcpy(my_ip, radv_ip, 4);
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
			my_ip[3] = 8 + i + 8 * j;
			memcpy(&(ip_header->ip_src), my_ip, 4);
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
		    memcmp(arp_header->arp_spa, radv_ip, 4) != 0 ||
		    memcmp(arp_header->arp_sha, radv_mac, ETH_ALEN) != 0);

		if ((double)(time(NULL)-start) <= 0.4)
			break;

		fprintf(stderr, "Got NO ARP reply from gateway. "
		    "Trying next IP sequence\n");
	}

	memcpy(my_ip, arp_header->arp_tpa, 4);
	fprintf(stderr, "Got ARP reply from gateway for working IP:\n");
	fprintf(stdout, "%hhu.%hhu.%hhu.%hhu\n",
	    my_ip[0], my_ip[1], my_ip[2], my_ip[3]);

	close(sock);
	return EXIT_SUCCESS;
fail:
	close(sock);
	return EXIT_FAILURE;
}
