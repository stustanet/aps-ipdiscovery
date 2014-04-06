#define __USE_BSD

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct ether_header ether_header;
typedef struct ether_arp ether_arp;
typedef struct iphdr iphdr;
typedef struct icmphdr icmphdr;

/* BEWARE: The interface has to be up for this to work */

int main(int argc, char* argv[]) {
	int sock;
	uint8_t subnet_id = 0;
	ether_header* eth_header;
	ether_arp* arp_header;
	iphdr* ip_header;
	icmphdr* icmp_header;
	int ifindex = 0;
	uint8_t ether_frame[ETH_FRAME_LEN];
	struct ifreq ifr;
	struct sockaddr_ll socket_address;
	uint8_t src_mac[ETH_ALEN];
	uint8_t dst_mac[ETH_ALEN];
	uint8_t sw_mac[ETH_ALEN];
	uint8_t src_ip[4] = {10, 150, 0, 240};
	uint8_t dst_ip[4] = {10, 150, 0, 254};

	eth_header  = (ether_header*)ether_frame;
	arp_header  = (ether_arp*)(ether_frame + sizeof(ether_header));
	ip_header   = (iphdr*)(ether_frame + sizeof(ether_header));
	icmp_header = (icmphdr*)(ether_frame + sizeof(ether_header) + sizeof(ip_header));

	/* Open raw socket (needs root) to listen for arp */
	if((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		perror("socket() failed");
		return EXIT_FAILURE;
	}

	/* Step 1: Get the subnet id from the first received ARP packet.
	 * We listen passively on all interfaces (only the upstream eth0 port should
	 * be up to ensure, we only get meaningful ARPs. From the first received ARP
	 * packet we take the subnet id x and from there on assume we are operating
	 * in 10.150.x.0 */
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
	} while(ntohs(eth_header->ether_type) != ETHERTYPE_ARP);
	subnet_id = arp_header->arp_spa[2];
	fprintf(stderr, "Got ARP, assuming 10.150.%u.0 subnet.\n", subnet_id);

	/* Step 2: Get the next gateways MAC address.
	 * We send an ARP from 10.150.x.240 to the gateway at 10.150.x.254 to get
	 * it's MAC. The ARP-caches of all neighbours from 10.150.x.0 get a wrong
	 * entry for 10.150.x.240, but this address is not used and Wolfi approved
	 * using it. */
	memset(ether_frame, 0, ETH_FRAME_LEN);
	src_ip[2] = dst_ip[2] = subnet_id;

	/* retrieve ethernet interface index */
	strncpy(ifr.ifr_name, "eth0", IFNAMSIZ);
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
	fprintf(stderr, "Own MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
	        src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5]);

	/* prepare sockaddr_ll */
	socket_address.sll_family   = AF_PACKET;
	socket_address.sll_protocol = htons(ETH_P_IP);
	socket_address.sll_ifindex  = ifindex;
	socket_address.sll_hatype   = ARPHRD_ETHER;
	socket_address.sll_pkttype  = PACKET_OTHERHOST;
	socket_address.sll_halen    = ETH_ALEN;
	memcpy(socket_address.sll_addr, dst_mac, ETH_ALEN);
	socket_address.sll_addr[6]  = 0x00;
	socket_address.sll_addr[7]  = 0x00;

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
	memcpy(arp_header->arp_tpa, dst_ip, 4);
	memcpy(arp_header->arp_sha, src_mac, ETH_ALEN);
	memcpy(arp_header->arp_spa, src_ip, 4);

	/* finally send our manually crafted, black-magic containing ARP request */
	if(sendto(sock, ether_frame, 60, 0, (const struct sockaddr*)&socket_address, sizeof(socket_address)) == -1) {
		perror("sendto() failed");
		goto fail;
	}
	fprintf(stderr, "Sent ARP request to gateway, waiting for reply...\n");

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
	} while(ntohs(eth_header->ether_type) != ETHERTYPE_ARP
	     || ntohs(arp_header->ea_hdr.ar_op) != ARPOP_REPLY
	     || memcmp(arp_header->arp_spa, dst_ip, 4) != 0);
	memcpy(sw_mac, arp_header->arp_sha, ETH_ALEN);
	fprintf(stderr, "Got ARP reply from gateway at %02x:%02x:%02x:%02x:%02x:%02x\n",
	       sw_mac[0], sw_mac[1], sw_mac[2], sw_mac[3], sw_mac[4], sw_mac[5]);

	close(sock);
	return EXIT_SUCCESS;
fail:
	close(sock);
	return EXIT_FAILURE;
}
