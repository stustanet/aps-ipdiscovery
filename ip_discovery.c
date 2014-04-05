#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

// BEWARE: The interface has to be up for this to work

// Define an struct for ARP header
typedef struct _arp_hdr arp_hdr;
struct _arp_hdr {
	uint16_t htype;
	uint16_t ptype;
	uint8_t hlen;
	uint8_t plen;
	uint16_t opcode;
	uint8_t sender_mac[ETH_ALEN];
	uint8_t sender_ip[4];
	uint8_t target_mac[ETH_ALEN];
	uint8_t target_ip[4];
	uint8_t fill[18];
};

typedef struct _eth_hdr eth_hdr;
struct _eth_hdr {
	uint8_t target_mac[ETH_ALEN];
	uint8_t sender_mac[ETH_ALEN];
	uint16_t packet_type;
};

int main(int argc, char* argv[]) {
	int sock;
	int i;
	uint8_t subnet_id = 0;
	eth_hdr* ethhdr;
	arp_hdr* arphdr;
	int ifindex = 0;
	uint8_t ether_frame[ETH_FRAME_LEN];
	struct ifreq ifr;
	struct sockaddr_ll socket_address;
	uint8_t src_mac[ETH_ALEN];
	uint8_t dst_mac[ETH_ALEN];
	uint8_t src_ip[4] = {10, 150, 0, 240};
	uint8_t dst_ip[4] = {10, 150, 0, 254};

	ethhdr = (eth_hdr*)ether_frame;
	arphdr = (arp_hdr*)(ether_frame + ETH_HLEN);

	// Open raw socket (needs root) to listen for arp
	if((sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		perror("socket() failed");
		return EXIT_FAILURE;
	}

	// Get the subnet id from the first received arp packet
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
	} while(ntohs(ethhdr->packet_type) != ETH_P_ARP);
	subnet_id = arphdr->sender_ip[2];
	printf("Got ARP packet, assuming 10.150.%u.0 subnet.\n", subnet_id);

	// send arp from 10.150.x.240 to the switch at 10.150.x.254 to get it's mac.
	memset(ether_frame, 0, ETH_FRAME_LEN);
	src_ip[2] = dst_ip[2] = subnet_id;

	/*retrieve ethernet interface index*/
	strncpy(ifr.ifr_name, "eth0", IFNAMSIZ);
	if(ioctl(sock, SIOCGIFINDEX, &ifr) == -1) {
		perror("SIOCGIFINDEX");
		goto fail;
	}
	ifindex = ifr.ifr_ifindex;
	printf("Successfully got interface index: %i\n", ifindex);

	/*retrieve corresponding MAC*/
	if(ioctl(sock, SIOCGIFHWADDR, &ifr) == -1) {
		perror("SIOCGIFHWADDR");
		goto fail;
	}
	for(i=0; i<ETH_ALEN; i++) {
		src_mac[i] = ifr.ifr_hwaddr.sa_data[i];
	}
	memset(dst_mac, 0xFF, ETH_ALEN);
	printf("Successfully got our MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
	       src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5]);

	/*prepare sockaddr_ll*/
	socket_address.sll_family   = AF_PACKET;
	socket_address.sll_protocol = htons(ETH_P_IP);
	socket_address.sll_ifindex  = ifindex;
	socket_address.sll_hatype   = ARPHRD_ETHER;
	socket_address.sll_pkttype  = PACKET_OTHERHOST;
	socket_address.sll_halen    = ETH_ALEN;
	socket_address.sll_addr[0]  = dst_mac[0];
	socket_address.sll_addr[1]  = dst_mac[1];
	socket_address.sll_addr[2]  = dst_mac[2];
	socket_address.sll_addr[3]  = dst_mac[3];
	socket_address.sll_addr[4]  = dst_mac[4];
	socket_address.sll_addr[5]  = dst_mac[5];
	socket_address.sll_addr[6]  = 0x00;
	socket_address.sll_addr[7]  = 0x00;

	// fill ethernet header
	memcpy(ethhdr->sender_mac, src_mac, ETH_ALEN);
	memcpy(ethhdr->target_mac, dst_mac, ETH_ALEN);
	ethhdr->packet_type = htons(ETH_P_ARP);

	// fill ARP header
	arphdr->htype = htons(ARPHRD_ETHER);
	arphdr->ptype = htons(0x800); // ethertype ip
	arphdr->hlen = ETH_ALEN;
	arphdr->plen = 4;
	arphdr->opcode = htons(ARPOP_REQUEST);
	// arphdr->target_mac already zeroed from memset()
	memcpy(arphdr->target_mac, dst_mac, ETH_ALEN);
	memcpy(arphdr->target_ip, dst_ip, 4);
	memcpy(arphdr->sender_mac, src_mac, ETH_ALEN);
	memcpy(arphdr->sender_ip, src_ip, 4);

	if(sendto(sock, ether_frame, 60, 0, (const struct sockaddr*)&socket_address, sizeof(socket_address)) == -1) {
		perror("sendto() failed");
		goto fail;
	}

	close(sock);
	return EXIT_SUCCESS;
fail:
	close(sock);
	return EXIT_FAILURE;
}
