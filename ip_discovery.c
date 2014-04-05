#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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
	uint8_t sender_mac[6];
	uint8_t sender_ip[4];
	uint8_t target_mac[6];
	uint8_t target_ip[4];
};

typedef struct _eth_hdr eth_hdr;
struct _eth_hdr {
	uint8_t target_mac[6];
	uint8_t sender_mac[6];
	uint16_t packet_type;
};

int main(int argc, char* argv[]) {
	int sock;
	uint8_t subnet_id = 0;
	eth_hdr* ethhdr;
	arp_hdr* arphdr;
	void* ether_frame;

	errno = 0;
	if(!(ether_frame = malloc(ETH_FRAME_LEN))) {
		perror("malloc() failed");
		return EXIT_FAILURE;
	}
	ethhdr = (eth_hdr*)ether_frame;
	arphdr = (arp_hdr*)(ether_frame + 6 + 6 + 2);

	errno = 0;
	// Open raw socket (needs root) to listen for arp
	if((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		perror("socket() failed");
		goto fail;
	}

	// Get the subnet id from the first received arp packet
	do {
		memset(ether_frame, 0, ETH_FRAME_LEN);

		errno = 0;
		if(recv(sock, ether_frame, ETH_FRAME_LEN, 0) == -1) {
			if(errno == EINTR) {
				continue;
			} else {
				perror("recv() failed");
				goto fail;
			}
		}
	} while(ntohs(ethhdr->packet_type) != ETH_P_ARP);
	close(sock);
	subnet_id = arphdr->sender_ip[2];
	printf("Got ARP packet, assuming 10.150.%u.0 subnet.\n", subnet_id);
	free(ether_frame);

	return EXIT_SUCCESS;
fail:
	free(ether_frame);
	return EXIT_FAILURE;
}
