#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <errno.h>


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

int main(int argc, char* argv[]) {
	int sock;
	arp_hdr* arp_header;

	// Submit request for a raw socket descriptor.
	if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		perror ("socket() failed ");
		exit (EXIT_FAILURE);
	}
	return 0;
}
