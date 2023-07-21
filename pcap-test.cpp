#include <pcap.h>
#include <stdbool.h>
#include <iostream>
#include <stdio.h>
#include <stdint.h>
#include <pcap/pcap.h>
#include <pcap.h>
#include <iostream>
#include <string.h>
//#include "./libnet/include/libnet/libnet-functions.h"
//#include "./libnet/include/libnet/libnet-structures.h"
//#include "./libnet/include/libnet/libnet-headers.h"
//#include "./libnet/include/libnet/libnet-types.h"
//#include "./libnet/include/libnet/libnet-macros.h"
//#include "./libnet/include/libnet/libnet-asn1.h"
//#define Ethernet eth0

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}
typedef unsigned char u_char;
typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

typedef struct {
	u_int16_t iptype;
	u_char srcmac[6];
	u_char dstmac[6];
} Ethernet;

typedef struct {
	u_char protocol;
	u_int16_t len;
	u_char srcip[4];
	u_char dstip[4];
} Ip;

typedef struct {
	u_char headerlen;
	u_char srcport[2];
	u_char dstport[2];
} Tcp;



class Ethernet_class {
	unsigned short iptype = 0x6;
	unsigned char srcmac[6] = { 0, };
	unsigned char dstmac[6] = { 0, };
public:
	Ethernet_class() {}
	Ethernet_class(const char *hex)
		: iptype{ 0x6 }, srcmac{}, dstmac{}
	{
		memcpy(srcmac, hex, sizeof(srcmac));
		memcpy(dstmac, hex + 6, sizeof(dstmac));
		memcpy(&iptype, hex + 12, sizeof(iptype));
		//memcpy((char*)srcmac, hex,sizeof(srcmac));
		//memcpy((char*)dstmac, hex+6,sizeof(dstmac));
		//memcpy((char*)(&iptype), hex + 12, sizeof(iptype));
	}
	void printSrc() { printf("Src MAC addr\t: %02x:%02x:%02x:%02x:%02x:%02x\n", srcmac[0], srcmac[1], srcmac[2], srcmac[3], srcmac[4], srcmac[5]); }
	void printDst() { printf("Dst MAC addr\t: %02x:%02x:%02x:%02x:%02x:%02x\n", dstmac[0], dstmac[1], dstmac[2], dstmac[3], dstmac[4], dstmac[5]); }
	void printiptype(void) {
		unsigned short h = ntohs(iptype);
		
		printf("IPtype\t\t: 0x%04x ",h);
		switch (h) {
		case 0x0800:
			printf("IPv4");
			break;
		case 0x86DD:
			printf("IPv6");
			break;
		case 0x0806:
			printf("ARP");
			break;
		}
		printf("\n");
	}
	void printall(void) {
		printSrc();
		printDst();
		printiptype();
	}
};

class Ip_class {
	unsigned char protocol = 0x06;
	unsigned char headerlen = 0;
	unsigned short len = 0;	
	unsigned char srcip[4] = { 0, };
	unsigned char dstip[4] = { 0, };
public:
	Ip_class() {}
	Ip_class(const char* hex)
		:protocol{ 0x06 }, len{}, srcip{}, dstip{}
	{
		memcpy(&headerlen, hex, sizeof(headerlen));
		headerlen &= 0x0f;
		headerlen *= 4;
		memcpy(&len, hex+2, sizeof(len));
		memcpy(&protocol, hex + 9, sizeof(protocol)); 
		memcpy(srcip, hex + 2 + 0xA, sizeof(srcip));
		memcpy(dstip, hex + 2 + 0xA + 4, sizeof(dstip));
		len = ntohs(len);
	}
	unsigned short length() { return len; }
	unsigned char headerLength(void) { return headerlen; }
	void printSrc(void) { printf("IP Src Addr\t: %d.%d.%d.%d\n", srcip[0], srcip[1], srcip[2], srcip[3]); }
	void printDst(void) { printf("IP Dst Addr\t: %d.%d.%d.%d\n", dstip[0], dstip[1], dstip[2], dstip[3]); }
	void printLen(void) { printf("IP len\t\t: %d\n", len); }
	void printheaderLen(void) {	printf("IP headerlen\t: %u\n", headerlen);}
	void printProtocol(void) { 
		printf("Transport\t: %02x ", protocol);
		switch (protocol) {
		case 0x01:
			printf("ICMP");
			break;
		case 0x06:
			printf("TCP");
			break;
		case 0x11:
			printf("UDP");
			break;
		}
		printf("\n");
	}
	void printall(void) {
		printSrc();
		printDst();
		printLen();
		printheaderLen();
		printProtocol();
	}
};

class Tcp_class {
private:
	unsigned char headerlen;
	unsigned char srcport[2] = { 0, };
	unsigned char dstport[2] = { 0, };
	char string[11] = { 0, };
public:
	Tcp_class() {}
	Tcp_class(const char* hex)
		: headerlen{}, srcport{}, dstport{0,5}
	{
		memcpy(srcport, hex, sizeof(srcport));
		memcpy(dstport, hex + 2, sizeof(dstport));
		memcpy(&headerlen, hex + 0xC, sizeof(headerlen));
		headerlen &= 0xf0;
		headerlen >>= 4;
		headerlen *= 4;
		memcpy(string, hex + headerlen, 10);
	}
	void printSrc() { 
		// for prevent overflow
		unsigned int port = srcport[0]*16*16 + srcport[1];
		printf("TCP Src Addr\t: %u\n", port); 
	}
	void printDst() {
		// for prevent overflow
		unsigned int port = dstport[0]*16*16 + dstport[1];
		printf("TCP Dst Addr\t: %u\n", port);
	}
	void printLen() { printf("Header Lenght\t: %d\n", headerlen); }
	void printString() { printf("HTTP string\t: %s\n",string); }
	void printAll() {
		printSrc();
		printDst();
		printLen();
		printString();
	}
};


bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv)){
		printf("not parsed");
		return -1;
	}
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header; // ts, caplen, len

		
		const char* packet;
		int res = pcap_next_ex(pcap, &header, (const u_char**)(&packet)); // open  (pcap_t *pcap, pcap_pkthdr **abstact info, packet const char **)
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_e./x return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);
		
		Ethernet_class ethernet(packet);
		Ip_class ip(packet+sizeof(ethernet));
		Tcp_class tcp(packet+sizeof(ethernet) + ip.headerLength());
		
		printf(" ----------------------\n");
		ethernet.printall();

		printf("\n\n");

		ip.printall();

		printf("\n\n");

		tcp.printAll();

		printf("\n\n");

		printf("Total lenght\t: %zu\n", sizeof(Ethernet_class) + ip.length());
	printf(" ----------------------\n");
	}

	pcap_close(pcap);
}
