#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "analyzer.h"
#include "pcap.h"

char packet[65535];


void readApplication(char ** pkt, int * pkt_len, int pro, int app)
{
    if(pro == 6)  //tcp
    {
        switch(app)
        {
            default:
                break;    
        }
    }
    else if(pro == 17)  //udp
    {
       switch(app)
       {
            case 68:
                printf("***DHCP***\n");
                dhcpAnalyzer(*pkt);
                break;
            case 520:
                printf("***RIP***\n");
                ripAnalyzer(*pkt,*pkt_len);
            default:
                break;    
        }
    }
}

int readTransport(char ** pkt, int * pkt_len, int protocol)
{
	struct tcphdr *tcp_h = (struct tcphdr*)*pkt;
	struct udphdr *udp_h = (struct udphdr*)*pkt;
    int app = 0;

	switch(protocol)
	{
		case 6:
		    app = tcpAnalyzer(*pkt);
			tcp_h++;
			*pkt = (char*)tcp_h;
            *pkt_len -= sizeof(struct tcphdr);
			break;
		case 17:
			app = udpAnalyzer(*pkt);
			udp_h++;
			*pkt = (char*)udp_h;
            *pkt_len -= sizeof(struct udphdr);
			break;
		default:
			break;	
	}
    return app;
}

int readNetwork(char ** pkt, int * pkt_len, int net)
{
    struct iphdr *ip_h = (struct iphdr*)*pkt;
    int pro = 0;

	switch(net)
	{
		case ETHERTYPE_IP:
			printf("Type: IP (%04x)\n",net);
			pro = ipAnalyzer(*pkt);
			ip_h++;
			*pkt = (char*)ip_h;
            *pkt_len -= sizeof(struct iphdr);
			break;
		case ETHERTYPE_ARP:
		    printf("Type: ARP (%04x)\n",net);
			pro = arpAnalyzer(*pkt);
			break;
		case ETHERTYPE_IPV6:
		    printf("Type: IPv6 (%04x)\n",net);
			break;
		default:
		    printf("Type: Other (%04x)\n",net);
			break;
	}
    return pro;
}

int readFrame(char ** pkt, int * pkt_len)
{
    struct ether_header *ether_h = (struct ether_header*)*pkt;
	struct ether_addr *dhost = (struct ether_addr*)ether_h->ether_dhost;
	struct ether_addr *shost = (struct ether_addr*)ether_h->ether_shost;
	
	printf("Dst: %s\n",ether_ntoa(dhost));
	printf("Src: %s\n",ether_ntoa(shost));
	
	int net = ntohs(ether_h->ether_type);
	ether_h++;
	*pkt = (char*)ether_h;
    *pkt_len = *pkt_len - sizeof(struct ether_header);
    return net;
}


void readFile(char * filename)
{
    FILE * fp = fopen(filename, "rb");
	pcap_pkthdr pkt_h;
	char *pkt;
	int pkt_len;
	int net_type,pro_type,app_type;
	int cnt = 0;

	if(fp == NULL)
	{
		printf("open file error\n");
		exit(1);
	}

	fseek(fp, sizeof(pcap_file_header), SEEK_SET);
	while(!feof(fp))
	{
		if(0 >= fread(&pkt_h,sizeof(pcap_pkthdr),1,fp))
		    break;

		cnt++;
		pkt_len = pkt_h.caplen;
		fread(packet,pkt_len,1,fp);
		pkt = packet;
		net_type = pro_type = app_type = 0;

		net_type = readFrame(&pkt,&pkt_len);
		pro_type = readNetwork(&pkt, &pkt_len, net_type);
		app_type = readTransport(&pkt, &pkt_len, pro_type);
        
        readApplication(&pkt, &pkt_len, pro_type, app_type);

		printf("-------------------------------------\n");
	}
	printf("\nreading finished...\n");
	printf("cnt: %d\n",cnt);
}


int main(int argc, char * argv[])
{
    char * filename = "test.pcap";
    if(argc == 2)
        filename = argv[1];
    readFile(filename);
    return 0;
}
