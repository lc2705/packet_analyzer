#include "analyzer.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <protocols/routed.h>

void _icmp_orig_ip(struct icmp_ipdata * data)
{
    printf("***Original Packet***\n");
    printf("Version:%d\tHeader length:%d bytes\n",data->ip_hdr.ip_v,data->ip_hdr.ip_hl * 4);
    printf("Tos:0x%02x\tTotal length:%d\n",
           data->ip_hdr.ip_tos,ntohs(data->ip_hdr.ip_len));
    printf("Identification:0x%04x\tFragment offset:0x%02x\n",
           ntohs(data->ip_hdr.ip_id),ntohs(data->ip_hdr.ip_off));
    printf("Time to live:%d\tChecksum:0x%04x\n",data->ip_hdr.ip_ttl,ntohs(data->ip_hdr.ip_sum));
    if(data->ip_hdr.ip_p == 6)
        printf("Protocol:6 (TCP)\n");
    else if(data->ip_hdr.ip_p == 17)
        printf("Protocol:17 (UDP)\n");
    else
        printf("other\n");

    printf("Source IP:%s  ",inet_ntoa(data->ip_hdr.ip_src));
    printf("Destination IP:%s\n",inet_ntoa(data->ip_hdr.ip_dst));
    
    //8 bytes in ip packet
    if(data->ip_hdr.ip_p == 6)
    {
        printf("Source port:%d\tDestination port:%d\n",ntohs(data->sport), ntohs(data->dport));
        printf("Sequence:0x%04x\n",ntohl(data->ipdata_un.seq));
    }
    else if(data->ip_hdr.ip_p == 17)
    {
        printf("Source port:%d\tDestination port:%d\n",ntohs(data->sport), ntohs(data->dport));
        printf("Length:%d\tChecksum:0x%04x\n", ntohs(data->ipdata_un.udp_hdr.length), ntohs(data->ipdata_un.udp_hdr.checksum)); 
    }
}



void _echo_and_reply(uint8_t type, uint16_t id, uint16_t seq, 
                     unsigned char data[], int data_length)
{
    if(type == ICMP_ECHOREPLY)
	    printf("Echo (ping) reply\n");
    else if(type == ICMP_ECHO)
        printf("Echo (ping) request\n");
	printf("Identifier: %d\tSequence number: %d\nData:\n",id,seq);
	
    int i = 0,j;
    unsigned char *data_p = data;
    while(i < data_length)
    {
        for(j = 0; j < 10 && i < data_length; i++,j++)
        {
		    printf("%02x",*data_p);
            data_p++;
        }
        printf("\n");
        j = 0;
    }
}

void _dest_unreach(uint8_t code, struct icmp_ipdata * data, uint16_t next_mtu = 0)
{
	printf("Destination unreachable, ");
    switch(code)
    {
        case ICMP_UNREACH_NET:
            printf("Network unreachable\n");
            break;
        case ICMP_UNREACH_HOST:
            printf("Host unreachable\n");
            break;
        case ICMP_UNREACH_PROTOCOL:
            printf("Protocol unreachable\n");
            break;
        case ICMP_UNREACH_PORT:
            printf("Port unreachable\n");
            break;
        case ICMP_UNREACH_NEEDFRAG:
            printf("Fragment is required\n");
            printf("Next hop MTU: %d\n",next_mtu);
            break;
        case ICMP_UNREACH_SRCFAIL:
            printf("Source route failed\n");
            break;
        case ICMP_UNREACH_NET_UNKNOWN:
            printf("Destination network unknown\n");
            break;
        case ICMP_UNREACH_HOST_UNKNOWN:
            printf("Destination host unknown\n");
            break;
        case ICMP_UNREACH_ISOLATED:
            printf("Source host isolated\n");
            break;
        case ICMP_UNREACH_NET_PROHIB:
            printf("Destination network administratively prohibited\n");
            break;
        case ICMP_UNREACH_HOST_PROHIB:
            printf("Destination host administratively prohibited\n");
            break;
        case ICMP_UNREACH_TOSNET:
            printf("Network unreachable for TOS\n");
            break;
        case ICMP_UNREACH_TOSHOST:
            printf("Host unreachable for TOS\n");
            break;
        case ICMP_UNREACH_FILTER_PROHIB:
            printf("Communication administratively prohibited\n");
            break;
        case ICMP_UNREACH_HOST_PRECEDENCE:
            printf("Host precedence violation\n");
            break;
        case ICMP_UNREACH_PRECEDENCE_CUTOFF:
            printf("Precedence cutoff in effect\n");
            break;
        default:
            break;
    }
    _icmp_orig_ip(data);
}

void _source_quench(struct icmp_ipdata * data)
{
    printf("Source quench\n");
    _icmp_orig_ip(data);    
}

void _redirect(uint8_t code, struct in_addr gwaddr, struct icmp_ipdata *data)
{
    printf("Redirect ");
    switch(code)
    {
        case ICMP_REDIRECT_NET:
            printf("for Network\n");
            break;
        case ICMP_REDIRECT_HOST:
            printf("for Host\n");
            break;
        case ICMP_REDIRECT_TOSNET:
            printf("for Type of Service and Network\n");
            break;
        case ICMP_REDIRECT_TOSHOST:
            printf("for Type of Service and Host\n");
            break;
        default:
            break;     
    }
    printf("Redirct gateway:%s\n",inet_ntoa(gwaddr));
    _icmp_orig_ip(data);
}

void _time_exceeded(uint8_t code, struct icmp_ipdata * data)
{
    printf("Time exceeded, ");
    if(code == ICMP_TIMXCEED_INTRANS)
        printf("Time-to-live exceeded in transit\n");
    else if(code == ICMP_TIMXCEED_REASS)
        printf("Fragment reassembly time exceeded\n");
    _icmp_orig_ip(data);    
}

void _timestamp_and_reply(uint8_t type, uint16_t id, uint16_t seq, 
                uint32_t otime, uint32_t rtime, uint32_t ttime)
{
    if(type == ICMP_TIMESTAMP)
        printf("Timestamp\n");
    else if(type == ICMP_TIMESTAMPREPLY)
        printf("Timestamp reply\n");
    printf("Identifier:%d\tSequence:%d\n", id, seq);
    printf("Originate timestamp:%d\n",otime);
    printf("Receive timestamp:%d\n",rtime);
    printf("Transmit timestamp:%d\n",ttime);
}

void _address_and_reply(uint8_t type, uint16_t id, 
                        uint16_t seq, uint32_t mask)
{
    if(type == ICMP_ADDRESS)
        printf("Mask request\n");
    else if(type == ICMP_ADDRESSREPLY)
        printf("Mask reply\n");
    printf("Identifier:%d\tSequence:%d\n", id, seq);
    struct in_addr in_mask;
    in_mask.s_addr = (in_addr_t)mask;
    printf("Mask:%s\n",inet_ntoa(in_mask));
}

void _parameter_prob(uint8_t code,u_char pptr,struct icmp_ipdata *data)
{
    printf("Parameter problem, ");
    if(code == 0)
    {
        printf("Pointer indicates the error\n");
        printf("Pointer:%d\n",(uint8_t)pptr);
    }
    else if(code == ICMP_PARAMPROB_OPTABSENT)
        printf("Required options absent\n");
    else if(code == 2)
        printf("Bad length\n");
    _icmp_orig_ip(data);   
}

void _router_advert(uint8_t num_addrs,uint8_t wpa, uint16_t lifetime,
                    struct icmp_ra_addr *ra)
{
    printf("Router Advertisement\n");
    printf("Advertisement count:%d\tAddress Entry size:%d bytes\n",num_addrs, wpa * 4);
    printf("Lifetime:%d\n",lifetime);
    
    struct icmp_ra_addr *ra_p = ra;
    struct in_addr in_address;
    for(int i = 0; i < num_addrs; i++)
    {
        in_address.s_addr = (in_addr_t)ra_p->ira_addr;
        printf("Router Address:%s  Preference level:%d\n",inet_ntoa(in_address), ra_p->ira_preference);        
    }
}

void _router_solicit()
{
    printf("Router Solicitation\n");
}


void icmpAnalyzer(char * pkt, int length)
{
	struct icmp *icmp_p = (struct icmp*)pkt;	
	uint8_t type = icmp_p->icmp_type;
	uint8_t code = icmp_p->icmp_code;
	uint16_t checksum = ntohs(icmp_p->icmp_cksum);
	
	printf("Type: %d\tCode: %d\n",type,code);
	printf("Checksum: 0x%04x\n",checksum);
	switch(type)
	{
		case ICMP_ECHOREPLY:
			_echo_and_reply(type,
                            ntohs(icmp_p->icmp_id),
						    ntohs(icmp_p->icmp_seq),
					        icmp_p->icmp_data,
                            length - 8);
			break;
		case ICMP_UNREACH:
			_dest_unreach(code,(struct icmp_ipdata*)&icmp_p->icmp_ip,
                                ntohs(icmp_p->icmp_nextmtu));
			break;
		case ICMP_SOURCE_QUENCH:
            if(code == 0)
			    _source_quench((struct icmp_ipdata*)&icmp_p->icmp_ip);
            else
                printf("Source quench packet error\n");
			break;
        case ICMP_REDIRECT:
            _redirect(code, icmp_p->icmp_gwaddr,
                      (struct icmp_ipdata*)&icmp_p->icmp_ip);
		case ICMP_ECHO:
			_echo_and_reply(type,
                            ntohs(icmp_p->icmp_id),
                            ntohs(icmp_p->icmp_seq),
                            icmp_p->icmp_data,
                            length - 8);
			break;
		case ICMP_TIME_EXCEEDED:
			_time_exceeded(code, (struct icmp_ipdata*)&icmp_p->icmp_ip);
			break;
		case ICMP_PARAMETERPROB:
			_parameter_prob(code,icmp_p->icmp_pptr,
                            (struct icmp_ipdata*)&icmp_p->icmp_ip);
			break;
		case ICMP_TIMESTAMP:
			_timestamp_and_reply(type, ntohs(icmp_p->icmp_id), 
                                 ntohs(icmp_p->icmp_seq),
                                 ntohl(icmp_p->icmp_otime),
                                 ntohl(icmp_p->icmp_rtime),
                                 ntohl(icmp_p->icmp_ttime));
			break;
		case ICMP_TIMESTAMPREPLY:
			_timestamp_and_reply(type, ntohs(icmp_p->icmp_id), 
                                 ntohs(icmp_p->icmp_seq),
                                 ntohl(icmp_p->icmp_otime),
                                 ntohl(icmp_p->icmp_rtime),
                                 ntohl(icmp_p->icmp_ttime));
			break;
		case ICMP_INFO_REQUEST:
			break;
		case ICMP_INFO_REPLY:
			break;
		case ICMP_ADDRESS:
			_address_and_reply(type, ntohs(icmp_p->icmp_id),
                               ntohs(icmp_p->icmp_seq),
                               icmp_p->icmp_mask);
			break;
		case ICMP_ADDRESSREPLY:
			_address_and_reply(type,ntohs(icmp_p->icmp_id),
                               ntohs(icmp_p->icmp_seq),
                               icmp_p->icmp_mask);
			break;
        case ICMP_ROUTERADVERT:
            _router_advert(icmp_p->icmp_num_addrs,icmp_p->icmp_wpa,
                           ntohs(icmp_p->icmp_lifetime),
                           &icmp_p->icmp_radv);
            break;
        case ICMP_ROUTERSOLICIT:
            _router_solicit();
            break;
		default:
			break;
	}
}
/*
void ospfAnalyzer(char * pkt, int length)
{

    printf("ospfAnalyzer\n");
}
*/
int ipAnalyzer(char * pkt)
{
    struct iphdr *ip_h = (struct iphdr*)pkt;
    uint16_t version = ip_h->version;
    uint16_t header_length = ip_h->ihl * 4;
    uint16_t tos = ip_h->tos;   //type of service
    uint16_t total_length = ntohs(ip_h->tot_len);
    uint16_t id = ntohs(ip_h->id);
    uint16_t flag = ntohs(ip_h->frag_off) >> 13;   // don't fragment ,  more fragment
    uint16_t fragment_offset = ntohs(ip_h->frag_off) & 0x1fff;
    uint16_t ttl = ip_h->ttl;
    uint16_t protocol = ip_h->protocol;
    uint16_t checksum = ntohs(ip_h->check);
    
    struct in_addr source_addr,dest_addr;
    source_addr.s_addr = (in_addr_t)ip_h->saddr;
    dest_addr.s_addr = (in_addr_t)ip_h->daddr;

    printf("version:%d\tHeader length:%d Bytes\n",version,header_length);

    printf("Tos:0x%02x\n",tos);
    switch(IPTOS_DSCP(tos))   //ip.h
    {
        case 0x0:
            printf("Differentiated Services Codepoint:default\n");
            break;
        case 0x28:
            printf("Differentiated Services Codepoint:AF11\n");
            break;
        case 0x30:
            printf("Differentiated Services Codepoint:AF12\n");
            break;
        default:
            break;
    }
    switch(IPTOS_ECN(tos))
    {
        case IPTOS_ECN_NOT_ECT:
            printf("Explicit Congestion Notification:Not-ECT\n");
            break;
        case IPTOS_ECN_ECT1:
            printf("Explicit Congestion Notification:ECT1\n");
            break;
        case IPTOS_ECN_ECT0:
            printf("Explicit Congestion Notification:ECT0\n");
            break;
        case IPTOS_ECN_CE:
            printf("Explicit Congestion Notification:CE\n");
            break;
        default:
            break;
    }
    
    printf("Total length:%d Bytes\tid:%d\n",total_length,id);
    printf("flag:0x%02x  ",flag);
    switch(flag)
    {
        case 0x2:
            printf("Don't fragment\n");
            break;
        case 0x0:
            printf("Last fragment\n");
            break;
        case 0x1:
            printf("More fragment\n");
            break;
        default:
            break;
    }
    printf("Fragment offset: %d\n",fragment_offset);
    printf("Time to live: %d\n",ttl);

    printf("Protocol: %d  ",protocol);
    printf("Checksum: %d\n",checksum);
    printf("Src IP address: %s\n",inet_ntoa(source_addr));
    printf("Dst IP address: %s\n",inet_ntoa(dest_addr));
    switch(protocol)  //in.h
    {
        case 0:
            printf("**IP**\n");
            break;
        case 1:
            printf("**ICMP**\n");
			icmpAnalyzer(pkt + sizeof(struct iphdr), total_length-header_length);
            break;
        case 6:
            printf("**TCP**\n");
            break;
        case 8:
            printf("**EGP**\n");
            break;
        case 17:
            printf("**UDP**\n");
            break;
        case 50:
            printf("ESP\n");
            break;
        case 89:
            printf("**OSPF**\n");
            //ospfAnalyzer(pkt + sizeof(struct iphdr), total_length-header_length);
            break;
        default:
		    printf("Other\n");
            break;
    }

    return protocol;
}

int arpAnalyzer(char * pkt)   // if_arp.h
{
	struct ether_arp *e_arp = (struct ether_arp*)pkt;
    uint16_t hrd_format = ntohs(e_arp->arp_hrd);  //format of hardware address
    uint16_t pro_format = ntohs(e_arp->arp_pro);  //format of protocol address
    uint8_t  hrd_length = e_arp->arp_hln;  //length of hardware address
    uint8_t  pro_length = e_arp->arp_pln;  //length of protocol address
    uint16_t ar_op = ntohs(e_arp->arp_op);

	struct ether_addr sender_mac,target_mac;
	struct in_addr sender_ip,target_ip;

	printf("Hardware type: ");
	switch(hrd_format)
	{
		case ARPHRD_ETHER:
			printf("Ethernet (%d)\n",hrd_format);
			break;
        case ARPHRD_IEEE802:
		    printf("IEEE 802.2 Ethernet (%d)\n",hrd_format);
			break;
		default:
		    printf("Other (%d)\n",hrd_format);
			break;
	}
	printf("Protocol type: ");
	switch(pro_format)
	{
		case 0x0800:
		    printf("IP (%04x)\n",pro_format);
			break;
		default:
		    printf("Other (%04x)\n",pro_format);
			break;	
	}
	printf("Hardware size: %d\tProtocol size: %d\n", hrd_length, pro_length);
	printf("Opcode: ");
	switch(ar_op)
	{
		case 1:
			printf("request (1)\n");
			break;
		case 2:
			printf("response (2)\n");
			break;
		default:
			printf("other (%d)\n",ar_op);
			break;
	}

	if(hrd_format == ARPHRD_ETHER)
	{
		memcpy(&sender_mac, e_arp->arp_sha,ETH_ALEN);
		memcpy(&target_mac, e_arp->arp_tha,ETH_ALEN);
		printf("Sender MAC: %s\n",ether_ntoa(&sender_mac));
		printf("Target MAC: %s\n",ether_ntoa(&target_mac));
	}
	if(pro_format == 0x0800)
	{
		memcpy(&sender_ip, e_arp->arp_spa,pro_length);
		memcpy(&target_ip, e_arp->arp_tpa,pro_length);
		printf("Sender IP: %s\n",inet_ntoa(sender_ip));
		printf("Target IP: %s\n",inet_ntoa(target_ip));		
	}
    return 0;
}

int tcpAnalyzer(char * pkt)
{
	struct tcphdr *tcp_h = (struct tcphdr*)pkt;
	uint16_t sport = ntohs(tcp_h->th_sport);
	uint16_t dport = ntohs(tcp_h->th_dport);
	uint32_t seq = ntohl(tcp_h->th_seq);
	uint32_t ack = ntohl(tcp_h->th_ack);
	uint8_t offset = (tcp_h->th_off)*4;
	uint8_t flags = tcp_h->th_flags;
	uint16_t window = ntohs(tcp_h->th_win);
	uint16_t checksum = ntohs(tcp_h->th_sum);
	uint16_t urgent_p = ntohs(tcp_h->th_urp);

    printf("Src port: %d\tDst port: %d\n",sport,dport);
	printf("Sequence: 0x%x\tAck: 0x%x\n",seq,ack);
	printf("Header length: %d\n",offset);
	
	printf("Flags: 0x%03x,",flags);
	if((flags&0x01) == 0x01) 
		printf("FIN ");
	if((flags&0x02) == 0x02) 
		printf("SYN ");
	if((flags&0x04) == 0x04) 
		printf("RST ");
	if((flags&0x08) == 0x08) 
		printf("PUSH ");
	if((flags&0x10) == 0x10) 
		printf("ACK ");
	if((flags&0x20) == 0x20) 
		printf("URG ");

	printf("\nWindow size: %d\tChecksum: 0x%04x\n",window,checksum);
}

int udpAnalyzer(char * pkt)
{
	struct udphdr *udp_h = (struct udphdr*)pkt;
	uint16_t sport = ntohs(udp_h->uh_sport);
	uint16_t dport = ntohs(udp_h->uh_dport);
	uint16_t length = ntohs(udp_h->uh_ulen);
	uint16_t checksum = ntohs(udp_h->uh_sum);

    printf("Src port: %d\tDst port: %d\n",sport,dport);
	printf("Length: %d\tChecksum: 0x%04x\n",length,checksum);

    if((sport == 68 && dport == 67) || (sport == 67 && dport == 68))
        return 68;
    else if(sport == 520 && dport == 520)
        return 520;
    else
        return 0;
}


void dhcpAnalyzer(char * pkt)
{
    struct dhcp_pkt *dhcp_p = (struct dhcp_pkt*)pkt;
    uint8_t msg = dhcp_p->msg;
    uint8_t htype = dhcp_p->htype;
    uint8_t hlen = dhcp_p->hlen;
    uint8_t hops = dhcp_p->hops;
    uint32_t xid = ntohl(dhcp_p->xid);
    uint16_t secs = ntohs(dhcp_p->secs);
    uint16_t flags = ntohs(dhcp_p->flags);

    struct in_addr ciaddr = dhcp_p->ciaddr;
    struct in_addr yiaddr = dhcp_p->yiaddr;
    struct in_addr siaddr = dhcp_p->siaddr;
    struct in_addr giaddr = dhcp_p->giaddr;

    uint32_t magic_cookie = ntohl(dhcp_p->magic_cookie);
    
    if(msg == DHCP_MSG_REQUEST)
        printf("Message type: Request(1)\t");
    else if(msg == DHCP_MSG_REPLY)
        printf("Message type: Reply(2)\t");

    printf("Hardware type:");
    if(htype == 1)
        printf("Ethernet(0x01)\n");
    else
        printf("Unknown(0x%04x)\n",htype);
    printf("Hardware address length:%d\t",hlen);
    printf("Hops:%d\n",hops);
    printf("Transaction ID:0x%08x\n",xid);
    printf("Seconds elapsed:%d\t",secs);
    if(flags)
        printf("Flags:0x8000(Broadcast)\n");
    else
        printf("Flags:0x0000(Unicase)\n");

    printf("Client IP address:%s\n",inet_ntoa(ciaddr));
    printf("Your(client) IP address:%s\n",inet_ntoa(yiaddr));
    printf("Next Server IP address:%s\n",inet_ntoa(siaddr));
    printf("Relay agent IP address:%s\n",inet_ntoa(giaddr));

    if(htype == 1)
    {
	    struct ether_addr chaddr_mac;
        memcpy(&chaddr_mac,dhcp_p->chaddr,hlen);
        printf("Client MAC address:  %s\n",ether_ntoa(&chaddr_mac));
    }
   
    if(magic_cookie == DHCP_MAGIC_COOKIE) 
        printf("Magic cookie:DHCP(0x%08x)\n",magic_cookie);
    else
        printf("Magic cookie:[error]\n");
    
    // option analysis
    uint8_t *opt_p = dhcp_p->option;
    uint8_t opt_length;
    uint8_t option[256];
    while(*opt_p != 0xff)
    {
        printf("-Option:(%d) ",*opt_p);
        switch(*opt_p)
        {
            case DHCP_OPT_MASK:
            {
                printf("Subnet Mask\n");
                opt_p++;
                opt_length = *opt_p;
                memcpy(option,opt_p+1,opt_length);
                opt_p += opt_length;
                printf(" Length:%d\n",opt_length);
                struct in_addr *mask = (struct in_addr*)option;
                printf(" Mask:%s\n",inet_ntoa(*mask));
                break;
            }
            case DHCP_OPT_ROUTER:
            {
                printf("Router\n");
                opt_p++;
                opt_length = *opt_p;
                memcpy(option,opt_p+1,opt_length);
                opt_p += opt_length;
                printf(" Length:%d\n",opt_length);
                struct in_addr *router = (struct in_addr*)option;
                for(int i = 0; i < opt_length; i += 4)
                {
                    printf(" Router:%s\n",inet_ntoa(*router));
                    router++;
                }
                break;
            }
            case DHCP_OPT_NAMESERVER:
            { 
                printf("Domain Name Server\n");
                opt_p++;
                opt_length = *opt_p;
                memcpy(option,opt_p+1,opt_length);
                opt_p += opt_length;
                printf(" Length:%d\n",opt_length);
                struct in_addr *server = (struct in_addr*)option;
                for(int i = 0; i < opt_length; i += 4)
                {
                    printf(" Domain Name Server:%s\n",inet_ntoa(*server));
                    server++;    
                }
                break; 
            }
            case DHCP_OPT_HOSTNAME:
            {
                printf("Host Name\n");
                opt_p++;
                opt_length = *opt_p;
                memcpy(option,opt_p+1,opt_length);
                opt_p += opt_length;
                printf(" Length:%d\n",opt_length);
                option[opt_length] = '\0';
                printf(" Host Name:%s\n",option);
                break; 
            }
            case DHCP_OPT_REQUESTEDIP:
            {
                printf("Requested IP Address\n");
                opt_p++;
                opt_length = *opt_p;
                memcpy(option,opt_p+1,opt_length);
                opt_p += opt_length;
                printf(" Length:%d\n",opt_length);
                struct in_addr *addr = (struct in_addr*)option;
                printf(" IP Address:%s\n",inet_ntoa(*addr));
                break; 
            }
            case DHCP_OPT_LEASETIME:
            {
                printf("IP Address Lease Time\n");
                opt_p++;
                opt_length = *opt_p;
                memcpy(option,opt_p+1,opt_length);
                opt_p += opt_length;
                printf(" Length:%d\n",opt_length);
                uint32_t *time = (uint32_t*)option;
                printf(" Lease Time:%d s\n",ntohl(*time));
                break; 
            }
            case DHCP_OPT_MSGTYPE:
            { 
                printf("DHCP Message type\n");
                opt_p++;
                opt_length = *opt_p;
                memcpy(option,opt_p+1,opt_length);
                opt_p += opt_length;
                printf(" Length:%d\n",opt_length);
                switch(option[0])
                {
                    case 1:
                        printf(" DHCP Discover\n");
                        break;
                    case 2:
                        printf(" DHCP Offer\n");
                        break;
                    case 3:
                        printf(" DHCP Request\n");
                        break;
                    case 5:
                        printf(" DHCP ACK\n");
                        break;
                    case 7:
                        printf(" DHCP Release\n");
                        break;
                    case 8:
                        printf(" DHCP Inform\n");
                        break;
                    default:
                        break;    
                }
                break;
            }
            case DHCP_OPT_SERVERID:
            {
                printf("DHCP Server Identifier\n");
                opt_p++;
                opt_length = *opt_p;
                memcpy(option,opt_p+1,opt_length);
                opt_p += opt_length;
                printf(" Length:%d\n",opt_length);
                struct in_addr *server_id = (struct in_addr*)option;
                printf(" Identifier:%s\n",inet_ntoa(*server_id));
                break;
            }
            case DHCP_OPT_PARAMLIST:
            {
                printf("Parameter Request List\n");
                opt_p++;
                opt_length = *opt_p;
                memcpy(option,opt_p+1,opt_length);
                opt_p += opt_length;
                printf(" Length:%d\n",opt_length);
                uint8_t *param_p = (uint8_t*)option;
                for(int i = 0; i < opt_length; i++)
                {
                    printf(" Parameter:%d\n",*param_p);
                    param_p++;    
                }
                break; 
            }
            case DHCP_OPT_RENEWALTIME:
            {
                printf("Renewal Time Value\n");
                opt_p++;
                opt_length = *opt_p;
                memcpy(option,opt_p+1,opt_length);
                opt_p += opt_length;
                printf(" Length:%d\n",opt_length);
                uint32_t *time = (uint32_t*)option;
                printf(" Time Value:%u s\n",ntohl(*time));
                break; 
            }
            case DHCP_OPT_REBINDINGTIME:
            {
                printf("Rebinding Time Value\n");
                opt_p++;
                opt_length = *opt_p;
                memcpy(option,opt_p+1,opt_length);
                opt_p += opt_length;
                printf(" Length:%d\n",opt_length);
                uint32_t *time = (uint32_t*)option;
                printf(" Time Value:%u s\n",ntohl(*time));
                break; 
            }
            case DHCP_OPT_VENDOR:
            {
                printf("Vendor Class Identifier\n");
                opt_p++;
                opt_length = *opt_p;
                memcpy(option,opt_p+1,opt_length);
                opt_p += opt_length;
                printf(" Length:%d\n",opt_length);
                option[opt_length] = '\0';
                printf(" Identifier:%s\n",option);
                break; 
            }
            case DHCP_OPT_CLIENTID:
            {
                printf("Client Identider\n");
                opt_p++;
                opt_length = *opt_p;
                memcpy(option,opt_p+1,opt_length);
                opt_p += opt_length;
                printf(" Length:%d\n",opt_length);
                if(*option == 1)
                {
                    printf(" Hardware type:Ethernet (0x01)\n");
                    printf(" Client MAC Address:  %s\n",
                            ether_ntoa((struct ether_addr*)(option+1)));
                }
                break; 
            }
            case DHCP_OPT_CLIENTNAME:
            {
                printf("Client Fully Qualified Domain Name\n");
                opt_p++;
                opt_length = *opt_p;
                memcpy(option,opt_p+1,opt_length);
                opt_p += opt_length;
                printf(" Length:%d\n",opt_length);
                uint8_t flags = option[0];
                uint8_t a_rr = option[1];
                uint8_t ptr_rr = option[2];
                option[opt_length] = '\0';
                printf(" Flags:0x%02x\n",flags);
                printf(" A_RR result:%d\n",a_rr);
                printf(" PTR_RR result:%d\n",ptr_rr);
                printf(" Client name:%s\n",option + 3);
                break; 
            }
            default:
                printf("Other\n");
                opt_p++;
                opt_length = *opt_p;
                opt_p += opt_length;
                printf(" Length:%d\n",opt_length);
                break;
        }
        opt_p++;
    }
} 

void ripAnalyzer(char * pkt, uint16_t length) //<protocols/routed.h>
{
    struct rip *rip_p = (struct rip*)pkt;
    uint8_t cmd = rip_p->rip_cmd;
    uint8_t vers = rip_p->rip_vers;
    struct netinfo *nets = rip_p->rip_nets;
    uint16_t nets_num = (length - 4) / sizeof(struct netinfo);

    switch(cmd)
    {
        case RIPCMD_REQUEST:
            printf("Command: Request(1)\t");
            break;
        case RIPCMD_RESPONSE:
            printf("Command: Response(2)\t");
            break;
        case RIPCMD_TRACEON:
        case RIPCMD_TRACEOFF:
        default:
            break;    
    }
    printf("Version:RIPv%d (%d)\n",vers,vers);
    for(int i = 0; i < nets_num; i++)
    {
        unsigned short family = ntohs(nets->rip_dst.sa_family);
        struct in_addr dst_addr;
        memcpy(&dst_addr,&(nets->rip_dst.sa_data[2]), sizeof(struct in_addr));
        int metric = nets->rip_metric;    
        printf("Family: IP(%d)   ",family);
        printf("Address: %s\n",inet_ntoa(dst_addr));
    }

}
