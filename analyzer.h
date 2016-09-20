
#ifndef ANALYZER_H
#define ANALYZER_H 1

#include <netinet/ip.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>

struct icmp_ipdata
{
    struct ip ip_hdr;
    uint16_t sport;
    uint16_t dport;
    union ipdata_un
    {
        uint32_t seq;
        struct 
        {
            uint16_t length;
            uint16_t checksum;    
        } udp_hdr;
    } ipdata_un;
};

struct dhcp_pkt
{
    uint8_t msg;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;

    uint32_t xid;

    uint16_t secs;
    uint16_t flags;

    struct in_addr ciaddr;
    struct in_addr yiaddr;
    struct in_addr siaddr;
    struct in_addr giaddr;

    u_char chaddr[16];
    u_char sname[64];
    u_char file[128];

    uint32_t magic_cookie;
    u_char option[1];  //variable , here is the first byte of option  
};

#define DHCP_MSG_REQUEST 1
#define DHCP_MSG_REPLY 2

#define DHCP_MAGIC_COOKIE 0x63825363

#define DHCP_OPT_MASK 1
#define DHCP_OPT_ROUTER 3
#define DHCP_OPT_NAMESERVER 6
#define DHCP_OPT_HOSTNAME 12
#define DHCP_OPT_REQUESTEDIP 50
#define DHCP_OPT_LEASETIME 51
#define DHCP_OPT_MSGTYPE 53
#define DHCP_OPT_SERVERID 54
#define DHCP_OPT_PARAMLIST 55
#define DHCP_OPT_RENEWALTIME 58
#define DHCP_OPT_REBINDINGTIME 59
#define DHCP_OPT_VENDOR 60
#define DHCP_OPT_CLIENTID 61
#define DHCP_OPT_CLIENTNAME 81
#define DHCP_OPT_END 255
/*

struct ospf_hdr
{
    uint8_t version;
    uint8_t type;
    uint16_t pkt_len;

    uint32_t router_id;
    uint32_t area_id;

    uint16_t checksum;
    uint16_t au_type;
    uint8_t au_data[8];
};

#define OSPF_TYPE_HELLO 1
#define OSPF_TYPE_DD 2
#define OSPF_TYPE_LSR 3
#define OSPF_TYPE_LSU 4
#define OSPF_TYPE_LSACK 5

#define OSPF_AU_NULL 0
#define OSPF_AU_SIMPLE 1
#define OSPF_AU_MD5 2

struct ospf_lsa_hdr
{
    uint16_t age;
    uint8_t options;
    uint8_t ls_type;

    struct in_addr ls_id;
    struct in_addr adv_rtr;

    uint32_t sequence;
    uint16_t checksum;
    uint16_t length;
};

struct ospf_lsa
{
    struct ospf_lsa_hdr header;
    uint8_t flags;
    uint16_t links_num;
    struct
    {
        struct in_addr id;
        struct in_addr data;
        uint8_t link_type;
        uint16_t metric_num;
        uint16_t metric;  
    } links[1];  
};

struct ospf_pkt
{
    struct ospf_hdr header;
    union
    {
        struct
        {
            uint32_t mask;
            uint16_t interval;
            uint8_t options;
            uint8_t rtr_pri;
            uint32_t dead_interval;

            struct in_addr dr;
            struct in_addr bdr;
            struct in_addr peer;
        } hello;
        struct 
        {
            uint16_t mtu;
            uint8_t options;
            uint8_t description;
            uint32_t sequence;
            struct ospf_lsa_hdr hdr[1];  //variable
        } dd;
        struct 
        {
            uint32_t type;
            uint32_t id;
            struct in_addr adv_rtr;
        } lsr[1];
        struct
        {
            uint32_t num;
            struct ospf_lsa lsa[1];
        } lsu;
        struct 
        {
            
        } lsack;  
    } packet;    
};

*/

int ipAnalyzer(char * pkt);

int arpAnalyzer(char * pkt);

int tcpAnalyzer(char * pkt);

int udpAnalyzer(char * pkt);

void dhcpAnalyzer(char * pkt);

void ripAnalyzer(char * pkt, uint16_t length);
#endif
