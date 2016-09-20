#ifndef PCAP_H
#define PCAP_H

typedef unsigned int bpf_u_int32;
typedef unsigned short u_short;
typedef int bpf_int32;
typedef unsigned char u_int8_t;
typedef unsigned short int u_int16_t;
typedef unsigned int u_int32_t;

typedef struct pcap_file_header
{
	bpf_u_int32 magic;
	u_short version_major;
	u_short version_minor;
	bpf_int32 thiszone;
	bpf_u_int32 sigfigs;
	bpf_u_int32 snaplen;
	bpf_u_int32 linktype;
}pcap_file_header;

typedef struct pcap_timestamp
{
	bpf_u_int32 timestamp_s;
	bpf_u_int32 timestamp_ms;
}pcap_timestamp;

typedef struct pcap_pkthdr
{
	pcap_timestamp ts;
	bpf_u_int32 caplen;
	bpf_u_int32 len;
}pcap_pkthdr;

#endif
