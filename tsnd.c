/*
 * main.c
 * 
 * Copyright 2014 Jasper Salathe
 * 
 * 
 */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>

#include <pcap/pcap.h>


#include "handler_table.h"
#include "ptp/simple_gptp_handler.h"
#include "port.h"
#include "packet.h"

char str[4096];

struct HandlerTable_table handlerTable;
struct Port *ports;
uint32_t portCnt;

void help(void)
{
    exit(1);
}

void pcap_callback(u_char* args, const struct pcap_pkthdr* packet_header, const u_char* packet)
{
    struct Packet_packet p;
    p.port = 1;
    p.len = packet_header->len;
    p.packet = malloc(p.len);
    if(p.packet == NULL)
        return;
    memcpy(p.packet, packet, p.len);
    p.t.t.tv_sec = packet_header->ts.tv_sec;
    p.t.t.tv_nsec = packet_header->ts.tv_usec * 1000;
    HandlerTable_handlePacket(&handlerTable, &p);
    free(p.packet);
}

int main(int argc, char **argv)
{
    pcap_t* handle = NULL;
    struct bpf_program comp_filter_exp;
    
    char *dev = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
    char *filter_exp = "";
    
    int c;
    while((c = getopt(argc, argv, "hi:")) > 0) 
    {
        switch (c) 
        {
        case 'h': 
            help();
            break;
        case 'i':
            dev = strdup(optarg);
            break;
        default:
            fprintf(stderr, "Unrecognized option!\n");
            break;
        }
    }
    
    // init handler table
    handlerTable.cnt = 0;
    handlerTable.firstEntry = NULL;

    portCnt = 1;
    ports = malloc(sizeof(struct Port) * portCnt);
    if(ports == NULL)
    {
        fprintf(stderr, "could not allocate memory\n");
        return -1;
    }
    ports[0].devName = (uint8_t*)dev;
    ports[0].portIdx = 0;
    memset(ports[0].macAddr, 0, ETHERNET_MAC_LEN);

    SimpleGPTPHandler_init(&handlerTable, ports, portCnt);

    puts("registered handler");

    handle = pcap_open_live(dev, BUFSIZ, 1, -1, errbuf);
	if (NULL == handle) 
	{
		fprintf(stderr, "Could not open device %s: %s\n", dev, errbuf);
		return -1;
	}

	if (-1 == pcap_compile(handle, &comp_filter_exp, filter_exp, 0, PCAP_NETMASK_UNKNOWN))
	{
		fprintf(stderr, "Could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return -1;
	}

	if (-1 == pcap_setfilter(handle, &comp_filter_exp)) 
	{
		fprintf(stderr, "Could not install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return -1;
	}

	puts("startup successful");

	pcap_loop(handle, -1, pcap_callback, NULL);
    
	puts("ending...");

    return 0;
}

