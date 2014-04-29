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
#include <poll.h>

#include <pcap/pcap.h>


#include "handler_table.h"
#include "ptp/simple_gptp_handler.h"
#include "port.h"
#include "packet.h"


#define PACKLEN 2048

char str[4096];

struct HandlerTable_table handlerTable;
struct Port *ports;
uint32_t portCnt;
struct pollfd *pollFds;


void help(void)
{
    exit(1);
}

/*
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
*/

int main(int argc, char **argv)
{
    pcap_t* handle = NULL;
    struct bpf_program comp_filter_exp;
    
    char **devList = NULL;
    int devListSize = 0, devListCnt = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
    char *filter_exp = "";
    int32_t resu;

    int cnt;
    struct Packet_packet p;

    int c;
    while((c = getopt(argc, argv, "hi:")) > 0) 
    {
        switch (c) 
        {
        case 'h': 
            help();
            break;
        case 'i':
            if(devListCnt >= devListSize)
            {
                devListSize += 16;
                devList = realloc(devList, devListSize * sizeof(char*));
                if(devList == NULL)
                {
                    fprintf(stderr, "could not allocate memory (devList)\n");
                    return -1;
                }
            }
            devList[devListCnt++] = strdup(optarg);
            break;
        default:
            fprintf(stderr, "Unrecognized option!\n");
            break;
        }
    }
    
    // init packet buffer
    p.packet = malloc(PACKLEN);
    if(p.packet == NULL)
    {
        fprintf(stderr, "could not allocate memory (packet)");
    }

    // init handler table
    handlerTable.cnt = 0;
    handlerTable.firstEntry = NULL;

    portCnt = devListCnt;
    ports = malloc(sizeof(struct Port) * portCnt);
    if(ports == NULL)
    {
        fprintf(stderr, "could not allocate memory (ports)\n");
        return -1;
    }
    pollFds = malloc(sizeof(struct pollfd) * portCnt);
    if(pollFds == NULL)
    {
        fprintf(stderr, "could not allocate memory (pollFds)\n");
    }
    for(int i = 0; i < devListCnt; i++)
    {
        resu = Port_open(devList[i], &(ports[i]));
        if(resu != 0)
        {
            fprintf(stderr, "could not open device %s (%d)\n", devList[i], resu);
            return -1;
        }
        pollFds[i].fd = ports[i].rawFd;
        pollFds[i].events = POLLIN | POLLPRI;
        fprintf(stdout, "opened device %s (%d)\n", devList[i], ports[i].ifIdx);
    }

    SimpleGPTPHandler_init(&handlerTable, ports, portCnt);

    puts("registered handler");

    while(1)
    {
        // handle packets
        cnt = poll(pollFds, portCnt, -1);
        if(cnt == 0)
            continue;
        if(cnt < 0)
        {
            fprintf(stderr, "error while polling\n");
        }
        for(int i = 0; i < portCnt; i++)
        {
            if((pollFds[i].revents & (POLLIN | POLLPRI)) != 0)
            {
                p.len = PACKLEN;
                resu = Port_recv(&(ports[i]), &p);
                if(resu == 0)
                {
                    fprintf(stdout, "got one on %s (l=%d)\n", ports[i].devName, p.len);
                    HandlerTable_handlePacket(&handlerTable, &p);
                }
                else
                    fprintf(stderr, "error (%d)\n", resu);
            }
            else if((pollFds[i].revents & POLLERR) != 0)
                fprintf(stderr, "device %s has error\n", ports[i].devName);
        }
    }
    /*
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
    */
	puts("ending...");

    return 0;
}

