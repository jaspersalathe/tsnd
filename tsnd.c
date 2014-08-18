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


void help(char *myname)
{
	fprintf(stdout, "Usage:\n%s [-b] -i <interface>\n", myname);
	fputs("Options:\n", stdout);
	fputs(" -i: interface to be used; multiple occurrence possible\n", stdout);
	fputs(" -b: start in bridge mode (will run bridge)\n", stdout);
	fputs(" -h: show this help\n", stdout);
    exit(1);
}

void init_endnode(struct HandlerTable_table *handlerTable, struct Port *ports, uint32_t portCnt)
{
    if(SimpleGPTPHandler_init(handlerTable, ports, portCnt) != 0)
        exit(1);
}

void init_bridgenode(struct HandlerTable_table *handlerTable, struct Port *ports, uint32_t portCnt)
{

}


int main(int argc, char **argv)
{
    char **devList = NULL;
    int devListSize = 0, devListCnt = 0;
    int32_t resu;

    int cnt;
    struct Packet_packet p;

    int bridgemode = 0;

    int c;
    while((c = getopt(argc, argv, "hib:")) > 0)
    {
        switch (c) 
        {
        case 'h': 
            help(argv[0]);
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
        case 'b':
        	bridgemode = 1;
        	break;
        default:
            fprintf(stderr, "Unrecognized option!\n");
            help(argv[0]);
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
        ports[i].portIdx = i;
        resu = Port_open(devList[i], &(ports[i]));
        if(resu != 0)
        {
            fprintf(stderr, "could not open device %s (%d)\n", devList[i], resu);
            return -1;
        }
        pollFds[i].fd = ports[i].rawFd;
        pollFds[i].events = POLLIN | POLLPRI;
        fprintf(stdout, "opened device %s (idx=%d, mac=%02X:%02X:%02X:%02X:%02X:%02X)\n",
                devList[i], ports[i].ifIdx, ports[i].macAddr[0], ports[i].macAddr[1], ports[i].macAddr[2],
                ports[i].macAddr[3], ports[i].macAddr[4], ports[i].macAddr[5]);
    }

    if(bridgemode)
    {
        init_bridgenode(&handlerTable, ports, portCnt);
    }
    else
    {
        init_endnode(&handlerTable, ports, portCnt);
    }

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
            return -1;
        }
        for(int i = 0; i < portCnt; i++)
        {
            if((pollFds[i].revents & (POLLIN | POLLPRI)) != 0)
            {
                p.len = PACKLEN;
                resu = Port_recv(&(ports[i]), &p);
                if(resu == 0)
                {
//                    memset(str, 0, sizeof(str));
//                    for(int j = 0; j < p.len; j++)
//                    {
//                        char cur[8];
//                        snprintf(cur, sizeof(cur), "%02X ", p.packet[j]);
//                        strcat(str, cur);
//                    }
//                    fprintf(stdout, "got one on %s (l=%d, p='%s')\n", ports[i].devName, p.len, str);
                    HandlerTable_handlePacket(&handlerTable, &p);
                }
                else
                    fprintf(stderr, "error (%d)\n", resu);
            }
            else if((pollFds[i].revents & POLLERR) != 0)
                fprintf(stderr, "device %s has error\n", ports[i].devName);
        }
    }

	puts("ending...");

    return 0;
}

