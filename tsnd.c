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
#include "bridge/bridge_forwarding.h"


#define PACKLEN (64*1024)

char str[4096];

struct HandlerTable_table handlerTable;
struct Port *ports;
uint32_t portCnt;
struct pollfd *pollFds;
struct BridgeForwarding_state bridgeForwardingState;


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
    struct BridgeForwarding_ruleset rs;
    struct BridgeForwarding_vlanRule vr[2];
    struct BridgeForwarding_macRule fr[1], sr[0];
    enum BridgeForwarding_action *allEnActs, *allDisActs, *allUnActs, *acts1, *acts2;
    int32_t i;
    uint8_t macMask[ETHERNET_MAC_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t macMVRP[ETHERNET_MAC_LEN] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x21};

    if(BridgeForwarding_init(&bridgeForwardingState, handlerTable, ports, portCnt) != 0)
        exit(1);

    memset(&rs, 0, sizeof(struct BridgeForwarding_ruleset));
    allEnActs = calloc(portCnt, sizeof(enum BridgeForwarding_action));
    allDisActs = calloc(portCnt, sizeof(enum BridgeForwarding_action));
    allUnActs = calloc(portCnt, sizeof(enum BridgeForwarding_action));
    acts1 = calloc(portCnt, sizeof(enum BridgeForwarding_action));
    acts2 = calloc(portCnt, sizeof(enum BridgeForwarding_action));
    rs.portDefaultVLANs = calloc(portCnt, sizeof(uint16_t));
    if(allEnActs == NULL || allDisActs == NULL || allUnActs == NULL || rs.portDefaultVLANs == NULL || acts1 == NULL || acts2 == NULL)
        exit(1);

    for(i = 0; i < portCnt; i++)
    {
        allEnActs[i] = BridgeForwarding_action_Forward;
        allDisActs[i] = BridgeForwarding_action_Filter;
        allUnActs[i] = BridgeForwarding_action_NextStage;
        acts1[i] = BridgeForwarding_action_NextStage;
        acts2[i] = BridgeForwarding_action_Filter;
        rs.portDefaultVLANs[i] = 1;
    }
    rs.portDefaultVLANs[0] = 4;
    acts1[0] = BridgeForwarding_action_Filter;
    acts2[0] = BridgeForwarding_action_Forward;

    vr[0].vid = 1;
    vr[0].portActions = allEnActs;
    vr[0].allIndividualActions = allUnActs;
    vr[0].allGroupActions = allUnActs;
    vr[0].allUnregisteredIndividualActions = allUnActs;
    vr[0].allUnregisteredGroupActions = acts1;
    vr[1].vid = 4;
    vr[1].portActions = allEnActs;
    vr[1].allIndividualActions = allUnActs;
    vr[1].allGroupActions = allUnActs;
    vr[1].allUnregisteredIndividualActions = allUnActs;
    vr[1].allUnregisteredGroupActions = allUnActs;
    rs.vlans = vr;
    rs.vlanCnt = sizeof(vr) / sizeof(struct BridgeForwarding_vlanRule);

    memcpy(fr[0].mac, macMVRP, ETHERNET_MAC_LEN);
    memcpy(fr[0].macMask, macMask, ETHERNET_MAC_LEN);
    fr[0].vid = 4;
    fr[0].vidMask = 0;//ETHERNET_VID_MASK;
    fr[0].portActions = acts2;
    fr[0].prio = 0;
    rs.firstStageRules = fr;
    rs.firstStageRuleCnt = sizeof(fr) / sizeof(struct BridgeForwarding_macRule);

    rs.secondStageRules = sr;
    rs.secondStageRuleCnt = sizeof(sr) / sizeof(struct BridgeForwarding_macRule);

    if(BridgeForwarding_updateRuleset(&bridgeForwardingState, &rs) != 0)
        exit(1);

    free(allEnActs);
    free(allDisActs);
    free(allUnActs);
    free(acts1);
    free(acts2);
    free(rs.portDefaultVLANs);
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
    while((c = getopt(argc, argv, "hbi:")) > 0)
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
        puts("initing in bridgemode");
        init_bridgenode(&handlerTable, ports, portCnt);
    }
    else
    {
        puts("initing in nodemode");
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

