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
#include "bridge/filtering_db.h"


#define PACKLEN (64*1024)

char str[4096];

struct HandlerTable_table handlerTable;
struct Port *ports;
uint32_t portCnt;
struct pollfd *pollFds;
struct BridgeForwarding_state bfState;
struct FDB_state fdbState;


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

/*
 * Testcase:
 *  vlan 1: untagged on port 1; allowed on all ports
 *  vlan 4: untagged on port 0; allowed on all ports
 *
 *  default behavior:
 *   - All Group: forward on all ports
 *   - All Unregistered Group: dynamic(next stage) on all ports
 *   - All Individual: dynamic(next stage) on all ports
 *
 *  filter all STP frames on all ports
 */
void init_bridgenode_testBridgeForwarding(struct HandlerTable_table *handlerTable, struct Port *ports, uint32_t portCnt)
{
    struct BridgeForwarding_ruleset rs;
    struct BridgeForwarding_vlanRule vr[2];
    struct BridgeForwarding_macRule fr[1], sr[0];
    enum BridgeForwarding_action *allEnActs, *allDisActs, *allUnActs, *acts1, *acts2;
    int32_t i;
    uint8_t macMask[ETHERNET_MAC_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t macSTP[ETHERNET_MAC_LEN] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x00};

    if(BridgeForwarding_init(&bfState, handlerTable, ports, portCnt) != 0)
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
    vr[0].allGroupActions = allEnActs;
    vr[0].allUnregisteredGroupActions = allUnActs;
    vr[1].vid = 4;
    vr[1].portActions = allEnActs;
    vr[1].allIndividualActions = allUnActs;
    vr[1].allGroupActions = allEnActs;
    vr[1].allUnregisteredGroupActions = allUnActs;
    rs.vlans = vr;
    rs.vlanCnt = sizeof(vr) / sizeof(struct BridgeForwarding_vlanRule);

    memcpy(fr[0].mac, macSTP, ETHERNET_MAC_LEN);
    memcpy(fr[0].macMask, macMask, ETHERNET_MAC_LEN);
    fr[0].vid = 4;
    fr[0].vidMask = 0;//ETHERNET_VID_MASK;
    fr[0].portActions = acts1;
    fr[0].prio = 0;
    rs.firstStageRules = fr;
    rs.firstStageRuleCnt = sizeof(fr) / sizeof(struct BridgeForwarding_macRule);

    rs.secondStageRules = sr;
    rs.secondStageRuleCnt = sizeof(sr) / sizeof(struct BridgeForwarding_macRule);

    if(BridgeForwarding_updateRuleset(&bfState, &rs) != 0)
        exit(1);

    BridgeForwarding_printCurRuleset(&bfState);

    free(allEnActs);
    free(allDisActs);
    free(allUnActs);
    free(acts1);
    free(acts2);
    free(rs.portDefaultVLANs);
}

/*
 * Testcase:
 *  vlan 1: untagged on all ports except port 0; allowed on all ports
 *  vlan 4: untagged on port 0; allowed on all ports
 *
 *  default behavior:
 *   - All Group: forward on all ports
 *   - All Unregistered Group: dynamic(next stage) on all ports
 *   - All Individual: dynamic(next stage) on all ports
 *
 *  filter all STP frames on all ports
 *
 * Results in rules:
 *  - StaticVLAN: vlan 1, untagged on all ports except port 0, allowed on all ports
 *  - StaticVLAN: vlan 4, untagged on port 0, allowed on all ports
 *  - StaticRegistration: STP mac, wildcard vid, filter on all ports
 */
void init_bridgenode_testFDB1(struct HandlerTable_table *handlerTable, struct Port *ports, uint32_t portCnt)
{
    struct FDB_rule r;
    struct FDB_PortMapEntry *pm = calloc(portCnt, sizeof(struct FDB_PortMapEntry));

    uint32_t i;

    uint8_t macSTP[ETHERNET_MAC_LEN] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x00};

    if(pm == NULL)
        exit(1);

    if(BridgeForwarding_init(&bfState, handlerTable, ports, portCnt) != 0)
        exit(1);
    BridgeForwarding_printCurRuleset(&bfState);

    if(FDB_init(&fdbState, portCnt) != 0)
        exit(1);

    r.type = FDB_RuleType_StaticVLANRegistration;
    r.rule.staticVLANRegistration.vid = 1;
    for(i = 0; i < portCnt; i++)
    {
        pm[i].filter = FDB_PortMapResult_Forward;
        pm[i].forwardUntagged = 1;
    }
    pm[0].forwardUntagged = 0;
    r.rule.staticVLANRegistration.portMap = pm;
    if(FDB_addRule(&fdbState, &r) != 0)
        exit(1);

    r.type = FDB_RuleType_StaticVLANRegistration;
    r.rule.staticVLANRegistration.vid = 4;
    for(i = 0; i < portCnt; i++)
    {
        pm[i].filter = FDB_PortMapResult_Forward;
        pm[i].forwardUntagged = 0;
    }
    pm[0].forwardUntagged = 1;
    r.rule.staticVLANRegistration.portMap = pm;
    if(FDB_addRule(&fdbState, &r) != 0)
        exit(1);


    // add static mac rule for stp (01:80:c2:00:00:00; filter all)
    r.type = FDB_RuleType_StaticFiltering;
    memcpy(r.rule.staticFiltering.mac, macSTP, ETHERNET_MAC_LEN);
    r.rule.staticFiltering.addrType = FDB_AddressType_Group;
    r.rule.staticFiltering.vid = ETHERNET_VID_WILDCARD;
    for(i = 0; i < portCnt; i++)
        pm[i].filter = FDB_PortMapResult_Filter;
    r.rule.staticFiltering.portMap = pm;
    if(FDB_addRule(&fdbState, &r) != 0)
        exit(1);

    // update ruleset in BridgeForwarding
    if(FDB_updateBridgeForwarding(&fdbState, &bfState) != 0)
        exit(1);
    BridgeForwarding_printCurRuleset(&bfState);

    free(pm);
}

/*
 * Testcase:
 *  vlan 1: untagged on all ports; allowed on all ports
 *  vlan 4: untagged on no ports; allowed on all ports
 *
 *  default behavior:
 *   - All Group: forward on all ports
 *   - All Unregistered Group: dynamic(next stage) on all ports
 *   - All Individual: dynamic(next stage) on all ports
 *
 *  filter all STP frames on all ports
 *
 * Results in rules:
 *  - StaticVLAN: vlan 1, untagged on all ports, allowed on all ports
 *  - DynamicVLAN: vlan 4, untagged on no ports, allowed on all ports
 *  - StaticRegistration: STP mac, wildcard vid, filter on all ports
 */
void init_bridgenode_testFDB2(struct HandlerTable_table *handlerTable, struct Port *ports, uint32_t portCnt)
{
    struct FDB_rule r;
    struct FDB_PortMapEntry *pm = calloc(portCnt, sizeof(struct FDB_PortMapEntry));

    uint32_t i;

    uint8_t macSTP[ETHERNET_MAC_LEN] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x00};

    if(pm == NULL)
        exit(1);

    if(BridgeForwarding_init(&bfState, handlerTable, ports, portCnt) != 0)
        exit(1);
    BridgeForwarding_printCurRuleset(&bfState);

    if(FDB_init(&fdbState, portCnt) != 0)
        exit(1);

    r.type = FDB_RuleType_StaticVLANRegistration;
    r.rule.staticVLANRegistration.vid = 1;
    for(i = 0; i < portCnt; i++)
    {
        pm[i].filter = FDB_PortMapResult_Forward;
        pm[i].forwardUntagged = 1;
    }
    r.rule.staticVLANRegistration.portMap = pm;
    if(FDB_addRule(&fdbState, &r) != 0)
        exit(1);

    r.type = FDB_RuleType_DynamicVLANRegistration;
    r.rule.dynamicVLANRegistration.vid = 4;
    for(i = 0; i < portCnt; i++)
    {
        pm[i].filter = FDB_PortMapResult_Forward;
    }
    r.rule.dynamicVLANRegistration.portMap = pm;
    if(FDB_addRule(&fdbState, &r) != 0)
        exit(1);


    // add static mac rule for stp (01:80:c2:00:00:00; filter all)
    r.type = FDB_RuleType_StaticFiltering;
    memcpy(r.rule.staticFiltering.mac, macSTP, ETHERNET_MAC_LEN);
    r.rule.staticFiltering.addrType = FDB_AddressType_Group;
    r.rule.staticFiltering.vid = ETHERNET_VID_WILDCARD;
    for(i = 0; i < portCnt; i++)
        pm[i].filter = FDB_PortMapResult_Filter;
    r.rule.staticFiltering.portMap = pm;
    if(FDB_addRule(&fdbState, &r) != 0)
        exit(1);

    // update ruleset in BridgeForwarding
    if(FDB_updateBridgeForwarding(&fdbState, &bfState) != 0)
        exit(1);
    BridgeForwarding_printCurRuleset(&bfState);

    free(pm);
}

/*
 * Testcase:
 *  vlan 1: untagged on all ports; allowed on all ports
 *
 *  behavior:
 *   - All Group: forward on all ports
 *   - All Unregistered Group: dynamic(next stage) on all ports
 *   - All Individual: filter on all ports
 *
 *  filter all STP frames on all ports
 *  no unknown individual allowed
 *  known hosts:
 *   - host 1 [10:0b:a9:8a:c8:24] on port 1
 *   - host 2 [00:01:2e:27:66:c4] on port 0
 *   - host 3 [c0:25:06:99:e6:b2] on port 0
 *   - host 4 [64:66:b3:33:c1:83] on port 1
 *
 * Results in rules:
 *  - StaticVLAN: vlan 1, untagged on all ports, allowed on all ports
 *  - StaticRegistration: All Individual, vid 1, filter on all ports
 *  - StaticRegistration: STP mac, wildcard vid, filter on all ports
 *  - StaticRegistration: host1, vid 1, forward on port 1
 *  - StaticRegistration: host2, vid 1, forward on port 0
 *  - StaticRegistration: host3, vid 1, forward on port 0
 *  - StaticRegistration: host4, vid 1, forward on port 1
 */
void init_bridgenode_testFDB3(struct HandlerTable_table *handlerTable, struct Port *ports, uint32_t portCnt)
{

    struct FDB_rule r;
    struct FDB_PortMapEntry *pm = calloc(portCnt, sizeof(struct FDB_PortMapEntry));

    uint32_t i;

    uint8_t macSTP[ETHERNET_MAC_LEN] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x00};
    uint8_t macHost1[ETHERNET_MAC_LEN] = {0x10, 0x0b, 0xa9, 0x8a, 0xc8, 0x24};
    uint8_t macHost2[ETHERNET_MAC_LEN] = {0x00, 0x01, 0x2e, 0x27, 0x66, 0xc4};
    uint8_t macHost3[ETHERNET_MAC_LEN] = {0xc0, 0x25, 0x06, 0x99, 0xe6, 0xb2};
    uint8_t macHost4[ETHERNET_MAC_LEN] = {0x64, 0x66, 0xb3, 0x33, 0xc1, 0x83};
//    uint8_t macHost5[ETHERNET_MAC_LEN] = {0x04, 0x7d, 0x7b, 0x65, 0x32, 0x4d}; currently not used

    if(pm == NULL)
        exit(1);

    if(BridgeForwarding_init(&bfState, handlerTable, ports, portCnt) != 0)
        exit(1);
    BridgeForwarding_printCurRuleset(&bfState);

    if(FDB_init(&fdbState, portCnt) != 0)
        exit(1);

    r.type = FDB_RuleType_StaticVLANRegistration;
    r.rule.staticVLANRegistration.vid = 1;
    for(i = 0; i < portCnt; i++)
    {
        pm[i].filter = FDB_PortMapResult_Forward;
        pm[i].forwardUntagged = 1;
    }
    r.rule.staticVLANRegistration.portMap = pm;
    if(FDB_addRule(&fdbState, &r) != 0)
        exit(1);

    // add static mac rule for stp (01:80:c2:00:00:00; filter all)
    r.type = FDB_RuleType_StaticFiltering;
    memcpy(r.rule.staticFiltering.mac, macSTP, ETHERNET_MAC_LEN);
    r.rule.staticFiltering.addrType = FDB_AddressType_Group;
    r.rule.staticFiltering.vid = ETHERNET_VID_WILDCARD;
    for(i = 0; i < portCnt; i++)
        pm[i].filter = FDB_PortMapResult_Filter;
    r.rule.staticFiltering.portMap = pm;
    if(FDB_addRule(&fdbState, &r) != 0)
        exit(1);

    // add static rule for all unregistered Individual Adresses (filter all)
    r.type = FDB_RuleType_StaticFiltering;
    r.rule.staticFiltering.addrType = FDB_AddressType_AllIndividual;
    r.rule.staticFiltering.vid = 1;
    for(i = 0; i < portCnt; i++)
        pm[i].filter = FDB_PortMapResult_Filter;
    r.rule.staticFiltering.portMap = pm;
    if(FDB_addRule(&fdbState, &r) != 0)
        exit(1);

    // add known devices
    r.type = FDB_RuleType_StaticFiltering;
    r.rule.staticFiltering.addrType = FDB_AddressType_Individual;
    memcpy(r.rule.staticFiltering.mac, macHost1, ETHERNET_MAC_LEN);
    r.rule.staticFiltering.vid = 1;
    for(i = 0; i < portCnt; i++)
        pm[i].filter = FDB_PortMapResult_Filter;
    pm[1].filter = FDB_PortMapResult_Forward;
    r.rule.staticFiltering.portMap = pm;
    if(FDB_addRule(&fdbState, &r) != 0)
        exit(1);

    r.type = FDB_RuleType_StaticFiltering;
    r.rule.staticFiltering.addrType = FDB_AddressType_Individual;
    memcpy(r.rule.staticFiltering.mac, macHost2, ETHERNET_MAC_LEN);
    r.rule.staticFiltering.vid = 1;
    for(i = 0; i < portCnt; i++)
        pm[i].filter = FDB_PortMapResult_Filter;
    pm[0].filter = FDB_PortMapResult_Forward;
    r.rule.staticFiltering.portMap = pm;
    if(FDB_addRule(&fdbState, &r) != 0)
        exit(1);

    r.type = FDB_RuleType_StaticFiltering;
    r.rule.staticFiltering.addrType = FDB_AddressType_Individual;
    memcpy(r.rule.staticFiltering.mac, macHost3, ETHERNET_MAC_LEN);
    r.rule.staticFiltering.vid = 1;
    for(i = 0; i < portCnt; i++)
        pm[i].filter = FDB_PortMapResult_Filter;
    pm[0].filter = FDB_PortMapResult_Forward;
    r.rule.staticFiltering.portMap = pm;
    if(FDB_addRule(&fdbState, &r) != 0)
        exit(1);

    r.type = FDB_RuleType_StaticFiltering;
    r.rule.staticFiltering.addrType = FDB_AddressType_Individual;
    memcpy(r.rule.staticFiltering.mac, macHost4, ETHERNET_MAC_LEN);
    r.rule.staticFiltering.vid = 1;
    for(i = 0; i < portCnt; i++)
        pm[i].filter = FDB_PortMapResult_Filter;
    pm[1].filter = FDB_PortMapResult_Forward;
    r.rule.staticFiltering.portMap = pm;
    if(FDB_addRule(&fdbState, &r) != 0)
        exit(1);

    // update ruleset in BridgeForwarding
    if(FDB_updateBridgeForwarding(&fdbState, &bfState) != 0)
        exit(1);
    BridgeForwarding_printCurRuleset(&bfState);

    free(pm);
}

/*
 * Testcase:
 *  vlan 1: untagged on all ports; allowed on all ports
 *
 *  behavior:
 *   - All Group: dynamic(next stage) on all ports
 *   - All Unregistered Group: dynamic(next stage) on all ports
 *   - All Individual: dynamic(next stage) on all ports
 *
 *  filter all group frames on all ports and explicit register wanted frames
 *  wanted group adresses:
 *   - Broadcast [ff:ff:ff:ff:ff:ff] on all ports
 *   - STP [01:80:c2:00:00:00] on all ports
 *   - IPv6 router solicitation [33:33:00:00:00:02] on port 1
 *   - SSDP [01:00:5e:7f:ff:fa] on port 0
 *  also some known hosts:
 *   - host 1 [10:0b:a9:8a:c8:24] on port 1
 *   - host 2 [00:01:2e:27:66:c4] on port 0
 *   - host 3 [c0:25:06:99:e6:b2] on port 0
 *   - host 4 [64:66:b3:33:c1:83] on port 1
 *
 *
 * Results in rules:
 *  - StaticVLAN: vlan 1, untagged on all ports, allowed on all ports
 *  - StaticRegistration: All Group, vid 1, dynamic on all ports
 *  - StaticRegistration: All Unregistered Group, vid 1, dynamic on all ports
 *  - StaticRegistration: Broadcast mac, vid 1, forward on all ports
 *  - MACAddressRegistration: STP mac, wildcard vid, forward on all ports
 *  - MACAddressRegistration: IPv6 router solicitation mac, vid 1, forward on port 1
 *  - DynamicReservation: SSDP mac, vid 1, forward on port 0
 *  - DynamicFiltering: host 1, vid 1, port 1
 *  - DynamicFiltering: host 2, vid 1, port 0
 *  - DynamicFiltering: host 3, vid 1, port 0
 *  - DynamicFiltering: host 4, vid 1, port 1
 */
void init_bridgenode_testFDB4(struct HandlerTable_table *handlerTable, struct Port *ports, uint32_t portCnt)
{
    struct FDB_rule r;
    struct FDB_PortMapEntry *pm = calloc(portCnt, sizeof(struct FDB_PortMapEntry));

    uint32_t i;

    uint8_t macSTP[ETHERNET_MAC_LEN] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x00};
    uint8_t macIPv6RS[ETHERNET_MAC_LEN] = {0x33, 0x33, 0x00, 0x00, 0x00, 0x02};
    uint8_t macBroadcast[ETHERNET_MAC_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint8_t macSSDP[ETHERNET_MAC_LEN] = {0x01, 0x00, 0x5e, 0x7f, 0xff, 0xfa};
    uint8_t macHost1[ETHERNET_MAC_LEN] = {0x10, 0x0b, 0xa9, 0x8a, 0xc8, 0x24};
    uint8_t macHost2[ETHERNET_MAC_LEN] = {0x00, 0x01, 0x2e, 0x27, 0x66, 0xc4};
    uint8_t macHost3[ETHERNET_MAC_LEN] = {0xc0, 0x25, 0x06, 0x99, 0xe6, 0xb2};
    uint8_t macHost4[ETHERNET_MAC_LEN] = {0x64, 0x66, 0xb3, 0x33, 0xc1, 0x83};

    if(pm == NULL)
        exit(1);

    if(BridgeForwarding_init(&bfState, handlerTable, ports, portCnt) != 0)
        exit(1);
    BridgeForwarding_printCurRuleset(&bfState);

    if(FDB_init(&fdbState, portCnt) != 0)
        exit(1);

    r.type = FDB_RuleType_StaticVLANRegistration;
    r.rule.staticVLANRegistration.vid = 1;
    for(i = 0; i < portCnt; i++)
    {
        pm[i].filter = FDB_PortMapResult_Forward;
        pm[i].forwardUntagged = 1;
    }
    r.rule.staticVLANRegistration.portMap = pm;
    if(FDB_addRule(&fdbState, &r) != 0)
        exit(1);

    r.type = FDB_RuleType_StaticFiltering;
    r.rule.staticFiltering.addrType = FDB_AddressType_AllGroup;
    r.rule.staticFiltering.vid = 1;
    for(i = 0; i < portCnt; i++)
        pm[i].filter = FDB_PortMapResult_Dynamic;
    r.rule.staticFiltering.portMap = pm;
    if(FDB_addRule(&fdbState, &r) != 0)
        exit(1);

    r.type = FDB_RuleType_StaticFiltering;
    r.rule.staticFiltering.addrType = FDB_AddressType_AllUnregGroup;
    r.rule.staticFiltering.vid = 1;
    for(i = 0; i < portCnt; i++)
        pm[i].filter = FDB_PortMapResult_Dynamic;
    r.rule.staticFiltering.portMap = pm;
    if(FDB_addRule(&fdbState, &r) != 0)
        exit(1);

    r.type = FDB_RuleType_StaticFiltering;
    r.rule.staticFiltering.addrType = FDB_AddressType_Group;
    memcpy(r.rule.staticFiltering.mac, macBroadcast, ETHERNET_MAC_LEN);
    r.rule.staticFiltering.vid = 1;
    for(i = 0; i < portCnt; i++)
        pm[i].filter = FDB_PortMapResult_Forward;
    r.rule.staticFiltering.portMap = pm;
    if(FDB_addRule(&fdbState, &r) != 0)
        exit(1);

    r.type = FDB_RuleType_MACAddressRegistration;
    r.rule.macAddressRegistration.addrType = FDB_AddressType_Group;
    memcpy(r.rule.macAddressRegistration.mac, macSTP, ETHERNET_MAC_LEN);
    r.rule.macAddressRegistration.vid = ETHERNET_VID_WILDCARD;
    for(i = 0; i < portCnt; i++)
        pm[i].filter = FDB_PortMapResult_Forward;
    r.rule.macAddressRegistration.portMap = pm;
    if(FDB_addRule(&fdbState, &r) != 0)
        exit(1);

    r.type = FDB_RuleType_MACAddressRegistration;
    r.rule.macAddressRegistration.addrType = FDB_AddressType_Group;
    memcpy(r.rule.macAddressRegistration.mac, macIPv6RS, ETHERNET_MAC_LEN);
    r.rule.macAddressRegistration.vid = 1;
    for(i = 0; i < portCnt; i++)
        pm[i].filter = FDB_PortMapResult_Filter;
    pm[1].filter = FDB_PortMapResult_Forward;
    r.rule.macAddressRegistration.portMap = pm;
    if(FDB_addRule(&fdbState, &r) != 0)
        exit(1);

    r.type = FDB_RuleType_DynamicReservation;
    memcpy(r.rule.dynamicReservation.mac, macSSDP, ETHERNET_MAC_LEN);
    r.rule.dynamicReservation.vid = 1;
    for(i = 0; i < portCnt; i++)
        pm[i].filter = FDB_PortMapResult_Filter;
    pm[0].filter = FDB_PortMapResult_Forward;
    r.rule.dynamicReservation.portMap = pm;
    if(FDB_addRule(&fdbState, &r) != 0)
        exit(1);

    // add known devices
    r.type = FDB_RuleType_DynamicFiltering;
    memcpy(r.rule.dynamicFiltering.mac, macHost1, ETHERNET_MAC_LEN);
    r.rule.dynamicFiltering.vid = 1;
    r.rule.dynamicFiltering.portMapPort = 1;
    if(FDB_addRule(&fdbState, &r) != 0)
        exit(1);

    r.type = FDB_RuleType_DynamicFiltering;
    memcpy(r.rule.dynamicFiltering.mac, macHost2, ETHERNET_MAC_LEN);
    r.rule.dynamicFiltering.vid = 1;
    r.rule.dynamicFiltering.portMapPort = 0;
    if(FDB_addRule(&fdbState, &r) != 0)
        exit(1);

    r.type = FDB_RuleType_DynamicFiltering;
    memcpy(r.rule.dynamicFiltering.mac, macHost3, ETHERNET_MAC_LEN);
    r.rule.dynamicFiltering.vid = 1;
    r.rule.dynamicFiltering.portMapPort = 0;
    if(FDB_addRule(&fdbState, &r) != 0)
        exit(1);

    r.type = FDB_RuleType_DynamicFiltering;
    memcpy(r.rule.dynamicFiltering.mac, macHost4, ETHERNET_MAC_LEN);
    r.rule.dynamicFiltering.vid = 1;
    r.rule.dynamicFiltering.portMapPort = 1;
    if(FDB_addRule(&fdbState, &r) != 0)
        exit(1);

    // update ruleset in BridgeForwarding
    if(FDB_updateBridgeForwarding(&fdbState, &bfState) != 0)
        exit(1);
    BridgeForwarding_printCurRuleset(&bfState);

    free(pm);
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
        return -1;
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
        init_bridgenode_testFDB4(&handlerTable, ports, portCnt);
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

