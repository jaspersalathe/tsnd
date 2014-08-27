/*
 * filtering_db.h
 *
 *  Created on: 20.08.2014
 *      Author: jasper
 */

#ifndef FILTERING_DB_H_
#define FILTERING_DB_H_

#include <inttypes.h>
#include "headers/ethernet.h"
#include "bridge_forwarding.h"


enum FDB_RuleType
{
    FDB_RuleType_StaticFiltering,
    FDB_RuleType_StaticVLANRegistraiton,
    FDB_RuleType_DynamicFiltering,
    FDB_RuleType_MACAddressRegistration,
    FDB_RuleType_DynamicVLANRegistration,
    FDB_RuleType_DynamicReservation
};

enum FDB_AddressType
{
    FDB_AddressType_AllIndividual,
    FDB_AddressType_AllGroup,
    FDB_AddressType_AllUnregIndividual,
    FDB_AddressType_AllUnregGroup,
    FDB_AddressType_Individual,
    FDB_AddressType_Group
};

enum FDB_PortMapEntry
{
    FDP_PortMapEntry_Filter,
    FDP_PortMapEntry_Forward,
    FDP_PortMapEntry_Dynamic,
};

struct FDB_StaticFiltering
{
    uint8_t mac[ETHERNET_MAC_LEN];
    enum FDB_AddressType addrType;
    enum FDB_PortMapEntry *portMap;
    uint32_t portMapCnt;
};

struct FDB_StaticVLANRegistration
{
    uint16_t vid;
    enum FDB_PortMapEntry *portMap;
    uint32_t portMapCnt;
    /*
     * Following mapping for portMap:
     *  - Filter <-> Forbidden
     *  - Normal <-> Dynamic
     *  - Fixed  <-> Forward
     */
};

struct FDB_DynamicFiltering
{
    uint8_t mac[ETHERNET_MAC_LEN];
    uint16_t vid; // korrekt: fid
    uint32_t portMap; // Port to forward to.
};

struct FDB_MACAddressRegistration
{
    uint8_t mac[ETHERNET_MAC_LEN];
    enum FDB_AddressType addrType;
    // not allowed: AllUnregIndividual
    uint16_t vid;
    enum FDB_PortMapEntry *portMap;
    uint32_t portMapCnt;
    // Dynamic is invalid for portMap.
};

struct FDB_DynamicVLANRegistration
{
    uint16_t vid;
    enum FDB_PortMapEntry *portMap;
    uint32_t portMapCnt;
    // Dynamic is invalid for portMap.
};

struct FDB_DynamicReservation
{
    uint8_t mac[ETHERNET_MAC_LEN];
    uint16_t vid;
    enum FDB_PortMapEntry *portMap;
    uint32_t portMapCnt;
    // Dynamic is invalid for portMap.
};

struct FDB_rule
{
    enum FDB_RuleType type;
    union
    {
        struct FDB_StaticFiltering staticFiltering;
        struct FDB_StaticVLANRegistration staticVLANRegistration;
        struct FDB_DynamicFiltering dynamicFiltering;
        struct FDB_MACAddressRegistration macAddressRegistration;
        struct FDB_DynamicVLANRegistration dynamicVLANRegistration;
        struct FDB_DynamicReservation dynamicRegistration;
    } rule;
};

struct FDB_state
{
    uint32_t portCnt;
    struct BridgeForwarding_state *bridgeForwarding;

    struct FDB_rule *rules;
    uint32_t ruleCnt;
    uint32_t ruleAllocCnt;
    int rulesStaticallyAllocated;
};

/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *
 */
int32_t FDB_init(struct FDB_state *state, struct BridgeForwarding_state *bridgeForwarding, uint32_t portCnt, struct FDB_rule *ruleMemory, uint32_t ruleAllocCnt);

/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *            -2: rule invalid
 *            -3: no memory left
 */
int32_t FDB_addRule(struct FDB_state *state, struct FDB_rule *rule);
/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *            -2: rule not found
 */
int32_t FDB_delRule(struct FDB_state *state, struct FDB_rule *rule);

uint32_t FDB_getRuleCnt(struct FDB_state *state);
struct FDB_rule *FDB_getRuleByIdx(struct FDB_state *state, uint32_t idx);

#endif /* FILTERING_DB_H_ */
