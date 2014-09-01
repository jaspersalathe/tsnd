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
    FDB_RuleType_StaticVLANRegistration,
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

enum FDB_PortMapResult
{
    FDB_PortMapResult_Filter,
    FDB_PortMapResult_Forward,
    FDB_PortMapResult_Dynamic,
};

struct FDB_PortMapEntry
{
    enum FDB_PortMapResult filter;
    uint8_t forwardUntagged; // only for static VLAN rules
};

struct FDB_StaticFiltering
{
    uint8_t mac[ETHERNET_MAC_LEN];
    enum FDB_AddressType addrType;
    uint16_t vid;
    struct FDB_PortMapEntry *portMap;
    uint8_t prio; // to distinguish the queue to be used for forwarding
};

struct FDB_StaticVLANRegistration
{
    uint16_t vid;
    struct FDB_PortMapEntry *portMap;
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
    uint32_t portMapPort; // Port to forward to ...
    uint8_t prio;  // ... and priority to use.
};

struct FDB_MACAddressRegistration
{
    uint8_t mac[ETHERNET_MAC_LEN];
    enum FDB_AddressType addrType;
    // not allowed: AllUnregIndividual, AllIndividual
    uint16_t vid;
    struct FDB_PortMapEntry *portMap;
    uint8_t prio; // to distinguish the queue to be used for forwarding
    // Dynamic is invalid for portMap.
};

struct FDB_DynamicVLANRegistration
{
    uint16_t vid;
    struct FDB_PortMapEntry *portMap;
    // Dynamic is invalid for portMap.
};

struct FDB_DynamicReservation
{
    uint8_t mac[ETHERNET_MAC_LEN];
    uint16_t vid;
    struct FDB_PortMapEntry *portMap;
    uint8_t prio; // to distinguish the queue to be used for forwarding
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
        struct FDB_DynamicReservation dynamicReservation;
    } rule;
};

struct FDB_state
{
    uint32_t portCnt;
    struct BridgeForwarding_state *bridgeForwarding;

    struct FDB_rule *rules;
    uint32_t ruleCnt;
    uint32_t ruleAllocCnt;
};

/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *
 */
int32_t FDB_init(struct FDB_state *state, struct BridgeForwarding_state *bridgeForwarding, uint32_t portCnt);

/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *            -2: rule invalid
 *            -3: could not allocate memory
 *            -4: rule not allowed
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
