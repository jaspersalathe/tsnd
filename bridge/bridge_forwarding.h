/*
 * bridge_forwarding.h
 *
 *  Created on: 18.08.2014
 *      Author: jasper
 */

#ifndef BRIDGE_FORWARDING_H_
#define BRIDGE_FORWARDING_H_


#include <inttypes.h>
#include "handler_table.h"
#include "port.h"
#include "headers/ethernet.h"


enum BridgeForwarding_action
{
    BridgeForwarding_action_Filter,
    BridgeForwarding_action_Forward,
    BridgeForwarding_action_NextStage
};

struct BridgeForwarding_vlanRule
{
    uint16_t vid;
    enum BridgeForwarding_action *portActions;
    // dynamic not allowed
    enum BridgeForwarding_action *allIndividualActions;
    enum BridgeForwarding_action *allGroupActions;
    enum BridgeForwarding_action *allUnregisteredIndividualActions;
    enum BridgeForwarding_action *allUnregisteredGroupActions;
};

struct BridgeForwarding_macRule
{
    uint8_t mac[ETHERNET_MAC_LEN];
    uint8_t macMask[ETHERNET_MAC_LEN];
    uint16_t vid;
    uint16_t vidMask;
    enum BridgeForwarding_action *portActions;
    uint8_t prio;
};

struct BridgeForwarding_ruleset
{
    // VLAN rules
    uint16_t *portDefaultVLANs;
    struct BridgeForwarding_vlanRule *vlans;
    int32_t vlanCnt;

    // first stage rules
    struct BridgeForwarding_macRule *firstStageRules;
    int32_t firstStageRuleCnt;

    // second stage rules
    struct BridgeForwarding_macRule *secondStageRules;
    int32_t secondStageRuleCnt;
};

struct BridgeForwarding_state
{
	struct Port *ports;
	int32_t portCnt;
	void *state;
};

/*
 * Initialize bridge forwarding logic.
 *
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *            -2: could not register handler
 *            -3: could not allocate memory
 *            -4: no ports
 *
 */
int32_t BridgeForwarding_init(struct BridgeForwarding_state *state, struct HandlerTable_table *table, struct Port *ports, const int32_t portCnt);

/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *            -2: ruleset invalid
 *            -3: could not allocate memory
 */
int32_t BridgeForwarding_updateRuleset(struct BridgeForwarding_state *state, struct BridgeForwarding_ruleset *ruleset);


#endif /* BRIDGE_FORWARDING_H_ */
