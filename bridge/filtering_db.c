/*
 * filtering_db.c
 *
 *  Created on: 20.08.2014
 *      Author: jasper
 */

#include "filtering_db.h"

#include <stdlib.h>
#include <string.h>


static int32_t cmpRules(const struct FDB_rule *r1, const struct FDB_rule *r2, const int32_t portCnt);
static void freeRuleInternalMemory(struct FDB_rule *r);
static int32_t copyRuleAllocInternalMemory(struct FDB_rule *to, const struct FDB_rule *from, const int32_t portCnt);
static int32_t updateBridgeForwarding(const struct FDB_state *s);
static int32_t checkRule(const struct FDB_rule *r, const int32_t portCnt);
static int32_t checkRuleConfilct(const struct FDB_state *s, const struct FDB_rule *r);

/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *
 */
int32_t FDB_init(struct FDB_state *state, struct BridgeForwarding_state *bridgeForwarding, uint32_t portCnt)
{
    if(state == NULL || bridgeForwarding == NULL)
        return -1;

    memset(state, 0, sizeof(struct FDB_state));
    state->bridgeForwarding = bridgeForwarding;
    state->portCnt = portCnt;
    state->ruleCnt = 0;
    state->ruleAllocCnt = 0;
    state->rules = NULL;

    return 0;
}

/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *            -2: rule invalid
 *            -3: no memory left
 *            -4: rule not allowed
 */
int32_t FDB_addRule(struct FDB_state *state, struct FDB_rule *rule)
{
    int32_t resu;

    if(state == NULL || rule == NULL)
        return -1;

    if(checkRule(rule, state->portCnt) != 0)
        return -2;
    if(checkRuleConfilct(state, rule) != 0)
        return -4;

    if(state->ruleAllocCnt <= state->ruleCnt +1)
    {
        struct FDB_rule *oldRules = state->rules;
        state->ruleAllocCnt++;
        state->rules = realloc(state->rules, state->ruleAllocCnt * sizeof(struct FDB_rule));
        if(state->rules == NULL)
        {
            state->rules = oldRules;
            state->ruleAllocCnt--;
            return -3;
        }
    }

    resu = copyRuleAllocInternalMemory(&(state->rules[state->ruleCnt]), rule, state->portCnt);
    if(resu != 0)
        return resu;

    state->ruleCnt++;

    updateBridgeForwarding(state);

    return 0;
}

/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *            -2: rule not found
 */
int32_t FDB_delRule(struct FDB_state *state, struct FDB_rule *rule)
{
    uint32_t i, j;
    int found = 0;

    if(state == NULL || rule == NULL)
        return -1;

    for(i = 0, j = 0; i < state->ruleCnt; i++)
    {
        if(cmpRules(rule, &(state->rules[i]), state->portCnt))
        {
            found = 1;
            // del rule by not incrementing write slot and not moving it forward
            freeRuleInternalMemory(&(state->rules[i]));
        }
        else
        {
            j++;
            if(j != i)
            {
                // fill up gaps
                memcpy(&(state->rules[j]), &(state->rules[i]), sizeof(struct FDB_rule));
            }
        }

    }

    state->ruleCnt = j;

    return found ? 0 : -2;
}

uint32_t FDB_getRuleCnt(struct FDB_state *state)
{
    if(state == NULL)
        return 0;
    return state->ruleCnt;
}

struct FDB_rule *FDB_getRuleByIdx(struct FDB_state *state, uint32_t idx)
{
    if(state == NULL || idx >= state->ruleCnt)
        return NULL;
    return &(state->rules[idx]);
}

static int32_t cmpRules(const struct FDB_rule *r1, const struct FDB_rule *r2, const int32_t portCnt)
{
    uint32_t i;
    const struct FDB_StaticFiltering *sf1, *sf2;
    const struct FDB_StaticVLANRegistration *sv1, *sv2;
    const struct FDB_DynamicFiltering *df1, *df2;
    const struct FDB_MACAddressRegistration *ma1, *ma2;
    const struct FDB_DynamicVLANRegistration *dv1, *dv2;
    const struct FDB_DynamicReservation *dr1, *dr2;

    if(r1 == r2)
        return 1;
    if(r1 == NULL || r2 == NULL)
        return 0;
    if(r1->type != r2->type)
        return 0;

    switch(r1->type)
    {
    case FDB_RuleType_StaticFiltering:
        sf1 = &(r1->rule.staticFiltering);
        sf2 = &(r2->rule.staticFiltering);
        if(sf1->addrType != sf2->addrType)
            return 0;
        for(i = 0; i < ETHERNET_MAC_LEN; i++)
            if(sf1->mac[i] != sf2->mac[i])
                return 0;
        if(sf1->prio != sf2->prio)
            return 0;
        if(sf1->portMap != sf2->portMap)
            for(i = 0; i < portCnt; i++)
                if(sf1->portMap[i].filter != sf2->portMap[i].filter)
                    return 0;
        return 1;

    case FDB_RuleType_StaticVLANRegistration:
        sv1 = &(r1->rule.staticVLANRegistration);
        sv2 = &(r2->rule.staticVLANRegistration);
        if(sv1->vid != sv2->vid)
            return 0;
        if(sv1->portMap != sv2->portMap)
            for(i = 0; i < portCnt; i++)
                if(   sv1->portMap[i].filter != sv2->portMap[i].filter
                   || sv1->portMap[i].forwardUntagged != sv2->portMap[i].forwardUntagged)
                    return 0;
        return 1;

    case FDB_RuleType_DynamicFiltering:
        df1 = &(r1->rule.dynamicFiltering);
        df2 = &(r2->rule.dynamicFiltering);
        for(i = 0; i < ETHERNET_MAC_LEN; i++)
            if(df1->mac[i] != df2->mac[i])
                return 0;
        if(df1->vid != df2->vid)
            return 0;
        if(   df1->portMapPort != df2->portMapPort
           || df1->portMapPrio != df2->portMapPrio)
            return 0;
        return 1;

    case FDB_RuleType_MACAddressRegistration:
        ma1 = &(r1->rule.macAddressRegistration);
        ma2 = &(r2->rule.macAddressRegistration);
        for(i = 0; i < ETHERNET_MAC_LEN; i++)
            if(ma1->mac[i] != ma2->mac[i])
                return 0;
        if(ma1->addrType != ma2->addrType)
            return 0;
        if(ma1->vid != ma2->vid)
            return 0;
        if(ma1->prio != ma2->prio)
            return 0;
        if(ma1->portMap != ma2->portMap)
            for(i = 0; i < portCnt; i++)
                if(ma1->portMap[i].filter != ma2->portMap[i].filter)
                    return 0;
        return 1;

    case FDB_RuleType_DynamicVLANRegistration:
        dv1 = &(r1->rule.dynamicVLANRegistration);
        dv2 = &(r2->rule.dynamicVLANRegistration);
        if(dv1->vid != dv2->vid)
            return 0;
        if(dv1->portMap != dv2->portMap)
            for(i = 0; i < portCnt; i++)
                if(dv1->portMap[i].filter != dv2->portMap[i].filter)
                    return 0;
        return 1;

    case FDB_RuleType_DynamicReservation:
        dr1 = &(r1->rule.dynamicReservation);
        dr2 = &(r2->rule.dynamicReservation);
        for(i = 0; i < ETHERNET_MAC_LEN; i++)
            if(dr1->mac[i] != dr2->mac[i])
                return 0;
        if(dr1->vid != dr2->vid)
            return 0;
        if(dr1->prio != dr2->prio)
            return 0;
        if(dr1->portMap != dr2->portMap)
            for(i = 0; i < portCnt; i++)
                if(dr1->portMap[i].filter != dr2->portMap[i].filter)
                    return 0;
        return 1;

    default:
        return 0;
    }
}

static void freeRuleInternalMemory(struct FDB_rule *r)
{
    void *toFree = NULL;
    if(r == NULL)
        return;

    switch(r->type)
    {
    case FDB_RuleType_StaticFiltering:
        toFree = r->rule.staticFiltering.portMap;
        break;
    case FDB_RuleType_StaticVLANRegistration:
        toFree = r->rule.staticVLANRegistration.portMap;
        break;
    case FDB_RuleType_MACAddressRegistration:
        toFree = r->rule.macAddressRegistration.portMap;
        break;
    case FDB_RuleType_DynamicVLANRegistration:
        toFree = r->rule.dynamicVLANRegistration.portMap;
        break;
    case FDB_RuleType_DynamicReservation:
        toFree = r->rule.dynamicReservation.portMap;
        break;
    default:
        break;
    }
    if(toFree != NULL)
        free(toFree);
    return;
}

static int32_t copyRuleAllocInternalMemory(struct FDB_rule *to, const struct FDB_rule *from, const int32_t portCnt)
{
    if(to == NULL || from == NULL)
        return -1;

    memcpy(to, from, sizeof(struct FDB_rule));

    switch(from->type)
    {
    case FDB_RuleType_StaticFiltering:
        to->rule.staticFiltering.portMap = calloc(portCnt, sizeof(struct FDB_PortMapEntry));
        if(to->rule.staticFiltering.portMap == NULL)
            return -3;
        memcpy(to->rule.staticFiltering.portMap, from->rule.staticFiltering.portMap, portCnt * sizeof(struct FDB_PortMapEntry));
        break;
    case FDB_RuleType_StaticVLANRegistration:
        to->rule.staticVLANRegistration.portMap = calloc(portCnt, sizeof(struct FDB_PortMapEntry));
        if(to->rule.staticVLANRegistration.portMap == NULL)
            return -3;
        memcpy(to->rule.staticVLANRegistration.portMap, from->rule.staticVLANRegistration.portMap, portCnt * sizeof(struct FDB_PortMapEntry));
        break;
    case FDB_RuleType_DynamicFiltering:
        break;
    case FDB_RuleType_MACAddressRegistration:
        to->rule.macAddressRegistration.portMap = calloc(portCnt, sizeof(struct FDB_PortMapEntry));
        if(to->rule.macAddressRegistration.portMap == NULL)
            return -3;
        memcpy(to->rule.macAddressRegistration.portMap, from->rule.macAddressRegistration.portMap, portCnt * sizeof(struct FDB_PortMapEntry));
        break;
    case FDB_RuleType_DynamicVLANRegistration:
        to->rule.dynamicVLANRegistration.portMap = calloc(portCnt, sizeof(struct FDB_PortMapEntry));
        if(to->rule.dynamicVLANRegistration.portMap == NULL)
            return -3;
        memcpy(to->rule.dynamicVLANRegistration.portMap, from->rule.dynamicVLANRegistration.portMap, portCnt * sizeof(struct FDB_PortMapEntry));
        break;
    case FDB_RuleType_DynamicReservation:
        to->rule.dynamicReservation.portMap = calloc(portCnt, sizeof(struct FDB_PortMapEntry));
        if(to->rule.dynamicReservation.portMap == NULL)
            return -3;
        memcpy(to->rule.dynamicReservation.portMap, from->rule.dynamicReservation.portMap, portCnt * sizeof(struct FDB_PortMapEntry));
        break;

    default:
        return -2;
    }

    return 0;
}

/*
 * Return values:
 *             0: success
 *            -1: could not allocate memory
 *            -2: error accessing BridgeForwarding
 */
static int32_t updateBridgeForwarding(const struct FDB_state *s)
{
    uint32_t i, j, resu = 0;
    struct BridgeForwarding_ruleset rs;

    memset(&rs, 0, sizeof(struct BridgeForwarding_ruleset));

    // start with VLANs filtering rules
    {
        int32_t vlanCnt = 0;
        uint16_t *vlans = calloc(s->ruleCnt, sizeof(uint16_t));
        struct FDB_PortMapEntry **staticPortMaps = calloc(s->ruleCnt, sizeof(struct FDB_PortMapEntry*));
        struct FDB_PortMapEntry **dynamicPortMaps = calloc(s->ruleCnt, sizeof(struct FDB_PortMapEntry*));

        if(vlans == NULL || staticPortMaps == NULL || dynamicPortMaps == NULL)
        {
            resu = -1;
            goto vlanEnd;
        }

        // search for VLAN rules
        for(i = 0; i < s->ruleCnt; i++)
        {
            uint16_t curVid;
            if(s->rules[i].type == FDB_RuleType_StaticVLANRegistration)
            {
                curVid = s->rules[i].rule.staticVLANRegistration.vid;
            }
            else if(s->rules[i].type == FDB_RuleType_DynamicVLANRegistration)
            {
                curVid = s->rules[i].rule.dynamicVLANRegistration.vid;
            }
            else
                continue;

            // check, if this VLAN already exists
            for(j = 0; j < vlanCnt; j++)
                if(curVid == vlans[j])
                    break;

            if(vlanCnt == j)
            {
                // okay, new one. init data ...
                vlans[j] = curVid;
                staticPortMaps[j] = NULL;
                dynamicPortMaps[j] = NULL;
                vlanCnt++;
            }
            if(s->rules[i].type == FDB_RuleType_StaticVLANRegistration)
            {
                staticPortMaps[j] = s->rules[i].rule.staticVLANRegistration.portMap;
            }
            else if(s->rules[i].type == FDB_RuleType_DynamicVLANRegistration)
            {
                dynamicPortMaps[j] = s->rules[i].rule.dynamicVLANRegistration.portMap;
            }
        }

        rs.vlans = calloc(vlanCnt, sizeof(struct BridgeForwarding_vlanRule));
        rs.portDefaultVLANs = calloc(s->portCnt, sizeof(uint16_t));
        if(rs.vlans == NULL || rs.portDefaultVLANs == NULL)
        {
            resu = -1;
            goto vlanEnd;
        }
        rs.vlanCnt = vlanCnt;

        // okay, now generate forwarding flags based on static and dynamic portMaps
        // ... and update the BridgeForwarding tables
        for(i = 0; i < vlanCnt; i++)
        {
            rs.vlans[i].vid = vlans[i];

            rs.vlans[i].portActions = calloc(s->portCnt, sizeof(enum BridgeForwarding_action));
            rs.vlans[i].allIndividualActions = calloc(s->portCnt, sizeof(enum BridgeForwarding_action));
            rs.vlans[i].allGroupActions = calloc(s->portCnt, sizeof(enum BridgeForwarding_action));
            rs.vlans[i].allUnregisteredIndividualActions = calloc(s->portCnt, sizeof(enum BridgeForwarding_action));
            rs.vlans[i].allUnregisteredGroupActions = calloc(s->portCnt, sizeof(enum BridgeForwarding_action));
            if(   rs.vlans[i].portActions == NULL
               || rs.vlans[i].allIndividualActions == NULL
               || rs.vlans[i].allGroupActions == NULL
               || rs.vlans[i].allUnregisteredIndividualActions == NULL
               || rs.vlans[i].allUnregisteredGroupActions == NULL)
            {
                resu = -1;
                goto vlanEnd;
            }

            for(j = 0; j < s->portCnt; j++)
            {
                int8_t forward = -1;
                // -1: unknown; 0: filter; 1:forward
                if(staticPortMaps[i] != NULL)
                {
                    if(staticPortMaps[i][j].filter == FDB_PortMapResult_Filter)
                        forward = 0;
                    else if(staticPortMaps[i][j].filter == FDB_PortMapResult_Forward)
                        forward = 1;

                    // analyse default (untagged state) for this vlan port
                    if(staticPortMaps[i][j].forwardUntagged)
                        rs.portDefaultVLANs[j] = vlans[i];
                }
                if(forward == -1 && dynamicPortMaps[i] != NULL)
                {
                    if(dynamicPortMaps[i][j].filter == FDB_PortMapResult_Filter)
                        forward = 0;
                    else if(dynamicPortMaps[i][j].filter == FDB_PortMapResult_Forward)
                        forward = 1;
                }

                // set vlan filtering
                if(forward == 1)
                    rs.vlans[i].portActions[j] = BridgeForwarding_action_Forward;
                else
                    rs.vlans[i].portActions[j] = BridgeForwarding_action_Filter;

                // set defaults for the remains
                rs.vlans[i].allIndividualActions[j] = BridgeForwarding_action_NextStage;
                rs.vlans[i].allGroupActions[j] = BridgeForwarding_action_NextStage;
                rs.vlans[i].allUnregisteredIndividualActions[j] = BridgeForwarding_action_NextStage;
                rs.vlans[i].allUnregisteredGroupActions[j] = BridgeForwarding_action_NextStage;
            }
        }

vlanEnd:
        if(vlans != NULL)
            free(vlans);
        if(staticPortMaps != NULL)
            free(staticPortMaps);
        if(dynamicPortMaps != NULL)
            free(dynamicPortMaps);
        if(resu != 0)
            goto end;
    }

    // here come the mac filtering rules ...
    {
        // search for static filtering rules with defined mac addresses

        rs.firstStageRules = calloc(s->ruleCnt, sizeof(struct BridgeForwarding_macRule));
        rs.firstStageRuleCnt = 0;
        if(rs.firstStageRules == NULL)
        {
            resu = -1;
            goto macEnd;
        }

        for(i = 0; i < s->ruleCnt; i++)
        {
            struct FDB_PortMapEntry *curPortMap;

            if(s->rules[i].type != FDB_RuleType_StaticFiltering)
                continue;
            if(   s->rules[i].rule.staticFiltering.addrType != FDB_AddressType_Individual
               || s->rules[i].rule.staticFiltering.addrType != FDB_AddressType_Group)
                continue;

            memcpy(rs.firstStageRules[rs.firstStageRuleCnt].mac, s->rules[i].rule.staticFiltering.mac, ETHERNET_MAC_LEN);
            memcpy(rs.firstStageRules[rs.firstStageRuleCnt].macMask, ETHERNET_MAC_MASK, ETHERNET_MAC_LEN);
            rs.firstStageRules[rs.firstStageRuleCnt].vid = s->rules[i].rule.staticFiltering.vid;
            if(rs.firstStageRules[rs.firstStageRuleCnt].vid == ETHERNET_VID_WILDCARD)
                rs.firstStageRules[rs.firstStageRuleCnt].vidMask = 0x0000;
            else
                rs.firstStageRules[rs.firstStageRuleCnt].vid = ETHERNET_VID_MASK;

            curPortMap = s->rules[i].rule.staticFiltering.portMap;
            rs.firstStageRules[rs.firstStageRuleCnt].portActions = calloc(s->portCnt, sizeof(enum BridgeForwarding_action));
            if(rs.firstStageRules[rs.firstStageRuleCnt].portActions == NULL)
            {
                resu = -1;
                goto macEnd;
            }

            for(j = 0; j < s->portCnt; j++)
            {
                if(curPortMap[j].filter == FDB_PortMapResult_Forward)
                    rs.firstStageRules[rs.firstStageRuleCnt].portActions[j] = BridgeForwarding_action_Forward;
                else if(curPortMap[j].filter == FDB_PortMapResult_Dynamic)
                    rs.firstStageRules[rs.firstStageRuleCnt].portActions[j] = BridgeForwarding_action_NextStage;
                else
                    rs.firstStageRules[rs.firstStageRuleCnt].portActions[j] = BridgeForwarding_action_Filter;
            }

            rs.firstStageRules[rs.firstStageRuleCnt].prio = s->rules[i].rule.staticFiltering.prio;

            rs.firstStageRuleCnt++;
        }
        // shrink allocated memory to needed size ...
        rs.firstStageRules = realloc(rs.firstStageRules, rs.firstStageRuleCnt * sizeof(struct BridgeForwarding_macRule));
        if(rs.firstStageRules == NULL)
        {
            resu = -1;
            goto macEnd;
        }

        // handle wildcard mac entries
        for(i = 0; i < s->ruleCnt; i++)
        {
            enum FDB_AddressType curAddrType;
            struct FDB_PortMapEntry *curPortMap;
            enum BridgeForwarding_action *targetActions;
            uint16_t curVid;
            int32_t vIdx;

            if(s->rules[i].type == FDB_RuleType_StaticFiltering)
            {
                if(   s->rules[i].rule.staticFiltering.addrType == FDB_AddressType_Group
                   || s->rules[i].rule.staticFiltering.addrType == FDB_AddressType_Individual)
                    continue;
                curAddrType = s->rules[i].rule.staticFiltering.addrType;
                curPortMap = s->rules[i].rule.staticFiltering.portMap;
                curVid = s->rules[i].rule.staticFiltering.vid;
            }
            else if(s->rules[i].type == FDB_RuleType_MACAddressRegistration)
            {
                if(   s->rules[i].rule.macAddressRegistration.addrType == FDB_AddressType_Group
                   || s->rules[i].rule.macAddressRegistration.addrType == FDB_AddressType_Individual)
                    continue;
                curAddrType = s->rules[i].rule.macAddressRegistration.addrType;
                curPortMap = s->rules[i].rule.macAddressRegistration.portMap;
                curVid = s->rules[i].rule.macAddressRegistration.vid;
            }
            else
                continue;

            // find vlan rule
            for(vIdx = 0; vIdx < rs.vlanCnt; vIdx++)
                if(rs.vlans[vIdx].vid == curVid)
                    break;
            if(vIdx >= rs.vlanCnt)
                continue; // vlan rule does not exist

            // distinguish target
            if(curAddrType == FDB_AddressType_AllIndividual)
                targetActions = rs.vlans[vIdx].allIndividualActions;
            else if(curAddrType == FDB_AddressType_AllGroup)
                targetActions = rs.vlans[vIdx].allGroupActions;
            else if(curAddrType == FDB_AddressType_AllUnregIndividual)
                targetActions = rs.vlans[vIdx].allUnregisteredIndividualActions;
            else if(curAddrType == FDB_AddressType_AllUnregGroup)
                targetActions = rs.vlans[vIdx].allUnregisteredGroupActions;
            else
                continue;

            // translate port actions
            for(j = 0; j < s->portCnt; j++)
            {
                if(curPortMap[j].filter == FDB_PortMapResult_Forward)
                    targetActions[j] = BridgeForwarding_action_Forward;
                else if(curPortMap[j].filter == FDB_PortMapResult_Filter)
                    targetActions[j] = BridgeForwarding_action_Filter;
            }
        }

        // search for dynamic filtering rules with defined mac addresses

        rs.secondStageRules = calloc(s->ruleCnt, sizeof(struct BridgeForwarding_macRule));
        rs.secondStageRuleCnt = 0;
        if(rs.secondStageRules == NULL)
        {
            resu = -1;
            goto macEnd;
        }

        for(i = 0; i < s->ruleCnt; i++)
        {
            struct FDB_PortMapEntry *curPortMap = NULL;
            int32_t curPortIdx = -1;

            if(s->rules[i].type == FDB_RuleType_DynamicFiltering)
            {
                memcpy(rs.secondStageRules[rs.secondStageRuleCnt].mac, s->rules[i].rule.dynamicFiltering.mac, ETHERNET_MAC_LEN);
                memcpy(rs.secondStageRules[rs.secondStageRuleCnt].macMask, ETHERNET_MAC_MASK, ETHERNET_MAC_LEN);
                rs.secondStageRules[rs.secondStageRuleCnt].vid = s->rules[i].rule.dynamicFiltering.vid;
                rs.secondStageRules[rs.secondStageRuleCnt].prio = s->rules[i].rule.dynamicFiltering.portMapPrio;
                curPortIdx = s->rules[i].rule.dynamicFiltering.portMapPort;
            }
            else if(s->rules[i].type == FDB_RuleType_MACAddressRegistration)
            {
                if(   s->rules[i].rule.macAddressRegistration.addrType != FDB_AddressType_Individual
                   && s->rules[i].rule.macAddressRegistration.addrType != FDB_AddressType_Group)
                    continue;

                memcpy(rs.secondStageRules[rs.secondStageRuleCnt].mac, s->rules[i].rule.macAddressRegistration.mac, ETHERNET_MAC_LEN);
                memcpy(rs.secondStageRules[rs.secondStageRuleCnt].macMask, ETHERNET_MAC_MASK, ETHERNET_MAC_LEN);
                rs.secondStageRules[rs.secondStageRuleCnt].vid = s->rules[i].rule.macAddressRegistration.vid;
                rs.secondStageRules[rs.secondStageRuleCnt].prio = s->rules[i].rule.macAddressRegistration.prio;
                curPortMap = s->rules[i].rule.macAddressRegistration.portMap;
            }
            else if(s->rules[i].type == FDB_RuleType_DynamicReservation)
            {
                memcpy(rs.secondStageRules[rs.secondStageRuleCnt].mac, s->rules[i].rule.dynamicReservation.mac, ETHERNET_MAC_LEN);
                memcpy(rs.secondStageRules[rs.secondStageRuleCnt].macMask, ETHERNET_MAC_MASK, ETHERNET_MAC_LEN);
                rs.secondStageRules[rs.secondStageRuleCnt].vid = s->rules[i].rule.dynamicReservation.vid;
                rs.secondStageRules[rs.secondStageRuleCnt].prio = s->rules[i].rule.dynamicReservation.prio;
                curPortMap = s->rules[i].rule.dynamicReservation.portMap;
            }
            else
                continue;

            if(rs.secondStageRules[rs.secondStageRuleCnt].vid == ETHERNET_VID_WILDCARD)
                rs.secondStageRules[rs.secondStageRuleCnt].vidMask = 0x0000;
            else
                rs.secondStageRules[rs.secondStageRuleCnt].vidMask = ETHERNET_VID_MASK;

            rs.secondStageRules[rs.secondStageRuleCnt].portActions = calloc(s->portCnt, sizeof(enum BridgeForwarding_action));
            if(rs.secondStageRules[rs.secondStageRuleCnt].portActions == NULL)
            {
                resu = -1;
                goto macEnd;
            }

            if(curPortMap != NULL)
            {
                for(j = 0; j < s->portCnt; j++)
                {
                    if(curPortMap[j].filter == FDB_PortMapResult_Forward)
                        rs.secondStageRules[rs.secondStageRuleCnt].portActions[j] = BridgeForwarding_action_Forward;
                    else
                        rs.secondStageRules[rs.secondStageRuleCnt].portActions[j] = BridgeForwarding_action_Filter;
                }
            }
            else
            {
                for(j = 0; j < s->portCnt; j++)
                {
                    if(j == curPortIdx)
                        rs.secondStageRules[rs.secondStageRuleCnt].portActions[j] = BridgeForwarding_action_Forward;
                    else
                        rs.secondStageRules[rs.secondStageRuleCnt].portActions[j] = BridgeForwarding_action_Filter;
                }
            }

            rs.secondStageRuleCnt++;
        }
        // shrink allocated memory to needed size ...
        rs.secondStageRules = realloc(rs.secondStageRules, rs.secondStageRuleCnt * sizeof(struct BridgeForwarding_macRule));
        if(rs.secondStageRules == NULL)
        {
            resu = -1;
            goto macEnd;
        }

macEnd:
        if(resu != 0)
            goto end;
    }

    if(BridgeForwarding_updateRuleset(s->bridgeForwarding, &rs) != 0)
        resu = -2;

end:
    // free stuff

    if(resu != 0)
        return resu;
    return 0;
}

static int32_t checkRule(const struct FDB_rule *r, const int32_t portCnt)
{
    return 0;
}

static int32_t checkRuleConfilct(const struct FDB_state *s, const struct FDB_rule *r)
{
    return 0;
}
