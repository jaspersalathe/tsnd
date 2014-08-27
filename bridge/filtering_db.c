/*
 * filtering_db.c
 *
 *  Created on: 20.08.2014
 *      Author: jasper
 */

#include "filtering_db.h"

#include <stdlib.h>
#include <string.h>


static int32_t cmpRules(const struct FDB_rule *r1, const struct FDB_rule *r2);
static void freeRuleInternalMemory(struct FDB_rule *r);
static int32_t copyRuleAllocInternalMemory(struct FDB_rule *to, const struct FDB_rule *from);
static int32_t updateBridgeForwarding(const struct FDB_state *s);
static int32_t checkRule(const struct FDB_rule *r);
static int32_t checkRuleConfilct(const struct FDB_rule *r);

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

    if(checkRule(rule) != 0)
        return -2;
    if(checkRuleConfilct(rule) != 0)
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

    resu = copyRuleAllocInternalMemory(&(state->rules[state->ruleCnt]), rule);
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
        if(cmpRules(rule, &(state->rules[i])))
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

static int32_t cmpRules(const struct FDB_rule *r1, const struct FDB_rule *r2)
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
        if(sf1->portMapCnt != sf2->portMapCnt)
            return 0;
        if(sf1->portMap != sf2->portMap)
            for(i = 0; i < sf1->portMapCnt; i++)
                if(   sf1->portMap[i].filter != sf2->portMap[i].filter
                   || sf1->portMap[i].prio != sf2->portMap[i].prio)
                    return 0;
        return 1;

    case FDB_RuleType_StaticVLANRegistration:
        sv1 = &(r1->rule.staticVLANRegistration);
        sv2 = &(r2->rule.staticVLANRegistration);
        if(sv1->vid != sv2->vid)
            return 0;
        if(sv1->portMapCnt != sv2->portMapCnt)
            return 0;
        if(sv1->portMap != sv2->portMap)
            for(i = 0; i < sv1->portMapCnt; i++)
                if(   sv1->portMap[i].filter != sv2->portMap[i].filter
                   || sv1->portMap[i].prio != sv2->portMap[i].prio
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
        if(ma1->portMapCnt != ma2->portMapCnt)
            return 0;
        if(ma1->portMap != ma2->portMap)
            for(i = 0; i < ma1->portMapCnt; i++)
                if(   ma1->portMap[i].filter != ma2->portMap[i].filter
                   || ma1->portMap[i].prio != ma2->portMap[i].prio)
                    return 0;
        return 1;

    case FDB_RuleType_DynamicVLANRegistration:
        dv1 = &(r1->rule.dynamicVLANRegistration);
        dv2 = &(r2->rule.dynamicVLANRegistration);
        if(dv1->vid != dv2->vid)
            return 0;
        if(dv1->portMapCnt != dv2->portMapCnt)
            return 0;
        if(dv1->portMap != dv2->portMap)
            for(i = 0; i < dv1->portMapCnt; i++)
                if(   dv1->portMap[i].filter != dv2->portMap[i].filter
                   || dv1->portMap[i].prio != dv2->portMap[i].prio)
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
        if(dr1->portMapCnt != dr2->portMapCnt)
            return 0;
        if(dr1->portMap != dr2->portMap)
            for(i = 0; i < dr1->portMapCnt; i++)
                if(   dr1->portMap[i].filter != dr2->portMap[i].filter
                   || dr1->portMap[i].prio != dr2->portMap[i].prio)
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

static int32_t copyRuleAllocInternalMemory(struct FDB_rule *to, const struct FDB_rule *from)
{
    if(to == NULL || from == NULL)
        return -1;

    memcpy(to, from, sizeof(struct FDB_rule));

    switch(from->type)
    {
    case FDB_RuleType_StaticFiltering:
        to->rule.staticFiltering.portMap = malloc(to->rule.staticFiltering.portMapCnt * sizeof(struct FDB_PortMapEntry));
        if(to->rule.staticFiltering.portMap == NULL)
            return -3;
        memcpy(to->rule.staticFiltering.portMap, from->rule.staticFiltering.portMap, to->rule.staticFiltering.portMapCnt * sizeof(struct FDB_PortMapEntry));
        break;
    case FDB_RuleType_StaticVLANRegistration:
        to->rule.staticVLANRegistration.portMap = malloc(to->rule.staticVLANRegistration.portMapCnt * sizeof(struct FDB_PortMapEntry));
        if(to->rule.staticVLANRegistration.portMap == NULL)
            return -3;
        memcpy(to->rule.staticVLANRegistration.portMap, from->rule.staticVLANRegistration.portMap, to->rule.staticVLANRegistration.portMapCnt * sizeof(struct FDB_PortMapEntry));
        break;
    case FDB_RuleType_DynamicFiltering:
        break;
    case FDB_RuleType_MACAddressRegistration:
        to->rule.macAddressRegistration.portMap = malloc(to->rule.macAddressRegistration.portMapCnt * sizeof(struct FDB_PortMapEntry));
        if(to->rule.macAddressRegistration.portMap == NULL)
            return -3;
        memcpy(to->rule.macAddressRegistration.portMap, from->rule.macAddressRegistration.portMap, to->rule.macAddressRegistration.portMapCnt * sizeof(struct FDB_PortMapEntry));
        break;
    case FDB_RuleType_DynamicVLANRegistration:
        to->rule.dynamicVLANRegistration.portMap = malloc(to->rule.dynamicVLANRegistration.portMapCnt * sizeof(struct FDB_PortMapEntry));
        if(to->rule.dynamicVLANRegistration.portMap == NULL)
            return -3;
        memcpy(to->rule.dynamicVLANRegistration.portMap, from->rule.dynamicVLANRegistration.portMap, to->rule.dynamicVLANRegistration.portMapCnt * sizeof(struct FDB_PortMapEntry));
        break;
    case FDB_RuleType_DynamicReservation:
        to->rule.dynamicReservation.portMap = malloc(to->rule.dynamicReservation.portMapCnt * sizeof(struct FDB_PortMapEntry));
        if(to->rule.dynamicReservation.portMap == NULL)
            return -3;
        memcpy(to->rule.dynamicReservation.portMap, from->rule.dynamicReservation.portMap, to->rule.dynamicReservation.portMapCnt * sizeof(struct FDB_PortMapEntry));
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

    // start with VLANs
    {
        uint32_t vlanCnt = 0;
        uint16_t *vlans = malloc(s->ruleCnt * sizeof(uint16_t));
        struct FDB_PortMapEntry **staticPortMaps = malloc(s->ruleCnt * sizeof(struct FDB_PortMapEntry*));
        struct FDB_PortMapEntry **dynamicPortMaps = malloc(s->ruleCnt * sizeof(struct FDB_PortMapEntry*));
        uint32_t *portEnabled = malloc(s->portCnt * sizeof(uint32_t));
        uint32_t portEnabledCnt;
        uint16_t *untaggedPortVlans = malloc(s->portCnt * sizeof(uint16_t));

        if(vlans == NULL || staticPortMaps == NULL || dynamicPortMaps == NULL || portEnabled == NULL || untaggedPortVlans == NULL)
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

        // okay, now generate forwarding flags based on static and dynamic portMaps
        // ... and update the BridgeForwarding tables
        if(BridgeForwarding_delAllVLAN(s->bridgeForwarding) != 0)
        {   resu = -2; goto vlanEnd; }
        for(i = 0; i < vlanCnt; i++)
        {
            portEnabledCnt = 0;
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
                        untaggedPortVlans[j] = vlans[i];
                }
                if(forward == -1 && dynamicPortMaps[i] != NULL)
                {
                    if(dynamicPortMaps[i][j].filter == FDB_PortMapResult_Filter)
                        forward = 0;
                    else if(dynamicPortMaps[i][j].filter == FDB_PortMapResult_Forward)
                        forward = 1;
                }
                if(forward == 1)
                    portEnabled[portEnabledCnt++] = j;
            }

            if(BridgeForwarding_addVLAN(s->bridgeForwarding, vlans[i], portEnabled, portEnabledCnt) != 0)
            {   resu = -2; goto vlanEnd; }
        }

        // update default (untagged) vlans for ports
        for(i = 0; i < s->portCnt; i++)
        {
            if(BridgeForwarding_setPortDefauldVID(s->bridgeForwarding, untaggedPortVlans[i], i) != 0)
            {   resu = -2; goto vlanEnd; }
        }

vlanEnd:
        if(vlans != NULL)
            free(vlans);
        if(staticPortMaps != NULL)
            free(staticPortMaps);
        if(dynamicPortMaps != NULL)
            free(dynamicPortMaps);
        if(portEnabled != NULL)
            free(portEnabled);
        if(untaggedPortVlans != NULL)
            free(untaggedPortVlans);
        if(resu != 0)
            return resu;
    }

    // here come the mac rules ...
    return 0;
}

static int32_t checkRule(const struct FDB_rule *r)
{
    return 0;
}

static int32_t checkRuleConfilct(const struct FDB_rule *r)
{
    return 0;
}
