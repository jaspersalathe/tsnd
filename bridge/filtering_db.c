/*
 * filtering_db.c
 *
 *  Created on: 20.08.2014
 *      Author: jasper
 */

#include "filtering_db.h"

#include <stdlib.h>
#include <string.h>


static int cmpRules(const struct FDB_rule *r1, const struct FDB_rule *r2);

/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *
 */
int32_t FDB_init(struct FDB_state *state, struct BridgeForwarding_state *bridgeForwarding, uint32_t portCnt, struct FDB_rule *ruleMemory, uint32_t ruleAllocCnt)
{
    if(state == NULL || bridgeForwarding == NULL)
        return -1;
    if(ruleAllocCnt > 0 && ruleMemory == NULL)
        return -1;

    memset(state, 0, sizeof(struct FDB_state));
    state->bridgeForwarding = bridgeForwarding;
    state->portCnt = portCnt;
    state->ruleCnt = 0;
    state->ruleAllocCnt = ruleAllocCnt;
    state->rules = ruleMemory;
    state->rulesStaticallyAllocated = ruleAllocCnt > 0;

    return 0;
}

/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *            -2: rule invalid
 *            -3: no memory left
 */
int32_t FDB_addRule(struct FDB_state *state, struct FDB_rule *rule)
{
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
        }
        else
        {
            j++;
            if(j != i)
            {
                // fill up gaps
            }
        }

    }

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

static int cmpRules(const struct FDB_rule *r1, const struct FDB_rule *r2)
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
                if(sf1->portMap[i] != sf2->portMap[i])
                    return 0;
        return 1;

    case FDB_RuleType_StaticVLANRegistraiton:
        sv1 = &(r1->rule.staticVLANRegistration);
        sv2 = &(r2->rule.staticVLANRegistration);
        if(sv1->vid != sv2->vid)
            return 0;
        if(sv1->portMapCnt != sv2->portMapCnt)
            return 0;
        if(sv1->portMap != sv2->portMap)
            for(i = 0; i < sv1->portMapCnt; i++)
                if(sv1->portMap[i] != sv2->portMap[i])
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
        if(df1->portMap != df2->portMap)
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
                if(ma1->portMap[i] != ma2->portMap[i])
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
                if(dv1->portMap[i] != dv2->portMap[i])
                    return 0;
        return 1;

    case FDB_RuleType_DynamicReservation:
        dr1 = &(r1->rule.dynamicRegistration);
        dr2 = &(r2->rule.dynamicRegistration);
        for(i = 0; i < ETHERNET_MAC_LEN; i++)
            if(dr1->mac[i] != dr2->mac[i])
                return 0;
        if(dr1->vid != dr2->vid)
            return 0;
        if(dr1->portMapCnt != dr2->portMapCnt)
            return 0;
        return 1;

    default:
        return 0;
    }
}
