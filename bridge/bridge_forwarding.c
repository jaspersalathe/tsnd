/*
 * bridge_forwarding.c
 *
 *  Created on: 18.08.2014
 *      Author: jasper
 */


#include "bridge_forwarding.h"

#include "bridge.h"
#include "common.h"
#include "port.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

struct macLearningEntry
{
    uint8_t mac[ETHERNET_MAC_LEN];
    int32_t outPort;
    struct Common_timestamp lastPacketTime;
};

struct internalState
{
    struct BridgeForwarding_ruleset *ruleset;

    struct macLearningEntry *macLearnings;
    int32_t macLearningCnt;
    int32_t macLearningAllocCnt;
};

const uint8_t NULL_MAC[ETHERNET_MAC_LEN] =
{0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static struct HandlerTable_filterEntry bridgeFilter[] =
{
        {HandlerTable_packetField_ETH_DST, 0, ETHERNET_MAC_LEN, NULL_MAC, NULL_MAC},
        {HandlerTable_packetField_NONE, 0, 0, NULL, NULL}
};

static void packetHandler(const struct Packet_packet *packet, void *context);
static void learnMACNotifier(struct BridgeForwarding_state *state, const uint8_t mac[ETHERNET_MAC_LEN], const uint32_t portIdx, const struct Common_timestamp *t);
static int32_t checkRuleset(const  struct BridgeForwarding_ruleset *r, const int32_t portCnt);
static int32_t matchLearnedMAC(const struct BridgeForwarding_state *state, const uint8_t mac[ETHERNET_MAC_LEN]);
static int32_t matchVLAN(const struct BridgeForwarding_vlanRule *vrs, const int32_t vrsCnt, const uint16_t vid);
static int32_t matchMacRule(const struct BridgeForwarding_macRule *mrs, const int32_t mrsCnt, const uint8_t mac[ETHERNET_MAC_LEN], const uint16_t vid);

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
int32_t BridgeForwarding_init(struct BridgeForwarding_state *state, struct HandlerTable_table *table, struct Port *ports, const int32_t portCnt)
{
    int32_t resu = 0;
    uint32_t i;
    struct internalState *iState = NULL;
    struct HandlerTable_tableEntry *entry = NULL;
    struct BridgeForwarding_ruleset *ruleset = NULL;
    uint16_t *defaultVLANs;
    struct BridgeForwarding_vlanRule *defaultVLANrule;
    enum BridgeForwarding_action *defaultVLANrulePortActions;
    enum BridgeForwarding_action *defaultVLANruleAllIndividualActions;
    enum BridgeForwarding_action *defaultVLANruleAllGroupActions;
    enum BridgeForwarding_action *defaultVLANruleAllUnregisteredGroupActions;

    if(state == NULL || table == NULL || ports == NULL)
        return -1;
    if(portCnt < 1)
        return -4;

    iState = calloc(1, sizeof(struct internalState));
    entry = calloc(1, sizeof(struct HandlerTable_tableEntry));
    ruleset = calloc(1, sizeof(struct BridgeForwarding_ruleset));
    defaultVLANs = calloc(portCnt, sizeof(uint16_t));
    defaultVLANrule = calloc(1, sizeof(struct BridgeForwarding_vlanRule));
    defaultVLANrulePortActions = calloc(portCnt, sizeof(enum BridgeForwarding_action));
    defaultVLANruleAllIndividualActions = calloc(portCnt, sizeof(enum BridgeForwarding_action));
    defaultVLANruleAllGroupActions = calloc(portCnt, sizeof(enum BridgeForwarding_action));
    defaultVLANruleAllUnregisteredGroupActions = calloc(portCnt, sizeof(enum BridgeForwarding_action));
    if(iState == NULL || entry == NULL || ruleset == NULL || defaultVLANs == NULL || defaultVLANrule == NULL || defaultVLANrulePortActions == NULL || defaultVLANruleAllIndividualActions == NULL || defaultVLANruleAllGroupActions == NULL || defaultVLANruleAllUnregisteredGroupActions == NULL)
    {   resu = -3; goto fail; }

    state->ports = ports;
    state->portCnt = portCnt;
    state->state = iState;

    iState->ruleset = ruleset;
    for(i = 0; i < portCnt; i++)
        defaultVLANs[i] = ETHERNET_VID_DEFAULT;
    ruleset->portDefaultVLANs = defaultVLANs;
    defaultVLANrule->vid = ETHERNET_VID_DEFAULT;
    for(i = 0; i < portCnt; i++)
    {
        defaultVLANrulePortActions[i] = BridgeForwarding_action_Forward;
        defaultVLANruleAllIndividualActions[i] = BridgeForwarding_action_Filter;
        defaultVLANruleAllGroupActions[i] = BridgeForwarding_action_Forward;
        defaultVLANruleAllUnregisteredGroupActions[i] = BridgeForwarding_action_Forward;
    }
    defaultVLANrule->portActions = defaultVLANrulePortActions;
    defaultVLANrule->allIndividualActions = defaultVLANruleAllIndividualActions;
    defaultVLANrule->allGroupActions = defaultVLANruleAllGroupActions;
    defaultVLANrule->allUnregisteredGroupActions = defaultVLANruleAllUnregisteredGroupActions;

    ruleset->vlans = defaultVLANrule;
    ruleset->vlanCnt = 1;

    iState->macLearnings = NULL;
    iState->macLearningCnt = 0;
    iState->macLearningAllocCnt = 0;

    entry->filters = bridgeFilter;
    entry->handler = &packetHandler;
    entry->context = state;

    if(HandlerTable_registerHandler(table, entry) != 0)
    {   resu = -2; goto fail; }

    return 0;

fail:
    fputs("could not init brdige_forwarding!\n", stderr);

    if(iState != NULL)
        free(iState);
    if(entry != NULL)
        free(entry);
    if(ruleset != NULL)
        free(ruleset);
    if(defaultVLANs != NULL)
        free(defaultVLANs);
    if(defaultVLANrule != NULL)
        free(defaultVLANrule);
    if(defaultVLANrulePortActions != NULL)
        free(defaultVLANrulePortActions);
    if(defaultVLANruleAllIndividualActions != NULL)
        free(defaultVLANruleAllIndividualActions);
    if(defaultVLANruleAllGroupActions != NULL)
        free(defaultVLANruleAllGroupActions);
    if(defaultVLANruleAllUnregisteredGroupActions != NULL)
        free(defaultVLANruleAllUnregisteredGroupActions);
    return resu;
}

/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *            -2: ruleset invalid
 *            -3: could not allocate memory
 */
int32_t BridgeForwarding_updateRuleset(struct BridgeForwarding_state *state, struct BridgeForwarding_ruleset *ruleset)
{
    struct internalState *is;
    int32_t resu;
    struct BridgeForwarding_ruleset *oldRuleset, *newRuleset;

    if(state == NULL || state->state == NULL || ruleset == NULL)
        return -1;

    is = state->state;

    resu = checkRuleset(ruleset, state->portCnt);
    if(resu != 0)
        return resu;

    newRuleset = BridgeForwarding_deepCopyRuleset(ruleset, state->portCnt);
    if(newRuleset == NULL)
        return -3;

    oldRuleset = is->ruleset;
    is->ruleset = newRuleset;

    BridgeForwarding_freeRuleset(oldRuleset);

    return 0;
}

static int isActionAllowed(enum BridgeForwarding_action a)
{
    return a == BridgeForwarding_action_Forward || a == BridgeForwarding_action_Filter || a == BridgeForwarding_action_NextStage;
}

static int32_t checkRuleset(const  struct BridgeForwarding_ruleset *r, const int32_t portCnt)
{
    int32_t i, j;

    if(r == NULL)
        return -1;

    if(r->portDefaultVLANs == NULL)
        return -1;

    if(r->vlanCnt < 0)
        return -2;
    if(r->vlanCnt > 0)
    {
        if(r->vlans == NULL)
            return -1;
        for(i = 0; i < r->vlanCnt; i++)
        {
            if(r->vlans[i].portActions == NULL)
                return -1;
            if(r->vlans[i].allIndividualActions == NULL)
                return -1;
            if(r->vlans[i].allGroupActions == NULL)
                return -1;
            if(r->vlans[i].allUnregisteredGroupActions == NULL)
                return -1;

            for(j = 0; j < portCnt; j++)
            {
                if(!isActionAllowed(r->vlans[i].portActions[j]))
                    return -2;
                if(!isActionAllowed(r->vlans[i].allIndividualActions[j]))
                    return -2;
                if(!isActionAllowed(r->vlans[i].allGroupActions[j]))
                    return -2;
                if(!isActionAllowed(r->vlans[i].allUnregisteredGroupActions[j]))
                    return -2;
            }
        }
    }

    if(r->firstStageRuleCnt < 0)
        return -2;
    if(r->firstStageRuleCnt > 0)
    {
        if(r->firstStageRules == NULL)
            return -1;

        for(i = 0; i < r->firstStageRuleCnt; i++)
        {
            if(r->firstStageRules[i].mac == NULL)
                return -1;
            if(r->firstStageRules[i].macMask == NULL)
                return -1;
            if(r->firstStageRules[i].portActions == NULL)
                return -1;
            for(j = 0; j < portCnt; j++)
                if(!isActionAllowed(r->firstStageRules[i].portActions[j]))
                    return -2;
        }
    }

    if(r->secondStageRuleCnt < 0)
        return -2;
    if(r->secondStageRuleCnt > 0)
    {
        if(r->secondStageRules == NULL)
            return -1;

        for(i = 0; i < r->secondStageRuleCnt; i++)
        {
            if(r->secondStageRules[i].mac == NULL)
                return -1;
            if(r->secondStageRules[i].macMask == NULL)
                return -1;
            if(r->secondStageRules[i].portActions == NULL)
                return -1;
            for(j = 0; j < portCnt; j++)
                if(!isActionAllowed(r->secondStageRules[i].portActions[j]))
                    return -2;
        }
    }

    return 0;
}

struct BridgeForwarding_ruleset* BridgeForwarding_deepCopyRuleset(const struct BridgeForwarding_ruleset *r, const int32_t portCnt)
{
    // incoming rule is checked for NULL pointers and validity... so do not check here...
    int32_t i;
    struct BridgeForwarding_ruleset *resu = calloc(1, sizeof(struct BridgeForwarding_ruleset));
    if(resu == NULL)
        goto fail;

    resu->portDefaultVLANs = calloc(portCnt, sizeof(uint16_t));
    if(resu->portDefaultVLANs == NULL)
        goto fail;
    memcpy(resu->portDefaultVLANs, r->portDefaultVLANs, portCnt * sizeof(uint16_t));

    resu->vlanCnt = r->vlanCnt;
    if(r->vlanCnt > 0)
    {
        resu->vlans = calloc(r->vlanCnt, sizeof(struct BridgeForwarding_vlanRule));
        if(resu->vlans == NULL)
            goto fail;
        for(i = 0; i < r->vlanCnt; i++)
        {
            resu->vlans[i].vid = r->vlans[i].vid;
            resu->vlans[i].portActions = calloc(portCnt, sizeof(enum BridgeForwarding_action));
            resu->vlans[i].allIndividualActions = calloc(portCnt, sizeof(enum BridgeForwarding_action));
            resu->vlans[i].allGroupActions = calloc(portCnt, sizeof(enum BridgeForwarding_action));
            resu->vlans[i].allUnregisteredGroupActions = calloc(portCnt, sizeof(enum BridgeForwarding_action));
            if(resu->vlans[i].portActions == NULL || resu->vlans[i].allIndividualActions == NULL || resu->vlans[i].allGroupActions == NULL || resu->vlans[i].allUnregisteredGroupActions == NULL)
                goto fail;
            memcpy(resu->vlans[i].portActions, r->vlans[i].portActions, portCnt * sizeof(enum BridgeForwarding_action));
            memcpy(resu->vlans[i].allIndividualActions, r->vlans[i].allIndividualActions, portCnt * sizeof(enum BridgeForwarding_action));
            memcpy(resu->vlans[i].allGroupActions, r->vlans[i].allGroupActions, portCnt * sizeof(enum BridgeForwarding_action));
            memcpy(resu->vlans[i].allUnregisteredGroupActions, r->vlans[i].allUnregisteredGroupActions, portCnt * sizeof(enum BridgeForwarding_action));
        }
    }

    resu->firstStageRuleCnt = r->firstStageRuleCnt;
    if(r->firstStageRuleCnt > 0)
    {
        resu->firstStageRules = calloc(r->firstStageRuleCnt, sizeof(struct BridgeForwarding_macRule));
        if(resu->firstStageRules == NULL)
            goto fail;
        for(i = 0; i < r->firstStageRuleCnt; i++)
        {
            memcpy(resu->firstStageRules[i].mac, r->firstStageRules[i].mac, ETHERNET_MAC_LEN);
            memcpy(resu->firstStageRules[i].macMask, r->firstStageRules[i].macMask, ETHERNET_MAC_LEN);
            resu->firstStageRules[i].vid = r->firstStageRules[i].vid;
            resu->firstStageRules[i].vidMask = r->firstStageRules[i].vidMask;
            resu->firstStageRules[i].portActions = calloc(portCnt, sizeof(enum BridgeForwarding_action));
            if(resu->firstStageRules[i].portActions == NULL)
                goto fail;
            memcpy(resu->firstStageRules[i].portActions, r->firstStageRules[i].portActions, portCnt * sizeof(enum BridgeForwarding_action));
            resu->firstStageRules[i].prio = r->firstStageRules[i].prio;
        }
    }

    resu->secondStageRuleCnt = r->secondStageRuleCnt;
    if(r->secondStageRuleCnt > 0)
    {
        resu->secondStageRules = calloc(r->secondStageRuleCnt, sizeof(struct BridgeForwarding_macRule));
        if(resu->secondStageRules == NULL)
            goto fail;
        for(i = 0; i < r->secondStageRuleCnt; i++)
        {
            memcpy(resu->secondStageRules[i].mac, r->secondStageRules[i].mac, ETHERNET_MAC_LEN);
            memcpy(resu->secondStageRules[i].macMask, r->secondStageRules[i].macMask, ETHERNET_MAC_LEN);
            resu->secondStageRules[i].vid = r->secondStageRules[i].vid;
            resu->secondStageRules[i].vidMask = r->secondStageRules[i].vidMask;
            resu->secondStageRules[i].portActions = calloc(portCnt, sizeof(enum BridgeForwarding_action));
            if(resu->secondStageRules[i].portActions == NULL)
                goto fail;
            memcpy(resu->secondStageRules[i].portActions, r->secondStageRules[i].portActions, portCnt * sizeof(enum BridgeForwarding_action));
            resu->secondStageRules[i].prio = r->secondStageRules[i].prio;
        }
    }

    return resu;

fail:
    BridgeForwarding_freeRuleset(resu);
    return NULL;
}

void BridgeForwarding_freeRuleset(struct BridgeForwarding_ruleset *r)
{
    int32_t i;

    if(r == NULL)
        return;

    if(r->portDefaultVLANs != NULL)
        free(r->portDefaultVLANs);

    if(r->vlanCnt > 0 && r->vlans != NULL)
    {
        for(i = 0; i < r->vlanCnt; i++)
        {
            if(r->vlans[i].portActions != NULL)
                free(r->vlans[i].portActions);
            if(r->vlans[i].allIndividualActions != NULL)
                free(r->vlans[i].allIndividualActions);
            if(r->vlans[i].allGroupActions != NULL)
                free(r->vlans[i].allGroupActions);
            if(r->vlans[i].allUnregisteredGroupActions != NULL)
                free(r->vlans[i].allUnregisteredGroupActions);
        }
        free(r->vlans);
    }

    if(r->firstStageRuleCnt > 0 && r->firstStageRules != NULL)
    {
        for(i = 0; i < r->firstStageRuleCnt; i++)
            if(r->firstStageRules[i].portActions != NULL)
                free(r->firstStageRules[i].portActions);
        free(r->firstStageRules);
    }

    if(r->secondStageRuleCnt > 0 && r->secondStageRules != NULL)
    {
        for(i = 0; i < r->secondStageRuleCnt; i++)
            if(r->secondStageRules[i].portActions != NULL)
                free(r->secondStageRules[i].portActions);
        free(r->secondStageRules);
    }

    free(r);
}

void BridgeForwarding_printCurRuleset(const struct BridgeForwarding_state *s)
{
    struct internalState *is;
    int32_t i, j;

    if(s == NULL || s->state == NULL)
        return;

    is = s->state;

    if(is->ruleset == NULL)
        return;

    printf("current ruleset (%"PRIi32" ports)\n", s->portCnt);

    printf("default Port VLANs:\n");
    for(i = 0; i < s->portCnt; i++)
        printf("0x%03"PRIx16" ", is->ruleset->portDefaultVLANs[i]);
    printf("\n");

    printf("VLAN rules:\n");
    for(i = 0; i < is->ruleset->vlanCnt; i++)
    {
        printf(" vid: 0x%03"PRIx16"\n  portMap: ", is->ruleset->vlans[i].vid);

        for(j = 0; j < s->portCnt; j++)
        {
            switch(is->ruleset->vlans[i].portActions[j])
            {
            case BridgeForwarding_action_Forward: printf("f "); break;
            case BridgeForwarding_action_Filter: printf("b "); break;
            default: printf("? "); break;
            }
        }
        printf("\n");

        printf("  AI: ");
        for(j = 0; j < s->portCnt; j++)
        {
            switch(is->ruleset->vlans[i].allIndividualActions[j])
            {
            case BridgeForwarding_action_Forward: printf("f "); break;
            case BridgeForwarding_action_Filter: printf("b "); break;
            case BridgeForwarding_action_NextStage: printf("n "); break;
            default: printf("? "); break;
            }
        }
        printf("\n");

        printf("  AG: ");
        for(j = 0; j < s->portCnt; j++)
        {
            switch(is->ruleset->vlans[i].allGroupActions[j])
            {
            case BridgeForwarding_action_Forward: printf("f "); break;
            case BridgeForwarding_action_Filter: printf("b "); break;
            case BridgeForwarding_action_NextStage: printf("n "); break;
            default: printf("? "); break;
            }
        }
        printf("\n");

        printf("  UG: ");
        for(j = 0; j < s->portCnt; j++)
        {
            switch(is->ruleset->vlans[i].allUnregisteredGroupActions[j])
            {
            case BridgeForwarding_action_Forward: printf("f "); break;
            case BridgeForwarding_action_Filter: printf("b "); break;
            case BridgeForwarding_action_NextStage: printf("n "); break;
            default: printf("? "); break;
            }
        }
        printf("\n");
    }
    printf("\n");

    printf("First stage rules:\n");
    for(i = 0; i < is->ruleset->firstStageRuleCnt; i++)
    {
        printf(" mac: [%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8"] & [%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8"] vid: 0x%03"PRIx16" & 0x%03"PRIx16" prio: %"PRIu8"\n  portMap: ",
                is->ruleset->firstStageRules[i].mac[0], is->ruleset->firstStageRules[i].mac[1], is->ruleset->firstStageRules[i].mac[2], is->ruleset->firstStageRules[i].mac[3], is->ruleset->firstStageRules[i].mac[4], is->ruleset->firstStageRules[i].mac[5],
                is->ruleset->firstStageRules[i].macMask[0], is->ruleset->firstStageRules[i].macMask[1], is->ruleset->firstStageRules[i].macMask[2], is->ruleset->firstStageRules[i].macMask[3], is->ruleset->firstStageRules[i].macMask[4], is->ruleset->firstStageRules[i].macMask[5],
                is->ruleset->firstStageRules[i].vid, is->ruleset->firstStageRules[i].vidMask, is->ruleset->firstStageRules[i].prio);

        for(j = 0; j < s->portCnt; j++)
        {
            switch(is->ruleset->firstStageRules[i].portActions[j])
            {
            case BridgeForwarding_action_Forward: printf("f "); break;
            case BridgeForwarding_action_Filter: printf("b "); break;
            case BridgeForwarding_action_NextStage: printf("n "); break;
            default: printf("? "); break;
            }
        }
        printf("\n");
    }
    printf("\n");

    printf("Second stage rules:\n");
    for(i = 0; i < is->ruleset->secondStageRuleCnt; i++)
    {
        printf(" mac: [%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8"] & [%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8"] vid: 0x%03"PRIx16" & 0x%03"PRIx16" prio: %"PRIu8"\n  portMap: ",
                is->ruleset->secondStageRules[i].mac[0], is->ruleset->secondStageRules[i].mac[1], is->ruleset->secondStageRules[i].mac[2], is->ruleset->secondStageRules[i].mac[3], is->ruleset->secondStageRules[i].mac[4], is->ruleset->secondStageRules[i].mac[5],
                is->ruleset->secondStageRules[i].macMask[0], is->ruleset->secondStageRules[i].macMask[1], is->ruleset->secondStageRules[i].macMask[2], is->ruleset->secondStageRules[i].macMask[3], is->ruleset->secondStageRules[i].macMask[4], is->ruleset->secondStageRules[i].macMask[5],
                is->ruleset->secondStageRules[i].vid, is->ruleset->secondStageRules[i].vidMask, is->ruleset->secondStageRules[i].prio);

        for(j = 0; j < s->portCnt; j++)
        {
            switch(is->ruleset->secondStageRules[i].portActions[j])
            {
            case BridgeForwarding_action_Forward: printf("f "); break;
            case BridgeForwarding_action_Filter: printf("b "); break;
            default: printf("? "); break;
            }
        }
        printf("\n");
    }
    printf("\n");
}


static void packetHandler(const struct Packet_packet *p, void *context)
{
    struct BridgeForwarding_state *st;
    struct internalState *is;
    struct BridgeForwarding_ruleset *rs;
    uint16_t vid;
    struct Ethernet_headerVLAN *ethHdr;
    struct Packet_packet pOut = { 0 }, pOutV = { 0 };
    int wasTagged, isGroupMac;
    int32_t i, vIdx, fIdx, sIdx, lIdx, *portForwarded;
    struct BridgeForwarding_vlanRule *v = NULL;
    struct BridgeForwarding_macRule *f = NULL, *s = NULL;
    struct macLearningEntry *l = NULL;

    if(context == NULL || p == NULL)
        return;

    st = context;
    if(st->state == NULL || st->ports == NULL || st->portCnt == 0)
        return;

    is = st->state;
    if(is->ruleset == NULL || (is->macLearningCnt > 0 && is->macLearnings == NULL))
        return;

    rs = is->ruleset;
    if(rs->portDefaultVLANs == NULL || (rs->vlanCnt > 0 && rs->vlans == NULL) || (rs->firstStageRuleCnt > 0 && rs->firstStageRules == NULL) || (rs->secondStageRuleCnt > 0 && rs->secondStageRules == NULL))
        return;

    if(p->port >= st->portCnt)
        return;
    if(p->len < sizeof(struct Ethernet_headerVLAN))
        return;

    portForwarded = calloc(st->portCnt, sizeof(int32_t));
    if(portForwarded == NULL)
        return;

    ethHdr = (struct Ethernet_headerVLAN*)p->packet;

    if(Ethernet_isPacketVLAN(p->packet, p->len))
    {
        vid = Common_nToLu16( *( (uint16_t*)(ethHdr->tci) ) ) & ETHERNET_VID_MASK;
        wasTagged = 1;
    }
    else
    {
        vid = rs->portDefaultVLANs[p->port];
        wasTagged = 0;
    }

    fprintf(stdout, ">> %02X:%02X:%02X:%02X:%02X:%02X (%u): %u [%c:%u] -> ", ethHdr->dst[0], ethHdr->dst[1], ethHdr->dst[2], ethHdr->dst[3], ethHdr->dst[4], ethHdr->dst[5], p->len, p->port, wasTagged ? 't' : 'u', vid);

    vIdx = matchVLAN(rs->vlans, rs->vlanCnt, vid);
    fIdx = matchMacRule(rs->firstStageRules, rs->firstStageRuleCnt, ethHdr->dst, vid);
    sIdx = matchMacRule(rs->secondStageRules, rs->secondStageRuleCnt, ethHdr->dst, vid);
    lIdx = matchLearnedMAC(st, ethHdr->dst);

    if(vIdx < 0)
        goto noForwarding;
    v = &(rs->vlans[vIdx]);

    if(fIdx >= 0)
        f = &(rs->firstStageRules[fIdx]);

    if(sIdx >= 0)
        s = &(rs->secondStageRules[sIdx]);

    if(lIdx >= 0)
        l = &(is->macLearnings[lIdx]);

    isGroupMac = Ethernet_isGroupMac(ethHdr->dst);

    if(wasTagged)
    {
        pOutV.packet = p->packet;
        pOutV.len = p->len;
        // initialize untagged packet format
        pOut.len = p->len - 4;
        pOut.packet = calloc(1, pOut.len);
        if(pOut.packet == NULL)
            goto fail;
        memcpy(&(pOut.packet[ 0]), &(p->packet[ 0]),          12); // copy macs
        memcpy(&(pOut.packet[12]), &(p->packet[16]), p->len - 16); // copy type and payload
    }
    else
    {
        pOut.packet = p->packet;
        pOut.len = p->len;
        // initialize tagged packet format
        pOutV.len = p->len + 4;
        pOutV.packet = calloc(1, pOutV.len);
        if(pOutV.packet == NULL)
            goto fail;
        memcpy(&(pOutV.packet[ 0]), &(p->packet[ 0]),          12); // copy macs
        pOutV.packet[12] = ETHERNET_TYPE_VLAN[0]; // 802.1Q Tag type
        pOutV.packet[13] = ETHERNET_TYPE_VLAN[1];
        pOutV.packet[14] = 0xFF & (vid >> 8); // tci
        pOutV.packet[15] = 0xFF & vid;
        memcpy(&(pOutV.packet[16]), &(p->packet[12]), p->len - 12); // copy type and payload
    }

    for(i = 0; i < st->portCnt; i++)
    {
        struct Packet_packet *toSend;
        int forward;

        // never forward on own port
        if(p->port == i)
            forward = 0;
        else if(!isGroupMac)
        {
            // Individual address, see IEEE 802.1Q-2011 p. 133 Table 8-7

            // general check if this VLAN is valid on port
            if(v->portActions[i] == BridgeForwarding_action_Filter)
                forward = 0;
            // IF any static entry for a VID allocated to the FID specifies Forward THEN Forward
            // ELSE IF a static entry for the wildcard VID specifies Forward THEN Forward
            else if(f != NULL && f->portActions[i] == BridgeForwarding_action_Forward)
                forward = 1;
            // ELSE IF any static entry for a VID allocated to the FID specifies Filter THEN Filter
            // ELSE IF a static entry for the wildcard VID specifies Filter THEN Filter
            else if(f != NULL && f->portActions[i] == BridgeForwarding_action_Filter)
                forward = 0;
            // IF any static entry for a VID allocated to the FID specifies Forward THEN Forward
            else if(v->allIndividualActions[i] == BridgeForwarding_action_Forward)
                forward = 1;
            // ELSE IF any static entry for a VID allocated to the FID specifies Filter THEN Filter
            else if(v->allIndividualActions[i] == BridgeForwarding_action_Filter)
                forward = 0;
            // ELSE IF dynamic (learnt filtering information) entry for the FID specifies Filter THEN Filter
            else if(s != NULL && s->portActions[i] == BridgeForwarding_action_Filter)
                forward = 0;
            // ELSE IF dynamic (learnt filtering information) entry for the FID specifies Filter THEN Filter
            // if this case does not exist, then second stage entry may be overwritten by selflearned entry
            else if(s != NULL && s->portActions[i] == BridgeForwarding_action_Forward)
                forward = 1;
            // ELSE IF dynamic (learnt filtering information) entry for the FID specifies Filter THEN Filter
            else if(l != NULL && l->outPort != i)
                forward = 0;
            // ELSE Forward
            else
                forward = 1;
        }
        else
        {
            // Group address, see IEEE 802.1Q-2011 p. 134 f. Table 8-8 and 8-9

            // general check if this VLAN is valid on port
            if(v->portActions[i] == BridgeForwarding_action_Filter)
                forward = 0;
            // IF a static entry for the specific group address and the frame's VID specifies Forward THEN Forward
            // ELSE IF a static entry for the specific group address and the wildcard VID specifies Forward THEN Forward
            else if(f != NULL && f->portActions[i] == BridgeForwarding_action_Forward)
                forward = 1;
            // ELSE IF a static entry for the specific group address and the frame's VID specifies Filter THEN Filter
            // ELSE IF a static entry for the specific group address and the wildcard VID specifies Filter THEN Filter
            else if(f != NULL && f->portActions[i] == BridgeForwarding_action_Filter)
                forward = 0;
            // ELSE IF the Table 8-8 result for "All Group Addresses" is Registered THEN Forward
            else if(v->allGroupActions[i] == BridgeForwarding_action_Forward)
                forward = 1;
            // ELSE IF the Table 8-8 result for "All Unregistered Group Addresses" is Registered THEN Forward
            else if(v->allUnregisteredGroupActions[i] == BridgeForwarding_action_Forward)
                forward = 1;
            // ELSE IF a dynamic (MAC Address Registration) entry for the specific group address and the frame's VID specifies Forward THEN Forward
            else if(s != NULL && s->portActions[i] == BridgeForwarding_action_Forward)
                forward = 1;
            // ELSE Filter
            else
                forward = 0;
        }

        // okay, what is the forwarding decision?
        if(!forward)
            continue;

        // determine, if it is to be sent tagged or untagged
        if(vid == rs->portDefaultVLANs[i])
            toSend = &pOut;
        else
            toSend = &pOutV;

        if(Port_send(&(st->ports[i]), toSend))
            fprintf(stdout, "<%d,%s>", errno, strerror(errno));
        portForwarded[i] = 1;
        // TODO: analyze outgoing timestamps ...
    }

fail:
noForwarding:
    for(i = 0; i < st->portCnt; i++)
        fprintf(stdout, "%d", (portForwarded[i]));
    fputs("\n", stdout);

    if(wasTagged && pOut.packet != NULL)
        free(pOut.packet);
    if(!wasTagged && pOutV.packet != NULL)
        free(pOutV.packet);
    free(portForwarded);
    learnMACNotifier(st, ethHdr->src, p->port, &(p->t));
}

static void learnMACNotifier(struct BridgeForwarding_state *state, const uint8_t mac[ETHERNET_MAC_LEN], const uint32_t portIdx, const struct Common_timestamp *t)
{
    int32_t idx;
    struct internalState *is;

    // only learn individual mac
    if(Ethernet_isGroupMac(mac))
        return;

    // TODO: do not learn macs, which are in ruleset!
    // TODO: reset learned macs on update of ruleset!

    idx = matchLearnedMAC(state, mac);
    is = state->state;

    if(idx < 0)
    {
        struct macLearningEntry *old = is->macLearnings;
        if(is->macLearningCnt <= is->macLearningAllocCnt)
        {
            is->macLearningAllocCnt += 4;
            is->macLearnings = realloc(old, is->macLearningAllocCnt * sizeof(struct macLearningEntry));
            if(is->macLearnings == NULL)
            {
                is->macLearnings = old;
                is->macLearningAllocCnt -= 4;
                return;
            }
        }
        idx = is->macLearningCnt++;

        memcpy(is->macLearnings[idx].mac, mac, ETHERNET_MAC_LEN);

        fprintf(stdout, "new mac: %02X:%02X:%02X:%02X:%02X:%02X on %u\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], portIdx);
    }


    is->macLearnings[idx].outPort = portIdx;
    is->macLearnings[idx].lastPacketTime = *t;
}


static int32_t matchVLAN(const struct BridgeForwarding_vlanRule *vrs, const int32_t vrsCnt, const uint16_t vid)
{
    int32_t i;

    for(i = 0; i < vrsCnt; i++)
        if(vrs[i].vid == (vid & ETHERNET_VID_MASK))
            return i;
    return -1;
}

static int32_t matchMacRule(const struct BridgeForwarding_macRule *mrs, const int32_t mrsCnt, const uint8_t mac[ETHERNET_MAC_LEN], const uint16_t vid)
{
    int32_t i;

    for(i = 0; i < mrsCnt; i++)
        if(Ethernet_cmpMacsMasked(mac, mrs[i].mac, mrs[i].macMask) == 0 && (vid & mrs[i].vidMask) == (mrs[i].vid & mrs[i].vidMask))
            return i;

    return -1;
}


static int32_t matchLearnedMAC(const struct BridgeForwarding_state *state, const uint8_t mac[ETHERNET_MAC_LEN])
{
    struct internalState *iState;
    int32_t i;

    iState = state->state;

    for(i = 0; i < iState->macLearningCnt; i++)
        if(Ethernet_cmpMacs(iState->macLearnings[i].mac, mac) == 0)
            return i;

    return -1;
}
