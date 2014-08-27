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

#define PORTNO_TO_PORTFLAGSIDX(portNo)  (portNo / 8)
#define PORTNO_TO_PORTFLAGSMASK(portNo) (1 << (portNo % 8))

struct vlan
{
    uint16_t vid;
    uint8_t *portFlags;
};

struct macFilter
{
    uint8_t mac[ETHERNET_MAC_LEN];
    uint8_t *portFlags;
};

struct macLearningEntry
{
    uint8_t mac[ETHERNET_MAC_LEN];
    uint32_t outPort;
    struct Common_timestamp lastPacketTime;
};

struct internalState
{
    uint16_t *defaultVIDs;

    struct vlan *vlans;
    uint32_t vlanCnt;
    uint32_t vlanAllocCnt;

    struct macFilter *macFilters;
    uint32_t macFilterCnt;
    uint32_t macFilterAllocCnt;

    struct macLearningEntry *macLearnings;
    uint32_t macLearningCnt;
    uint32_t macLearningAllocCnt;
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
static int64_t findVLANbyVID(const struct BridgeForwarding_state *state, const uint16_t vid);
static int64_t findMacFilterbyMAC(const struct BridgeForwarding_state *state, const uint8_t mac[ETHERNET_MAC_LEN]);
static int64_t findMacLearnedbyMAC(const struct BridgeForwarding_state *state, const uint8_t mac[ETHERNET_MAC_LEN]);
static int32_t cmpMacs(const uint8_t mac1[ETHERNET_MAC_LEN], const uint8_t mac2[ETHERNET_MAC_LEN]);

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
int32_t BridgeForwarding_init(struct BridgeForwarding_state *state, struct HandlerTable_table *table, struct Port *ports, uint32_t portCnt)
{
    int32_t resu = 0;
    uint32_t i;
    struct internalState *iState = NULL;
    struct HandlerTable_tableEntry *entry = NULL;
    uint16_t *defVIDs = NULL;
    uint32_t *portList;

    if(state == NULL || table == NULL || ports == NULL)
        return -1;
    if(portCnt < 1)
        return -4;

    iState = malloc(sizeof(struct internalState));
    defVIDs = malloc(((uint64_t)portCnt) * sizeof(uint16_t));
    entry = malloc(sizeof(struct HandlerTable_tableEntry));
    portList = malloc(portCnt * sizeof(uint32_t));
    if(iState == NULL || defVIDs == NULL || entry == NULL || portList == NULL)
    {   resu = -3; goto fail; }

    memset(iState, 0, sizeof(struct internalState));
    memset(defVIDs, 0, ((uint64_t)portCnt) * sizeof(uint16_t));
    memset(entry, 0, sizeof(struct HandlerTable_tableEntry));

    state->ports = ports;
    state->portCnt = portCnt;
    state->state = iState;

    iState->vlans = NULL;
    iState->vlanCnt = 0;
    iState->vlanAllocCnt = 0;

    iState->macFilters = NULL;
    iState->macFilterCnt = 0;
    iState->macFilterAllocCnt = 0;

    iState->macLearnings = NULL;
    iState->macLearningCnt = 0;
    iState->macLearningAllocCnt = 0;

    iState->defaultVIDs = defVIDs;
    for(i = 0; i < portCnt; i++)
        defVIDs[i] = BRIDGE_DEF_VID;

    entry->filters = bridgeFilter;
    entry->handler = &packetHandler;
    entry->context = state;

    // add default VLAN
    for(i = 0; i < portCnt; i++)
        portList[i] = i;
    if(BridgeForwarding_addVLAN(state, BRIDGE_DEF_VID, portList, portCnt) != 0)
    {   resu = -3; goto fail; }
    free(portList);

    if(HandlerTable_registerHandler(table, entry) != 0)
    {   resu = -2; goto fail; }

    return 0;

fail:
    fputs("could not init brdige_forwarding!\n", stderr);

    if(iState != NULL)
        free(iState);

    if(defVIDs != NULL)
        free(defVIDs);

    if(entry != NULL)
        free(entry);

    if(portList != NULL)
        free(portList);

    return resu;
}

/*
 *
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *            -2: invalid port
 *            -3: VID invalid
 */
int32_t BridgeForwarding_setPortDefauldVID(struct BridgeForwarding_state *state, uint16_t vid, uint32_t portIdx)
{
    struct internalState *iState;

    if(state == NULL || state->state == NULL)
        return -1;

    iState = state->state;

    if(iState->defaultVIDs == NULL)
        return -1;

    if(portIdx >= state->portCnt)
        return -2;

    if((vid & ETHERNET_VID_MASK) != vid)
        return -3;

    iState->defaultVIDs[portIdx] = vid;

    return 0;
}

/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *            -2: VLAN already exists
 *            -3: invalid port
 *            -4: VID invalid
 *            -5: could not allocate memory
 */
int32_t BridgeForwarding_addVLAN(struct BridgeForwarding_state *state, uint16_t vid, uint32_t *portEnabled, uint32_t portEnabledCnt)
{
    struct internalState *iState;
    uint32_t i;

    if(state == NULL || state->state == NULL)
        return -1;

    iState = state->state;

    if(iState->vlanAllocCnt > 0 &&  iState->vlans == NULL)
        return -1;

    if(findVLANbyVID(state, vid) >= 0)
        return -2;

    if((vid & ETHERNET_VID_MASK) != vid)
        return -4;

    for(i = 0; i < portEnabledCnt; i++)
        if(portEnabled[i] >= state->portCnt)
            return -3;

    if(iState->vlanCnt >= iState->vlanAllocCnt)
    {
        struct vlan *v_old = iState->vlans;
        iState->vlanAllocCnt++;
        iState->vlans = realloc(v_old, ((uint64_t)iState->vlanAllocCnt) * sizeof(struct vlan));
        if(iState->vlans == NULL)
        {
            iState->vlans = v_old;
            iState->vlanAllocCnt--;
            return -5;
        }
    }

    iState->vlans[iState->vlanCnt].vid = vid;
    iState->vlans[iState->vlanCnt].portFlags = malloc((state->portCnt / 8) + 1); // 8 Ports fit into on byte
    if(iState->vlans[iState->vlanCnt].portFlags == NULL)
        return -5;

    memset(iState->vlans[iState->vlanCnt].portFlags, 0, (state->portCnt / 8) + 1);

    for(i = 0; i < portEnabledCnt; i++)
    {
        uint32_t idx = PORTNO_TO_PORTFLAGSIDX(portEnabled[i]);
        uint8_t mask = PORTNO_TO_PORTFLAGSMASK(portEnabled[i]);
        iState->vlans[iState->vlanCnt].portFlags[idx] |= mask;
    }

    iState->vlanCnt++;

    return 0;
}
/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *            -2: VLAN not found
 *            -3: invalid port
 *            -4: VID invalid
 */
int32_t BridgeForwarding_updateVLAN(struct BridgeForwarding_state *state, uint16_t vid, uint32_t *portEnabled, uint32_t portEnabledCnt)
{
    struct internalState *iState;
    int64_t i, vIdx;

    if(state == NULL || state->state == NULL)
        return -1;

    iState = state->state;

    if(iState->vlanAllocCnt > 0 &&  iState->vlans == NULL)
        return -1;

    if((vid & ETHERNET_VID_MASK) != vid)
        return -4;

    for(i = 0; i < portEnabledCnt; i++)
        if(portEnabled[i] >= state->portCnt)
            return -3;

    vIdx = findVLANbyVID(state, vid);
    if(vIdx < 0)
        return -2;

    for(i = 0; i < portEnabledCnt; i++)
    {
        uint32_t idx = PORTNO_TO_PORTFLAGSIDX(portEnabled[i]);
        uint8_t mask = PORTNO_TO_PORTFLAGSMASK(portEnabled[i]);
        iState->vlans[vIdx].portFlags[idx] |= mask;
    }

    return 0;
}
/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *            -2: VLAN not found
 *            -3: VID invalid
 */
int32_t BridgeForwarding_delVLAN(struct BridgeForwarding_state *state, uint16_t vid)
{
    struct internalState *iState;
    uint32_t i, j, resu;

    if(state == NULL || state->state == NULL)
        return -1;

    iState = state->state;

    if(iState->vlanAllocCnt > 0 &&  iState->vlans == NULL)
        return -1;

    if((vid & ETHERNET_VID_MASK) != vid)
        return -3;

    // i is read index
    // j is write index
    for(i = 0, j = 0; i < iState->vlanCnt; i++, j++)
    {
        if(iState->vlans[i].vid == vid)
        {
            // okay, delete it (which means: don't move it forward)
            j--;
            free(iState->vlans[i].portFlags);
            iState->vlans[i].portFlags = NULL;
            iState->vlans[i].vid = 0;
        }
        else if(i != j)
        {
            // fill up gaps
            iState->vlans[j] = iState->vlans[i];
        }
    }

    // check, if one was deleted
    if(i != j)
        resu = 0; // yes
    else
        resu = -2; // no

    iState->vlanCnt = j;

    return resu;
}

/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 */
int32_t BridgeForwarding_delAllVLAN(struct BridgeForwarding_state *state)
{
    struct internalState *iState;
    uint32_t i, cnt;

    if(state == NULL || state->state == NULL)
        return -1;

    iState = state->state;

    cnt = iState->vlanCnt;
    iState->vlanCnt = 0;

    for(i = 0; i < cnt; i++)
        free(iState->vlans[i].portFlags);

    return 0;
}

/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *            -2: entry already exists
 *            -3: invalid port
 *            -4: could not allocate memory
 */
int32_t BridgeForwarding_addDstMACFilter(struct BridgeForwarding_state *state, uint8_t dstMac[6], uint32_t *portEnabled, uint32_t *portQueuesEnabled, uint32_t portEnabledCnt)
{
    // TODO: portQueues
    struct internalState *iState;
    uint32_t i;

    if(state == NULL || state->state == NULL)
        return -1;

    iState = state->state;

    if(iState->macFilterCnt > 0 &&  iState->macFilters == NULL)
        return -1;

    for(i = 0; i < portEnabledCnt; i++)
        if(portEnabled[i] >= state->portCnt)
            return -3;

    if(findMacFilterbyMAC(state, dstMac) >= 0)
        return -2;

    if(iState->macFilterCnt >= iState->macFilterAllocCnt)
    {
        struct macFilter *mf_old = iState->macFilters;
        iState->macFilterAllocCnt++;
        iState->macFilters = realloc(mf_old, ((uint64_t)iState->macFilterAllocCnt) * sizeof(struct macFilter));
        if(iState->macFilters == NULL)
        {
            iState->macFilters = mf_old;
            iState->macFilterAllocCnt--;
            return -4;
        }
    }

    memcpy(iState->macFilters[iState->macFilterCnt].mac, dstMac, ETHERNET_MAC_LEN);
    iState->macFilters[iState->macFilterCnt].portFlags = malloc((state->portCnt / 8) + 1); // 8 Ports fit into on byte
    if(iState->macFilters[iState->macFilterCnt].portFlags == NULL)
        return -4;

    memset(iState->macFilters[iState->macFilterCnt].portFlags, 0, (state->portCnt / 8) + 1);

    for(i = 0; i < portEnabledCnt; i++)
    {
        uint32_t idx = PORTNO_TO_PORTFLAGSIDX(portEnabled[i]);
        uint8_t mask = PORTNO_TO_PORTFLAGSMASK(portEnabled[i]);
        iState->macFilters[iState->macFilterCnt].portFlags[idx] |= mask;
    }

    iState->macFilterCnt++;

    return 0;
}
/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *            -2: entry not found
 *            -3: invalid port
 */
int32_t BridgeForwarding_updateDstMACFilter(struct BridgeForwarding_state *state, uint8_t dstMac[6], uint32_t *portEnabled, uint32_t *portQueuesEnabled, uint32_t portEnabledCnt)
{
    // TODO: portQueues
    struct internalState *iState;
    int64_t i, mfIdx;

    if(state == NULL || state->state == NULL)
        return -1;

    iState = state->state;

    if(iState->macFilterCnt > 0 &&  iState->macFilters == NULL)
        return -1;

    for(i = 0; i < portEnabledCnt; i++)
        if(portEnabled[i] >= state->portCnt)
            return -3;

    mfIdx = findMacFilterbyMAC(state, dstMac);
    if(mfIdx < 0)
        return -2;

    for(i = 0; i < portEnabledCnt; i++)
    {
        uint32_t idx = PORTNO_TO_PORTFLAGSIDX(portEnabled[i]);
        uint8_t mask = PORTNO_TO_PORTFLAGSMASK(portEnabled[i]);
        iState->macFilters[mfIdx].portFlags[idx] |= mask;
    }

    return 0;
}
/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *            -2: entry not found
 */
int32_t BridgeForwarding_delDstMACFilter(struct BridgeForwarding_state *state, uint8_t dstMac[6])
{
    // TODO: portQueues
    struct internalState *iState;
    uint32_t i, j, resu;

    if(state == NULL || state->state == NULL)
        return -1;

    iState = state->state;

    if(iState->macFilterAllocCnt > 0 &&  iState->macFilters == NULL)
        return -1;

    // i is read index
    // j is write index
    for(i = 0, j = 0; i < iState->macFilterCnt; i++, j++)
    {
        if(cmpMacs(iState->macFilters[i].mac, dstMac) == 0)
        {
            // okay, delete it (which means: don't move it forward)
            j--;
            free(iState->macFilters[i].portFlags);
            iState->macFilters[i].portFlags = NULL;
            memset(iState->macFilters[i].mac, 0, ETHERNET_MAC_LEN);
        }
        else if(i != j)
        {
            // fill up gaps
            iState->macFilters[j] = iState->macFilters[i];
        }
    }

    // check, if one was deleted
    if(i != j)
        resu = 0; // yes
    else
        resu = -2; // no

    iState->macFilterCnt = j;

    return resu;
}


static void packetHandler(const struct Packet_packet *p, void *context)
{
    struct BridgeForwarding_state *s;
    struct internalState *is;
    uint16_t vid;
    uint8_t *portsEnabled;
    int64_t vIdx, mfIdx, mlIdx;
    struct vlan *v = NULL;
    struct macFilter *f = NULL;
    struct macLearningEntry *l = NULL;
    struct Ethernet_headerVLAN *ethHdr;
    uint32_t i, idx, mask;
    struct Packet_packet pOut, pOutV;
    int wasTagged;

    if(context == NULL || p == NULL)
        return;

    s = context;
    if(s->state == NULL || s->ports == NULL || s->portCnt == 0)
        return;

    is = s->state;
    if(is->defaultVIDs == NULL || (is->macFilterCnt > 0 && is->macFilters == NULL) || (is->vlanCnt > 0 && is->vlans == NULL) || (is->macLearningCnt > 0 && is->macLearnings == NULL))
        return;

    if(p->len < sizeof(struct Ethernet_headerVLAN))
        return;

    ethHdr = (struct Ethernet_headerVLAN*)p->packet;

    if(Ethernet_isPacketVLAN(p->packet, p->len))
    {
        vid = Common_nToLu16( *( (uint16_t*)(ethHdr->tci) ) ) & ETHERNET_VID_MASK;
        wasTagged = 1;
    }
    else
    {
        vid = is->defaultVIDs[p->port];
        wasTagged = 0;
    }

    portsEnabled = malloc((s->portCnt / 8) + 1);
    if(portsEnabled == NULL)
        return;
    memset(portsEnabled, 0, (s->portCnt / 8) + 1);

    vIdx = findVLANbyVID(s, vid);
    mfIdx = findMacFilterbyMAC(s, ethHdr->dst);
    mlIdx = findMacLearnedbyMAC(s, ethHdr->dst);

    memset(&pOut, 0, sizeof(pOut));
    memset(&pOutV, 0, sizeof(pOutV));

    fprintf(stdout, ">> %02X:%02X:%02X:%02X:%02X:%02X (%u): %u [%c:%u] -> ", ethHdr->dst[0], ethHdr->dst[1], ethHdr->dst[2], ethHdr->dst[3], ethHdr->dst[4], ethHdr->dst[5], p->len, p->port, wasTagged ? 't' : 'u', vid);

    if(vIdx < 0)
        goto noForwarding;

    idx = PORTNO_TO_PORTFLAGSIDX(p->port);
    mask = PORTNO_TO_PORTFLAGSMASK(p->port);

    v = &(is->vlans[vIdx]);

    if((v->portFlags[idx] & mask ) == 0)
        goto noForwarding; // this vid is not active on this port

    if(mfIdx >= 0)
        f = &(is->macFilters[mfIdx]);
    if(mlIdx >= 0)
        l = &(is->macLearnings[mlIdx]);

    if(wasTagged)
    {
        pOutV.packet = p->packet;
        pOutV.len = p->len;
        // initialize untagged packet format
        pOut.len = p->len - 4;
        pOut.packet = malloc(pOut.len);
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
        pOutV.packet = malloc(pOutV.len);
        if(pOutV.packet == NULL)
            goto fail;
        memcpy(&(pOutV.packet[ 0]), &(p->packet[ 0]),          12); // copy macs
        pOutV.packet[12] = ETHERNET_TYPE_VLAN[0]; // 802.1Q Tag type
        pOutV.packet[13] = ETHERNET_TYPE_VLAN[1];
        pOutV.packet[14] = 0xFF & (vid >> 8); // tci
        pOutV.packet[15] = 0xFF & vid;
        memcpy(&(pOutV.packet[16]), &(p->packet[12]), p->len - 12); // copy type and payload

    }

    for(i = 0; i < s->portCnt; i++)
    {
        struct Packet_packet *toSend;

        idx = PORTNO_TO_PORTFLAGSIDX(i);
        mask = PORTNO_TO_PORTFLAGSMASK(i);

        if((v->portFlags[idx] & mask) == 0)
            continue; // port is not in vlan
        if(f != NULL)
            if((f->portFlags[idx] & mask) == 0)
                continue; // this port is filtered by rule
        if(l != NULL)
            if((l->outPort != i) && f == NULL)
                continue; // no filtering rule and this is not the known port for target host
        if(l == NULL && f == NULL)
            if(i == p->port)
                continue; // do not broadcast packet to sender (if there is no rule saying anything else)

        // okay, if we are here, then the packet is supposed to be sent on this port

        // determine, if it is to be sent tagged or untagged
        if(vid == is->defaultVIDs[i])
            toSend = &pOut;
        else
            toSend = &pOutV;

        if(Port_send(&(s->ports[i]), toSend))
            fprintf(stdout, "<%d,%s>", errno, strerror(errno));
        portsEnabled[idx] |= mask;
        // TODO: analyze outgoing timestamps ...
    }

noForwarding:
fail:

    for(i = 0; i < s->portCnt; i++)
        fprintf(stdout, "%s", (portsEnabled[PORTNO_TO_PORTFLAGSIDX(i)] & PORTNO_TO_PORTFLAGSMASK(i)) ? "1" : "0");
    fputs("\n", stdout);

    if(wasTagged && pOut.packet != NULL)
        free(pOut.packet);
    if(!wasTagged && pOutV.packet != NULL)
        free(pOutV.packet);
    free(portsEnabled);

    learnMACNotifier(s, ethHdr->src, p->port, &(p->t));
}

static void learnMACNotifier(struct BridgeForwarding_state *state, const uint8_t mac[ETHERNET_MAC_LEN], const uint32_t portIdx, const struct Common_timestamp *t)
{
    int64_t idx = findMacLearnedbyMAC(state, mac);
    struct internalState *is = state->state;

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

static int64_t findVLANbyVID(const struct BridgeForwarding_state *state, const uint16_t vid)
{
    struct internalState *iState;
    uint32_t i;

    iState = state->state;

    for(i = 0; i < iState->vlanCnt; i++)
        if(iState->vlans[i].vid == vid)
            return i;
    return -1;
}

static int64_t findMacFilterbyMAC(const struct BridgeForwarding_state *state, const uint8_t mac[ETHERNET_MAC_LEN])
{
    struct internalState *iState;
    uint32_t i;

    iState = state->state;

    for(i = 0; i < iState->macFilterCnt; i++)
        if(cmpMacs(iState->macFilters[i].mac, mac) == 0)
            return i;

    return -1;
}


static int64_t findMacLearnedbyMAC(const struct BridgeForwarding_state *state, const uint8_t mac[ETHERNET_MAC_LEN])
{
    struct internalState *iState;
    uint32_t i;

    iState = state->state;

    for(i = 0; i < iState->macLearningCnt; i++)
        if(cmpMacs(iState->macLearnings[i].mac, mac) == 0)
            return i;

    return -1;
}

/*
 * Return values:
 *             1: mac2 is larger
 *             0: equal
 *            -1: mac1 is larger
 */
static int32_t cmpMacs(const uint8_t mac1[ETHERNET_MAC_LEN], const uint8_t mac2[ETHERNET_MAC_LEN])
{
    uint32_t i;
    for(i = 0; i < ETHERNET_MAC_LEN; i++)
    {
        if(mac2[i] > mac1[i])
            return 1;
        else if(mac1[i] > mac2[i])
            return -1;
    }
    return 0;
}
