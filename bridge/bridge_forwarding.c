/*
 * bridge_forwarding.c
 *
 *  Created on: 18.08.2014
 *      Author: jasper
 */


#include "bridge_forwarding.h"

#include "bridge.h"

#include <stdlib.h>
#include <string.h>


struct vlan
{
    uint16_t vid;
    uint32_t *ports;
    uint32_t portCnt;
};

struct internalState
{
    uint16_t *defaultVIDs;

    struct vlan *vlans;
    uint32_t vlanCnt;
};

const uint8_t NULL_MAC[ETHERNET_MAC_LEN] =
{0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static struct HandlerTable_filterEntry bridgeFilter[] =
{
        {HandlerTable_packetField_ETH_DST, 0, ETHERNET_MAC_LEN, NULL_MAC, NULL_MAC},
        {HandlerTable_packetField_NONE, 0, 0, NULL, NULL}
};

static void packetHandler(const struct Packet_packet *packet, void *context);

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

    if(state == NULL || table == NULL || ports == NULL)
        return -1;
    if(portCnt < 1)
        return -4;

    iState = malloc(sizeof(struct internalState));
    defVIDs = malloc(((uint64_t)portCnt) * sizeof(uint16_t));
    entry = malloc(sizeof(struct HandlerTable_tableEntry));
    if(iState == NULL || defVIDs == NULL || entry == NULL)
    {   resu = -3; goto fail; }

    memset(iState, 0, sizeof(struct internalState));
    memset(defVIDs, 0, ((uint64_t)portCnt) * sizeof(uint16_t))
    memset(entry, 0, sizeof(struct HandlerTable_tableEntry));

    state->ports = ports;
    state->portCnt = portCnt;
    state->state = iState;

    iState->vlans = NULL;
    iState->vlanCnt = 0;

    iState->defaultVIDs = defVIDs;
    for(i = 0; i < portCnt; i++)
        defVIDs[i] = BRIDGE_DEF_VID;

    entry->filters = bridgeFilter;
    entry->handler = &packetHandler;
    entry->context = state;

    if(HandlerTable_registerHandler(table, entry) != 0)
    {   resu = -2; goto fail; }

    return 0;

fail:
    fputs(stderr, "could not init brdige_forwarding!\n");

    if(iState != NULL)
        free(iState);

    if(defVIDs != NULL)
        free(defVIDs);

    if(entry != NULL)
        free(entry);

    return resu;
}

/*
 *
 * Return values:
 *             0: success
 *            -1: pointer NULL
 */
int32_t BridgeForwarding_setPortDefauldVID(struct BridgeForwarding_state *state, uint16_t vid, uint32_t portIdx)
{

    return 0;
}

/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *            -2: VLAN already exists
 */
int32_t BridgeForwarding_addVLAN(struct BridgeForwarding_state *state, uint16_t vid, uint32_t *portEnabled, uint32_t portEnabledCnt)
{

    return 0;
}
/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *            -2: VLAN not found
 */
int32_t BridgeForwarding_updateVLAN(struct BridgeForwarding_state *state, uint16_t vid, uint32_t *portEnabled, uint32_t portEnabledCnt)
{

    return 0;
}
/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *            -2: VLAN not found
 */
int32_t BridgeForwarding_delVLAN(struct BridgeForwarding_state *state, uint16_t vid)
{

    return 0;
}

/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *            -2: entry already exists
 */
int32_t BridgeForwarding_addDstMACFilter(struct BridgeForwarding_state *state, uint8_t dstMac[6], uint32_t *portEnabled, uint32_t *portQueuesEnabled, uint32_t portEnabledCnt)
{

    return 0;
}
/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *            -2: entry not found
 */
int32_t BridgeForwarding_updateDstMACFilter(struct BridgeForwarding_state *state, uint8_t dstMac[6], uint32_t *portEnabled, uint32_t *portQueuesEnabled, uint32_t portEnabledCnt)
{

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

    return 0;
}


static void packetHandler(const struct Packet_packet *packet, void *context)
{

}
