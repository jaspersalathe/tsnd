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


struct BridgeForwarding_state
{
	struct Port *ports;
	uint32_t portCnt;
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
int32_t BridgeForwarding_init(struct BridgeForwarding_state *state, struct HandlerTable_table *table, struct Port *ports, uint32_t portCnt);

/*
 *
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *            -2: invalid port
 *            -3: VID invalid
 */
int32_t BridgeForwarding_setPortDefauldVID(struct BridgeForwarding_state *state, uint16_t vid, uint32_t portIdx);

/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *            -2: VLAN already exists
 *            -3: invalid port
 *            -4: VID invalid
 *            -5: could not allocate memory
 */
int32_t BridgeForwarding_addVLAN(struct BridgeForwarding_state *state, uint16_t vid, uint32_t *portEnabled, uint32_t portEnabledCnt);
/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *            -2: VLAN not found
 *            -3: invalid port
 *            -4: VID invalid
 */
int32_t BridgeForwarding_updateVLAN(struct BridgeForwarding_state *state, uint16_t vid, uint32_t *portEnabled, uint32_t portEnabledCnt);
/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *            -2: VLAN not found
 *            -3: VID invalid
 */
int32_t BridgeForwarding_delVLAN(struct BridgeForwarding_state *state, uint16_t vid);
/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 */
int32_t BridgeForwarding_delAllVLAN(struct BridgeForwarding_state *state);

/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *            -2: entry already exists
 *            -3: invalid port
 *            -4: could not allocate memory
 */
int32_t BridgeForwarding_addDstMACFilter(struct BridgeForwarding_state *state, uint8_t dstMac[ETHERNET_MAC_LEN], uint32_t *portEnabled, uint32_t *portQueuesEnabled, uint32_t portEnabledCnt);
/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *            -2: entry not found
 *            -3: invalid port
 */
int32_t BridgeForwarding_updateDstMACFilter(struct BridgeForwarding_state *state, uint8_t dstMac[ETHERNET_MAC_LEN], uint32_t *portEnabled, uint32_t *portQueuesEnabled, uint32_t portEnabledCnt);
/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *            -2: entry not found
 */
int32_t BridgeForwarding_delDstMACFilter(struct BridgeForwarding_state *state, uint8_t dstMac[ETHERNET_MAC_LEN]);

#endif /* BRIDGE_FORWARDING_H_ */
