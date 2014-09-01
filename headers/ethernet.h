/*
 * ethernet.h
 *
 *  Created on: 24.04.2014
 *      Author: jasper
 */

#ifndef ETHERNET_H_
#define ETHERNET_H_

#include <inttypes.h>

#include "common.h"

#define ETHERNET_MAC_LEN 6
#define ETHERNET_MAC_GROUP_MASK 0x01
#define ETHERNET_TYPE_LEN 2
#define ETHERNET_VLAN_TCI_LEN 2
#define ETHERNET_VID_MASK 0xFFF
#define ETHERNET_VID_WILDCARD 0xFFF
#define ETHERNET_VID_DEFAULT 0x001

struct Ethernet_header
{
    uint8_t dst[ETHERNET_MAC_LEN];
    uint8_t src[ETHERNET_MAC_LEN];
    uint8_t type[ETHERNET_TYPE_LEN];
    uint8_t payload[0];
} PACKED;

struct Ethernet_headerVLAN
{
    uint8_t dst[ETHERNET_MAC_LEN];
    uint8_t src[ETHERNET_MAC_LEN];
    uint8_t type[ETHERNET_TYPE_LEN];
    uint8_t tci[ETHERNET_VLAN_TCI_LEN];
    uint8_t vlanType[ETHERNET_TYPE_LEN];
    uint8_t payload[0];
} PACKED;

const extern uint8_t ETHERNET_MAC_MASK[ETHERNET_MAC_LEN];
const extern uint8_t ETHERNET_TYPE_MASK[ETHERNET_TYPE_LEN];

const extern uint8_t ETHERNET_TYPE_VLAN[ETHERNET_TYPE_LEN];

int Ethernet_isPacketVLAN(const uint8_t *packet, const uint32_t len);

uint32_t Ethernet_getHeaderLength(const uint8_t *packet, const uint32_t len);

/*
 * Return values:
 *             1: mac2 is larger
 *             0: equal
 *            -1: mac1 is larger
 */
int32_t Ethernet_cmpMacs(const uint8_t mac1[ETHERNET_MAC_LEN], const uint8_t mac2[ETHERNET_MAC_LEN]);
int32_t Ethernet_cmpMacsMasked(const uint8_t mac1[ETHERNET_MAC_LEN], const uint8_t mac2[ETHERNET_MAC_LEN], const uint8_t mask[ETHERNET_MAC_LEN]);

int Ethernet_isGroupMac(const uint8_t mac[ETHERNET_MAC_LEN]);

#endif /* ETHERNET_H_ */
