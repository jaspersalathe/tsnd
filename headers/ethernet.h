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
#define ETHERNET_TYPE_LEN 2
#define ETHERNET_VLAN_TCI_LEN 2
#define ETHERNET_VID_MASK 0x7FF


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

#endif /* ETHERNET_H_ */
