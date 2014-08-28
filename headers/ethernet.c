/*
 * ethernet.c
 *
 *  Created on: 24.04.2014
 *      Author: jasper
 */

#include "ethernet.h"

#include <stdlib.h>

const uint8_t ETHERNET_MAC_MASK[ETHERNET_MAC_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
const uint8_t ETHERNET_TYPE_MASK[ETHERNET_TYPE_LEN] = {0xFF, 0xFF};

const uint8_t ETHERNET_TYPE_VLAN[ETHERNET_TYPE_LEN] = {0x81, 0x00};

int Ethernet_isPacketVLAN(const uint8_t *packet, const uint32_t len)
{
    const struct Ethernet_header *eth = (struct Ethernet_header*)packet;

    if(len < sizeof(struct Ethernet_headerVLAN) || eth == NULL)
        return 0;

    for(int i = 0; i < ETHERNET_TYPE_LEN; i++)
        if(ETHERNET_TYPE_VLAN[i] != eth->type[i])
            return 0;
    return 1;
}

uint32_t Ethernet_getHeaderLength(const uint8_t *packet, const uint32_t len)
{
    if(packet == NULL || len < sizeof(struct Ethernet_header))
        return 0;
    if(Ethernet_isPacketVLAN(packet, len))
        return sizeof(struct Ethernet_headerVLAN);
    else
        return sizeof(struct Ethernet_header);
}

/*
 * Return values:
 *             1: mac2 is larger
 *             0: equal
 *            -1: mac1 is larger
 */
int32_t Ethernet_cmpMacs(const uint8_t mac1[ETHERNET_MAC_LEN], const uint8_t mac2[ETHERNET_MAC_LEN])
{
    return Ethernet_cmpMacsMasked(mac1, mac2, ETHERNET_MAC_MASK);
}

int32_t Ethernet_cmpMacsMasked(const uint8_t mac1[ETHERNET_MAC_LEN], const uint8_t mac2[ETHERNET_MAC_LEN], const uint8_t mask[ETHERNET_MAC_LEN])
{
    uint32_t i;
    uint8_t b1, b2;
    for(i = 0; i < ETHERNET_MAC_LEN; i++)
    {
        b1 = mac1[i] & mask[i];
        b2 = mac2[i] & mask[i];
        if(b2 > b1)
            return 1;
        else if(b1 > b2)
            return -1;
    }
    return 0;
}

int Ethernet_isGroupMac(const uint8_t mac[ETHERNET_MAC_LEN])
{
    return (mac[0] & ETHERNET_MAC_GROUP_MASK) == ETHERNET_MAC_GROUP_MASK;
}
