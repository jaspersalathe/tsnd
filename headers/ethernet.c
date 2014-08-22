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
