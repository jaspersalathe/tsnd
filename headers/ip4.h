/*
 * ip4.h
 *
 *  Created on: 24.04.2014
 *      Author: jasper
 */

#ifndef IP4_H_
#define IP4_H_

#include <inttypes.h>

#include "common.h"
#include "ethernet.h"

#define IP4_ADDR_LEN 4

const extern uint8_t IP4_ETH_TYPE[ETHERNET_TYPE_LEN];

struct ip4_header
{
    uint8_t version_headerLen;
    uint8_t tos;
    uint16_t len;
    uint16_t id;
    uint16_t flag_fragOffset;
    uint8_t ttl;
    uint8_t prot;
    uint16_t hdrChecksum;
    uint8_t srcIp[IP4_ADDR_LEN];
    uint8_t dstIp[IP4_ADDR_LEN];
} PACKED;

#endif /* IP4_H_ */
