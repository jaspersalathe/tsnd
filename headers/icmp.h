/*
 * icmp.h
 *
 *  Created on: 24.04.2014
 *      Author: jasper
 */

#ifndef ICMP_H_
#define ICMP_H_

#include <inttypes.h>

#include "common.h"
#include "ip4.h"

const extern uint8_t ICMP_IP4_PROTOCOL;

struct icmp_header
{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint8_t payload[0];
} PACKED;

#endif /* ICMP_H_ */
