/*
 * port.h
 *
 *  Created on: 25.04.2014
 *      Author: jasper
 */

#ifndef PORT_H_
#define PORT_H_

#include <inttypes.h>
#include "headers/ethernet.h"
#include "packet.h"


struct Port
{
    uint8_t *devName;
    uint8_t macAddr[ETHERNET_MAC_LEN];
    uint32_t portIdx;
};

int32_t Port_open(const uint8_t *devName, struct Port *port);
int32_t Port_close(struct Port *port);
int32_t Port_send(struct Port *port, struct Packet_packet *packet);

#endif /* PORT_H_ */
