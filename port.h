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
    char *devName;
    uint8_t macAddr[ETHERNET_MAC_LEN];
    uint32_t portIdx;
    int rawFd;
    int ifIdx;
};

/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *            -2: could not open raw socket
 *            -3: could not find interface
 *            -4: could not bind interface
 *            -5: could not set promiscuous mode
 */
int32_t Port_open(const char *devName, struct Port *port);

/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *            -2: could not register/unregister group
 */
int32_t Port_addMcastGrp(struct Port *port, const uint8_t *mcastAddr, const uint32_t len);
int32_t Port_remMcastGrp(struct Port *port, const uint8_t *mcastAddr, const uint32_t len);

/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 */
int32_t Port_close(struct Port *port);

/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *            -2: could not send packet
 */
int32_t Port_send(struct Port *port, struct Packet_packet *packet);

/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *            -2: could not receive
 */
int32_t Port_recv(struct Port *port, struct Packet_packet *packet);

#endif /* PORT_H_ */
