/*
 * port.c
 *
 *  Created on: 25.04.2014
 *      Author: jasper
 */

#include "port.h"

#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>


#define MIN(x, y)                   \
        ({ __typeof__ (x) _x = (x); \
           __typeof__ (y) _y = (y); \
           _x < _y ? _x : _y;       })

static int32_t getInterfaceIndex(struct Port *p)
{
    struct ifreq ifr;
    int resu;

    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_ifrn.ifrn_name, p->devName, IFNAMSIZ);

    resu = ioctl(p->rawFd, SIOCGIFINDEX, &ifr);
    if(resu < 0)
        return -1;
    p->ifIdx = ifr.ifr_ifru.ifru_ivalue;
    return 0;
}

static int32_t getInterfaceMac(struct Port *p)
{
    struct ifreq ifr;
    int resu;

    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_ifrn.ifrn_name, p->devName, IFNAMSIZ);

    resu = ioctl(p->rawFd, SIOCGIFHWADDR, &ifr);
    if(resu < 0)
        return -1;
    memcpy(p->macAddr, ifr.ifr_ifru.ifru_hwaddr.sa_data, ETHERNET_MAC_LEN);

    return 0;
}

static void getTime(struct timespec *t)
{
    memset(t, 0, sizeof(struct timespec));
    clock_gettime(CLOCK_REALTIME, t);
}

/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *            -2: could not open raw socket
 *            -3: could not find interface
 *            -4: could not bind interface
 *            -5: could not set promiscuous mode
 */
int32_t Port_open(const char *devName, struct Port *port)
{
    struct sockaddr_ll sockaddr;
    struct packet_mreq pReq;

    if(devName == NULL || port == NULL)
        return -1;

    port->devName = strdup(devName);

    port->rawFd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(port->rawFd == -1)
        return -2;

    if(getInterfaceIndex(port) != 0)
        return -3;

    if(getInterfaceMac(port) != 0)
        return -3;

    memset(&sockaddr, 0, sizeof(sockaddr));
    sockaddr.sll_ifindex = port->ifIdx;
    sockaddr.sll_family = AF_PACKET;
    sockaddr.sll_protocol = htons(ETH_P_ALL);
    if(bind(port->rawFd, (struct sockaddr *)&sockaddr, sizeof(sockaddr)))
        return -4;

    if(setsockopt(port->rawFd, SOL_SOCKET, SO_BINDTODEVICE, port->devName, strlen(port->devName)))
        return -4;

    pReq.mr_ifindex = port->rawFd;
    pReq.mr_type = PACKET_MR_PROMISC;
    pReq.mr_alen = 0;
    if(setsockopt(port->rawFd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &pReq, sizeof(pReq)))
        return -5;

    return 0;
}

/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *            -2: could not register/unregister group
 */
int32_t Port_addMcastGrp(struct Port *port, const uint8_t *mcastAddr, const uint32_t len)
{
    struct packet_mreq pReq;
    if(port == NULL || mcastAddr == NULL)
        return -1;

    pReq.mr_ifindex = port->ifIdx;
    pReq.mr_type = PACKET_MR_MULTICAST;
    pReq.mr_alen = MIN(len, sizeof(pReq.mr_address));
    memcpy(pReq.mr_address, mcastAddr, pReq.mr_alen);

    if(setsockopt(port->rawFd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &pReq, sizeof(pReq)))
        return -2;
    return 0;
}

/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *            -2: could not register/unregister group
 */

int32_t Port_remMcastGrp(struct Port *port, const uint8_t *mcastAddr, const uint32_t len)
{
    struct packet_mreq pReq;
    if(port == NULL || mcastAddr == NULL)
        return -1;

    pReq.mr_ifindex = port->ifIdx;
    pReq.mr_type = PACKET_MR_MULTICAST;
    pReq.mr_alen = MIN(len, sizeof(pReq.mr_address));
    memcpy(pReq.mr_address, mcastAddr, pReq.mr_alen);

    if(setsockopt(port->rawFd, SOL_PACKET, PACKET_DROP_MEMBERSHIP, &pReq, sizeof(pReq)))
        return -2;
    return 0;
}

/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 */
int32_t Port_close(struct Port *port)
{
    return 0;
}

/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *            -2: could not send packet
 */
int32_t Port_send(struct Port *port, struct Packet_packet *packet)
{
    int resu;
    struct msghdr hdr;
    struct iovec iov;
    char control[256];

    if(port == NULL || packet == NULL)
        return -1;

    hdr.msg_name = NULL; hdr.msg_namelen = 0;
    hdr.msg_flags = 0;
    iov.iov_base = packet->packet;
    iov.iov_len = packet->len;
    hdr.msg_iov = &iov;
    hdr.msg_iovlen = 1;
    memset(control, 0, sizeof(control));
    hdr.msg_control = control;
    hdr.msg_controllen = sizeof(control);

    resu = sendmsg(port->rawFd, &hdr, 0);

    if(resu != packet->len)
        return -2;

    getTime(&(packet->t.t));
    return 0;
}

/*
 * Return values:
 *             0: success
 *            -1: pointer NULL
 *            -2: could not receive
 */
int32_t Port_recv(struct Port *port, struct Packet_packet *packet)
{
    int resu;
    struct msghdr hdr;
    struct iovec iov;
    char control[256];

    if(port == NULL || packet == NULL || packet->packet == NULL)
        return -1;

    hdr.msg_name = NULL; hdr.msg_namelen = 0;
    hdr.msg_flags = 0;
    iov.iov_base = packet->packet;
    iov.iov_len = packet->len;
    hdr.msg_iov = &iov;
    hdr.msg_iovlen = 1;
    memset(control, 0, sizeof(control));
    hdr.msg_control = control;
    hdr.msg_controllen = sizeof(control);

    resu = recvmsg(port->rawFd, &hdr, 0);

    if(resu < 1)
        return -2;

    packet->port = port->portIdx;
    getTime(&(packet->t.t));
    packet->len = resu;

    return 0;
}
