/*
 * ptp.h
 *
 *  Created on: 24.04.2014
 *      Author: jasper
 */

#ifndef PTP_H_
#define PTP_H_

#include <inttypes.h>

#include "common.h"
#include "port.h"
#include "ethernet.h"
#include "ptp/ptp_config.h"

const extern uint8_t PTP_ETH_TYPE[ETHERNET_TYPE_LEN];

const extern uint8_t PTP_ETH_MAC_GENERAL[ETHERNET_MAC_LEN];
const extern uint8_t PTP_ETH_MAC_P2P[ETHERNET_MAC_LEN];

#define PTP_TRANSPORT_SPECIFIC_DEFAULT 0x00
#define PTP_TRANSPORT_SPECIFIC_AVB     0x01

#define PTP_VERSIONPTP_0 0
#define PTP_VERSIONPTP_1 1
#define PTP_VERSIONPTP_2 2
#ifndef PTP_VERSIONPTP
# define PTP_VERSIONPTP PTP_VERSIONPTP_2
#endif

#define PTP_MESSAGE_TYPE_SYNC                   0x00
#define PTP_MESSAGE_TYPE_DELAY_REQ              0x01
#define PTP_MESSAGE_TYPE_PDELAY_REQ             0x02
#define PTP_MESSAGE_TYPE_PDELAY_RESP            0x03
#define PTP_MESSAGE_TYPE_FOLLOW_UP              0x08
#define PTP_MESSAGE_TYPE_DELAY_RESP             0x09
#define PTP_MESSAGE_TYPE_PDELAY_RESP_FOLLOW_UP  0x0A
#define PTP_MESSAGE_TYPE_ANNOUNCE               0x0B
#define PTP_MESSAGE_TYPE_SIGNALING              0x0C
#define PTP_MESSAGE_TYPE_MANAGEMENT             0x0D

#define PTP_FLAG_ALTERNATE_MASTER   (1<< 0)
#define PTP_FLAG_TWO_STEP           (1<< 1)
#define PTP_FLAG_UNICAST            (1<< 2)
#define PTP_FLAG_PROFILE1           (1<< 5)
#define PTP_FLAG_PROFILE2           (1<< 6)
#define PTP_FLAG_LEAP61             (1<< 8)
#define PTP_FLAG_LEAP59             (1<< 9)
#define PTP_FLAG_CURR_UTC_OFFSET    (1<<10)
#define PTP_FLAG_PTP_TIMESCALE      (1<<11)
#define PTP_FLAG_TIME_TRACABLE      (1<<12)
#define PTP_FLAG_FREQ_TRACABLE      (1<<13)

#define PTP_CONTROL_FIELD_SYNC          0x00
#define PTP_CONTROL_FIELD_DELAY_REQ     0x01
#define PTP_CONTROL_FIELD_FOLLOW_UP     0x02
#define PTP_CONTROL_FIELD_DELAY_RESP    0x03
#define PTP_CONTROL_FIELD_MANAGEMENT    0x04
#define PTP_CONTROL_FIELD_OTHERS        0x05

#define PTP_CLOCKID_LEN 8

struct PTP_portId
{
    uint8_t clockId[PTP_CLOCKID_LEN];
    uint16_t portNo;
} PACKED;

struct PTP_timestamp
{
    uint8_t t[10];
} PACKED;

struct PTP_header
{
    uint8_t transportSpecific_messageType;
#define PTP_GET_TRANSPORTSPECIFIC(ts_mt)    ((  ts_mt>>4)&0x0F)
#define PTP_GET_MESSAGETYPE(ts_mt)          ((  ts_mt>>0)&0x0F)
#define PTP_SET_TRANSP_MSGTYPE(ts, mt)      (((ts&0x0F)<<4) | (mt&0x0F))
    uint8_t reserved_versionPTP;
#define PTP_GET_VERSIONPTP(res_ver)         ((res_ver>>0)&0x0F)
#define PTP_SET_VERSIONPTP(ver)             (ver&0x0F)
    uint16_t messageLen;
    uint8_t domainNumber;
    uint8_t reserved1;
    uint16_t flags;
    uint8_t correction[8];
    uint8_t reserved2[4];
    struct PTP_portId sourcePortId;
    uint16_t sequId;
    uint8_t controlField;
    uint8_t logMessageInterval;
} PACKED;

struct PTP_announce
{
    struct PTP_header hdr;
    struct PTP_timestamp originTimestamp;
    uint16_t currUtcOffset;
    uint8_t reserved1;
    uint8_t grandmasterPrio1;
    uint32_t grandmasterClockQuality;
    uint8_t grandmasterPrio2;
    uint8_t grandmasterId[8];
    uint16_t stepsRemoved;
    uint8_t timeSource;
} PACKED;

struct PTP_sync
{
    struct PTP_header hdr;
    uint8_t originTimestamp[10];
} PACKED;

struct PTP_delayReq
{
    struct PTP_header hdr;
    uint8_t originTimestamp[10];
} PACKED;

struct PTP_followUp
{
    struct PTP_header hdr;
    uint8_t originTimestamp[10];
} PACKED;

struct PTP_delayResp
{
    struct PTP_header hdr;
    uint8_t receiveTimestamp[10];
    struct PTP_portId requestingPortId;
} PACKED;

struct PTP_pDelayReq
{
    struct PTP_header hdr;
    uint8_t originTimestamp[10];
    uint8_t reserved1[10];
} PACKED;

struct PTP_pDelayResp
{
    struct PTP_header hdr;
    uint8_t receiveTimestamp[10];
    struct PTP_portId requestingPortId;
} PACKED;

struct PTP_pDelayRespFollowUp
{
    struct PTP_header hdr;
    uint8_t receiveTimestamp[10];
    struct PTP_portId requestingPortId;
} PACKED;

struct PTP_signaling
{
    struct PTP_header hdr;
    struct PTP_portId targetPortId;
    uint8_t tlv[0];
} PACKED;


uint8_t PTP_getControlField(const uint8_t messageType);

/*
 * Return values:
 *             0: result invalid
 *            >0: required length of packet
 */
uint32_t PTP_getRequiredLength(const uint8_t messageType);

/*
 * Return values:
 *             0: packet is okay
 *            -1: pointer NULL
 *            -2: packet length too small
 *            -3: wrong version
 *            -4: transportSpecific wrong
 */
int32_t PTP_isPacketValid(const uint8_t *packet, const uint32_t len, const struct PTPConfig *conf);

/*
 * Parameters:
 *  - inPacket: might contain a packet, to which the packet to be generated is the response
 *  - inLen: length of inPacket
 *  - outPacket: buffer to write packet to be generated
 *  - outLen: when entering, length of the buffer outPacket, when exiting with success length of the packet generated
 *  - conf: configuration of ptp stack
 *  - msgType: type of the message to be generated
 *  - port: port the generated message is to be sent to
 *
 * Return values:
 *             0: success
 *            -1: pointer null
 *            -2: packet output buffer too small
 *            -3: unknown message
 *
 */
int32_t PTP_initMsg(const uint8_t *inPacket, const uint32_t inLen, uint8_t *outPacket, uint32_t *outLen, const struct PTPConfig *conf, const uint8_t msgType, const struct Port *port);


#endif /* PTP_H_ */
