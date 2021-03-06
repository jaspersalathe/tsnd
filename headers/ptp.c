/*
 * ptp.c
 *
 *  Created on: 24.04.2014
 *      Author: jasper
 */

#include "ptp.h"

#include <stdlib.h>
#include <string.h>

const uint8_t PTP_ETH_TYPE[ETHERNET_TYPE_LEN] = {0x88, 0xF7};

const uint8_t PTP_ETH_MAC_GENERAL[ETHERNET_MAC_LEN] = {0x01, 0x1B, 0x19, 0x00, 0x00, 0x00};
const uint8_t PTP_ETH_MAC_P2P[ETHERNET_MAC_LEN] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E};


int32_t PTP_init_PDelay_Req(struct PTP_pDelayReq *outPacket, const struct PTPConfig *conf, const struct Port *port);
int32_t PTP_init_PDelay_Resp(const struct Packet_packet *inPacket, struct PTP_pDelayResp *outPacket, const struct PTPConfig *conf, const struct Port *port, const struct Common_timestamp *ts);
int32_t PTP_init_PDelay_Resp_FollowUp(const struct Packet_packet *inPacket, struct PTP_pDelayRespFollowUp *outPacket, const struct PTPConfig *conf, const struct Port *port, const struct Common_timestamp *ts);


uint8_t PTP_getControlField(const uint8_t messageType)
{
    switch(messageType)
    {
    case PTP_MESSAGE_TYPE_SYNC:       return PTP_CONTROL_FIELD_SYNC;
    case PTP_MESSAGE_TYPE_DELAY_REQ:  return PTP_CONTROL_FIELD_DELAY_REQ;
    case PTP_MESSAGE_TYPE_FOLLOW_UP:  return PTP_CONTROL_FIELD_FOLLOW_UP;
    case PTP_MESSAGE_TYPE_DELAY_RESP: return PTP_CONTROL_FIELD_DELAY_RESP;
    case PTP_MESSAGE_TYPE_MANAGEMENT: return PTP_CONTROL_FIELD_MANAGEMENT;
    default:                          return PTP_CONTROL_FIELD_OTHERS;
    }
}

uint32_t PTP_getRequiredLength(const uint8_t messageType)
{
    switch(messageType)
    {
    case PTP_MESSAGE_TYPE_SYNC:
        return sizeof(struct PTP_sync);
    case PTP_MESSAGE_TYPE_DELAY_REQ:
        return sizeof(struct PTP_delayReq);
    case PTP_MESSAGE_TYPE_PDELAY_REQ:
        return sizeof(struct PTP_pDelayReq);
    case PTP_MESSAGE_TYPE_PDELAY_RESP:
        return sizeof(struct PTP_pDelayResp);
    case PTP_MESSAGE_TYPE_PDELAY_RESP_FOLLOW_UP:
        return sizeof(struct PTP_pDelayRespFollowUp);
    case PTP_MESSAGE_TYPE_FOLLOW_UP:
        return sizeof(struct PTP_followUp);
    case PTP_MESSAGE_TYPE_DELAY_RESP:
        return sizeof(struct PTP_delayResp);
    case PTP_MESSAGE_TYPE_ANNOUNCE:
        return sizeof(struct PTP_announce);
    case PTP_MESSAGE_TYPE_SIGNALING:
        return sizeof(struct PTP_signaling);
    case PTP_MESSAGE_TYPE_MANAGEMENT:
    default:
        return 0;
    }
}

/*
 * Return values:
 *             0: packet is okay
 *            -1: pointer NULL
 *            -2: packet length too small
 *            -3: wrong version
 *            -4: transportSpecific wrong
 */
int32_t PTP_isPacketValid(const uint8_t *packet, const uint32_t len, const struct PTPConfig *conf)
{
    struct PTP_header *ptpPacket = (struct PTP_header*)packet;
    uint32_t reqLen;
    uint8_t transportSpecific, ptpVersion;

    if(packet == NULL || conf == NULL)
        return -1;

    if(len < sizeof(struct PTP_header))
        return -2;

    reqLen = PTP_getRequiredLength(PTP_GET_MESSAGETYPE(ptpPacket->transportSpecific_messageType));
    if(len < reqLen)
        return -2;

    transportSpecific = PTPConfig_getTransportSpecific(conf);
    ptpVersion = PTPConfig_getVersionPTP(conf);

    if(transportSpecific != PTP_GET_TRANSPORTSPECIFIC(ptpPacket->transportSpecific_messageType))
        return -4;
    if(ptpVersion != PTP_GET_VERSIONPTP(ptpPacket->reserved_versionPTP))
        return -3;

    // okay, packet seams okay
    return 0;
}

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
int32_t PTP_initMsg(const struct Packet_packet *inPacket, uint8_t *outPacket, uint32_t *outLen, const struct PTPConfig *conf, const uint8_t msgType, const struct Port *port, void *param)
{
    uint32_t myLen;
    struct Ethernet_header *outEHdr = (struct Ethernet_header*)outPacket;
    struct PTP_header *outPHdr = (struct PTP_header*)NULL;
    uint8_t transportSpecific, versionPTP;

    // inPacket is not checked, as it is only needed by specific messages
    // --> checked in initializer for corresponding message
    if(outPacket == NULL || conf == NULL)
        return -1;

    // assume inPacket is checked by isPacketValid successful

    // check minimum required length
    myLen = PTP_getRequiredLength(msgType) + sizeof(struct Ethernet_header);
    if(*outLen < myLen)
        return -2;

    outPHdr = (struct PTP_header*)outEHdr->payload;

    // init values
    transportSpecific = PTPConfig_getTransportSpecific(conf);
    versionPTP = PTPConfig_getVersionPTP(conf);

    // init buffer
    memset(outEHdr, 0, myLen);

    // set ethernet header
    PTPConfig_getDstMAC(msgType, conf, outEHdr->dst);
    memcpy(outEHdr->src, port->macAddr, ETHERNET_MAC_LEN);
    memcpy(outEHdr->type, PTP_ETH_TYPE, ETHERNET_TYPE_LEN);

    // set values (ptp)
    outPHdr->transportSpecific_messageType = PTP_SET_TRANSP_MSGTYPE(transportSpecific, msgType);
    outPHdr->reserved_versionPTP = PTP_SET_VERSIONPTP(versionPTP);
    outPHdr->messageLen = 0; // this is calculated in specific message initializer
    outPHdr->domainNumber = conf->defaultDS.domainNumber;
    outPHdr->flags = PTPConfig_generateFlags(conf, msgType);
    memset(&(outPHdr->correction), 0, 8);
    memcpy(outPHdr->sourcePortId.clockId, conf->defaultDS.clockId, PTP_CLOCKID_LEN);
    outPHdr->sourcePortId.portNo = Common_lToNu16(port->portIdx+1);
    outPHdr->sequId = 0; // this is set by specific message initializer
    outPHdr->controlField = PTP_getControlField(msgType);
    outPHdr->logMessageInterval = PTPConfig_getLogMessageInterval(msgType, conf);

    // call individual initializers for messages
    *outLen = myLen;
    switch(msgType)
    {
    case PTP_MESSAGE_TYPE_SYNC:
        return -3;
    case PTP_MESSAGE_TYPE_DELAY_REQ:
        return -3;
    case PTP_MESSAGE_TYPE_PDELAY_REQ:
        return PTP_init_PDelay_Req((struct PTP_pDelayReq*)outPHdr, conf, port);
    case PTP_MESSAGE_TYPE_PDELAY_RESP:
        return PTP_init_PDelay_Resp(inPacket, (struct PTP_pDelayResp*)outPHdr, conf, port, param);
    case PTP_MESSAGE_TYPE_PDELAY_RESP_FOLLOW_UP:
        return PTP_init_PDelay_Resp_FollowUp(inPacket, (struct PTP_pDelayRespFollowUp*)outPHdr, conf, port, param);
    case PTP_MESSAGE_TYPE_FOLLOW_UP:
        return -3;
    case PTP_MESSAGE_TYPE_DELAY_RESP:
        return -3;
    case PTP_MESSAGE_TYPE_ANNOUNCE:
        return -3;
    case PTP_MESSAGE_TYPE_SIGNALING:
        return -3;
    case PTP_MESSAGE_TYPE_MANAGEMENT:
        return -3;
    default:
        return -3;
    }
}

int32_t PTP_init_PDelay_Req(struct PTP_pDelayReq *outPacket, const struct PTPConfig *conf, const struct Port *port)
{
    if(outPacket == NULL || conf == NULL || port == NULL)
        return -1;
    // assume this is enough checking

    // set remaining stuff in general header
    outPacket->hdr.sequId = 0; // TODO: add counter for sequId
    outPacket->hdr.messageLen = Common_lToNu16(54);

    // set message content
    memset(&(outPacket->originTimestamp), 0, 10);
    // could be zero, if unknown

    return 0;
}

int32_t PTP_init_PDelay_Resp(const struct Packet_packet *inPacket, struct PTP_pDelayResp *outPacket, const struct PTPConfig *conf, const struct Port *port, const struct Common_timestamp *ts)
{
    uint32_t inEthLen, inReqLen = PTP_getRequiredLength(PTP_MESSAGE_TYPE_PDELAY_REQ);
    const struct PTP_pDelayReq *inReq;

    if(inPacket == NULL || outPacket == NULL || conf == NULL || port == NULL)
        return -1;
    inEthLen = Ethernet_getHeaderLength(inPacket->packet, inPacket->len);
    if(inPacket->len < inReqLen + inEthLen)
        return -1;
    inReq = (struct PTP_pDelayReq*)(inPacket->packet + inEthLen);

    // assume this is enough checking

    // set remaining stuff in general header
    outPacket->hdr.sequId = inReq->hdr.sequId;
    outPacket->hdr.messageLen = Common_lToNu16(54);

    // set message content
    PTP_convertTimestampLtoPTP(ts, &(outPacket->receiveTimestamp));
    memcpy(&(outPacket->requestingPortId), &(inReq->hdr.sourcePortId), sizeof(struct PTP_portId));

    return 0;
}

int32_t PTP_init_PDelay_Resp_FollowUp(const struct Packet_packet *inPacket, struct PTP_pDelayRespFollowUp *outPacket, const struct PTPConfig *conf, const struct Port *port, const struct Common_timestamp *ts)
{
    uint32_t inEthLen, inReqLen = PTP_getRequiredLength(PTP_MESSAGE_TYPE_PDELAY_REQ);
    const struct PTP_pDelayReq *inReq;

    if(inPacket == NULL || outPacket == NULL || conf == NULL || port == NULL)
        return -1;
    inEthLen = Ethernet_getHeaderLength(inPacket->packet, inPacket->len);
    if(inPacket->len < inReqLen + inEthLen)
        return -1;
    inReq = (struct PTP_pDelayReq*)(inPacket->packet + inEthLen);

    // assume this is enough checking

    // set remaining stuff in general header
    outPacket->hdr.sequId = inReq->hdr.sequId;
    outPacket->hdr.messageLen = Common_lToNu16(54);

    // set message content
    PTP_convertTimestampLtoPTP(ts, &(outPacket->receiveTimestamp));
    memcpy(&(outPacket->requestingPortId), &(inReq->hdr.sourcePortId), sizeof(struct PTP_portId));

    return 0;
}


void PTP_convertTimestampPTPtoL(const struct PTP_timestamp *ptp, struct Common_timestamp *l)
{
    if(ptp == NULL || l == NULL)
        return;

    l->t.tv_sec = Common_nToLu32(ptp->sec_lsb);
    l->t.tv_nsec = Common_nToLu64(ptp->nsec);
}

void PTP_convertTimestampLtoPTP(const struct Common_timestamp *l, struct PTP_timestamp *ptp)
{
    if(ptp == NULL || l == NULL)
        return;

    ptp->sec_msb = 0;
    ptp->sec_lsb = Common_lToNu32(l->t.tv_sec);
    ptp->nsec = Common_lToNu32(l->t.tv_nsec);
}
