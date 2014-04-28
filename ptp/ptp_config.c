/*
 * ptp_config.c
 *
 *  Created on: 28.04.2014
 *      Author: jasper
 */

#include "ptp_config.h"

#include <stdlib.h>
#include <string.h>

#include "headers/ptp.h"


uint8_t PTPConfig_getTransportSpecific(const struct PTPConfig *conf)
{
    if(conf == NULL)
        return 0xFF;
    if(conf->isAVB)
        return PTP_TRANSPORT_SPECIFIC_AVB;
    else
        return PTP_TRANSPORT_SPECIFIC_DEFAULT;
}

uint8_t PTPConfig_getVersionPTP(const struct PTPConfig *conf)
{
    if(conf == NULL)
        return 0xFF;
    return conf->versionPTP;
}

void PTPConfig_getDstMAC(const uint8_t messageType, const struct PTPConfig *conf, uint8_t *dstMAC)
{
    const uint8_t *mac = PTP_ETH_MAC_GENERAL;
    if(conf == NULL || dstMAC == NULL)
        return;
    if(conf->isAVB)
        mac = PTP_ETH_MAC_P2P;
    else if(messageType == PTP_MESSAGE_TYPE_PDELAY_REQ
          || messageType == PTP_MESSAGE_TYPE_PDELAY_RESP
          || messageType == PTP_MESSAGE_TYPE_PDELAY_RESP_FOLLOW_UP)
        mac = PTP_ETH_MAC_P2P;
    memcpy(dstMAC, mac, ETHERNET_MAC_LEN);
}

uint8_t PTPConfig_getLogMessageInterval(const uint8_t messageType, const struct PTPConfig *conf)
{
    if(conf == NULL)
        return 0xFF;
    switch(messageType)
    {
    case PTP_MESSAGE_TYPE_ANNOUNCE:
        return 0; //TODO see 1588 13.3.2.11
    case PTP_MESSAGE_TYPE_SYNC:
    case PTP_MESSAGE_TYPE_FOLLOW_UP:
        return 0; //TODO see 1588 13.3.2.11
    case PTP_MESSAGE_TYPE_DELAY_RESP:
        return 0; //TODO see 1588 13.3.2.11
    default:
        return 0x7F;
    }
}
