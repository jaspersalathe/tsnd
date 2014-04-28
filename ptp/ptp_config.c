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

uint16_t PTPConfig_generateFlags(const struct PTPConfig *conf, const uint8_t msgType)
{
    uint16_t resu = 0;

    if(conf == NULL)
        return 0xFFFF;

    if(0 /* TODO: check, if I am MASTER */
       && ( msgType == PTP_MESSAGE_TYPE_ANNOUNCE
         || msgType == PTP_MESSAGE_TYPE_SYNC
         || msgType == PTP_MESSAGE_TYPE_FOLLOW_UP
         || msgType == PTP_MESSAGE_TYPE_DELAY_RESP ))
        resu &= PTP_FLAG_ALTERNATE_MASTER;

    if(conf->defaultDS.twoStepFlag
       && ( msgType == PTP_MESSAGE_TYPE_SYNC
         || msgType == PTP_MESSAGE_TYPE_PDELAY_RESP ))
        resu &= PTP_FLAG_TWO_STEP;

    // unicast flag is currently not supported

    // profile specific 1 and 2 currently not set

    if(conf->timePropertiesDS.leap61
       && msgType == PTP_MESSAGE_TYPE_ANNOUNCE)
        resu &= PTP_FLAG_LEAP61;

    if(conf->timePropertiesDS.leap59
       && msgType == PTP_MESSAGE_TYPE_ANNOUNCE)
        resu &= PTP_FLAG_LEAP59;

    if(conf->timePropertiesDS.currentUtcOffsetValid
       && msgType == PTP_MESSAGE_TYPE_ANNOUNCE)
        resu &= PTP_FLAG_CURR_UTC_OFFSET;

    if(conf->timePropertiesDS.ptpTimescale
       && msgType == PTP_MESSAGE_TYPE_ANNOUNCE)
        resu &= PTP_FLAG_PTP_TIMESCALE;

    if(conf->timePropertiesDS.timeTracable
       && msgType == PTP_MESSAGE_TYPE_ANNOUNCE)
        resu &= PTP_FLAG_TIME_TRACABLE;

    if(conf->timePropertiesDS.frequencyTracable
       && msgType == PTP_MESSAGE_TYPE_ANNOUNCE)
        resu &= PTP_FLAG_FREQ_TRACABLE;

    return resu;
}
