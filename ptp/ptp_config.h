/*
 * ptp.h
 *
 *  Created on: 25.04.2014
 *      Author: jasper
 */

#ifndef PTP_CONFIG_H_
#define PTP_CONFIG_H_

#include <inttypes.h>

//#include "headers/ptp.h"


#define PTP_CURRUTCOFFSET 35 // as on 28. Apr 2014
#define PTP_CLOCKID_LEN 8


struct PTPConfig_ClockQuality
{
    uint8_t clockClass; // see 1588 -> 7.6.2.4 (255 is slave only)
    uint8_t clockAccuracy; // see 1588 -> 5.3.7 / 7.6.2.5 (0xFE = unknown)
    uint16_t offsetScaledLogVariance; // see 1588 -> 5.3.7 and 7.6.3.5
};

// see 1588 -> 8.2.1
struct PTPConfig_defaultDS
{
    // static values
    uint8_t twoStepFlag; // 0 or 1
    uint8_t clockId[PTP_CLOCKID_LEN]; // see 1588 -> 7.6.2.1 -> 7.5.2.2
    uint8_t numberPorts;
    // dynamic values
    struct PTPConfig_ClockQuality clockQuality;
    uint8_t priority1; // see 1588 -> 7.6.2.2
    uint8_t priority2; // see 1588 -> 7.6.2.3
    uint8_t domainNumber; // see 1588 -> 7.1
    uint8_t slaveOnly; // 0 or 1 see 1588 -> 9.2.2
};

struct PTPConfig_currentDS
{
    // dynamic values
    // TODO: types are unclear
    uint8_t stepsRemoved;
    uint8_t offsetFromMaster;
    uint8_t meanPathDelay;
};

struct PTPConfig_parentDS
{
    // dynamic values
    // TODO: types are unclear
    uint8_t parentPortId[PTP_CLOCKID_LEN];
    uint8_t partentStats; // 0 or 1
    uint16_t observedParentOffsetScaledLogVariance;
    uint32_t observedParentClockPhaseChangeRate;
    uint8_t grandmasterIdentity[PTP_CLOCKID_LEN];
    struct PTPConfig_ClockQuality grandmasterClockQuality;
    uint8_t grandmasterPriority1;
    uint8_t grandmasterPriority2;
};

struct PTPConfig_timePropertiesDS
{
    // dynamic values
    uint16_t currentUtcOffset; // see 1588 -> 8.2.4.2
    uint8_t currentUtcOffsetValid; // 0 or 1
    uint8_t leap59; // 0 or 1 see 1588 -> 8.2.4.8
    uint8_t leap61; // 0 or 1 see 1588 -> 8.2.4.8
    uint8_t timeTracable; // 0 or 1 see 1588 -> 8.2.4.8
    uint8_t frequencyTracable; // 0 or 1
    uint8_t ptpTimescale; // 0 or 1 see 1588 -> 7.2.1
    uint8_t timeSource; // see 1588 -> 7.6.2.6 (0xA0 for INTERNAL_OSCILLATOR)
};

struct PTPConfig
{
    struct PTPConfig_defaultDS defaultDS;
    struct PTPConfig_currentDS currentDS;
    struct PTPConfig_parentDS parentDS;
    struct PTPConfig_timePropertiesDS timePropertiesDS;
    uint8_t isAVB;
    uint8_t versionPTP;
};

uint8_t PTPConfig_getTransportSpecific(const struct PTPConfig *conf);
uint8_t PTPConfig_getVersionPTP(const struct PTPConfig *conf);
void PTPConfig_getDstMAC(const uint8_t messageType, const struct PTPConfig *conf, uint8_t *dstMAC);
uint8_t PTPConfig_getLogMessageInterval(const uint8_t messageType, const struct PTPConfig *conf);

#endif /* PTP_CONFIG_H_ */
