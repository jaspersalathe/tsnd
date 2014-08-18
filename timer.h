/*
 * timer.h
 *
 *  Created on: 01.05.2014
 *      Author: jasper
 */

#ifndef TIMER_H_
#define TIMER_H_

#include <inttypes.h>

#include "common.h"


typedef void (*Timer_handler)(void *context);

struct Timer_entry
{
    Timer_handler handler;
    void *context;
    uint8_t prio;
    uint64_t period;
    uint8_t isNext;
    uint8_t isPeriodic;
    struct Common_timestamp nextOccurence;
};

struct Timer
{
    struct Timer_entry *entries;
    uint32_t cnt;
    int timerFd;
};

int32_t Timer_init(struct Timer *t);

int32_t Timer_registerPeriodic(struct Timer *t, const uint8_t prio, const uint64_t periodNs, Timer_handler handler, void *context);

int32_t Timer_registerOnce(struct Timer *t, const uint8_t prio, const uint64_t inNs, Timer_handler handler, void *context);

void Timer_unregister(struct Timer *t, const int32_t id)

void Timer_handleInterrupt(struct Timer *t);


#endif /* TIMER_H_ */
