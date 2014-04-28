/*
 * simple_gptp_handler.h
 *
 *  Created on: 24.04.2014
 *      Author: jasper
 */

#ifndef SIMPLE_GPTP_HANDLER_H_
#define SIMPLE_GPTP_HANDLER_H_

#include <inttypes.h>
#include "handler_table.h"
#include "port.h"
#include "ptp_config.h"

struct SimpleGPTPHandler_state
{
    struct Port *ports;
    uint32_t portCnt;
    struct PTPConfig *conf;
};

/*
 * Return values:
 *             0: success
 *            -1: pointer null
 *            -2: could not register handler
 *            -3: could not allocate memory
 */
int32_t SimpleGPTPHandler_init(struct HandlerTable_table *table, struct Port *ports, uint32_t portCnt /* TODO: config */);

#endif /* SIMPLE_GPTP_HANDLER_H_ */
