/*
 * handler_table.h
 *
 * Copyright 2014 Jasper Salathe
 *
 *
 */

#ifndef HANDLER_TABLE_H_
#define HANDLER_TABLE_H_

#include <inttypes.h>

#include "packet.h"


enum HandlerTable_packetField
{
	HandlerTable_packetField_HDR_ETH,
	HandlerTable_packetField_ETH_DST,
    HandlerTable_packetField_ETH_SRC,
    HandlerTable_packetField_ETH_TYPE, // effective type, maps to VLAN field, if VLAN extension is there
    HandlerTable_packetField_VLAN_TCI,
    HandlerTable_packetField_NONE /* entry for unused filter */
};
int HandlerTable_isPacketFieldValid(const enum HandlerTable_packetField value);

struct HandlerTable_filterEntry
{
    const enum HandlerTable_packetField offsetField;
    const uint32_t offset;
    const uint32_t cnt;
    const uint8_t *machtTo;
    const uint8_t *mask;
};

typedef void (*HandlerTable_packetHandler)(const struct Packet_packet *packet, void *context);

struct HandlerTable_tableEntry
{
    struct HandlerTable_tableEntry *nextEntry;
    struct HandlerTable_filterEntry *filters; // array with filters, terminated with HandlerTable_packetField_NONE
    HandlerTable_packetHandler handler;
    void *context;
};

struct HandlerTable_table
{
    struct HandlerTable_tableEntry *firstEntry;
    uint32_t cnt;
};



/*
 * Return values:
 *             1: success (packet did match)
 *             0: success (packet did not match)
 *            -1: pointer null
 *            -2: filters invalid
 *
 */
int32_t HandlerTable_matchPacketFilter(const struct HandlerTable_filterEntry *filters, const struct Packet_packet *packet);

/*
 * Return values:
 *          NULL: no handler found / other error
 *          else: table entry to handle packet
 */
struct HandlerTable_tableEntry *HandlerTable_getHandler(const struct HandlerTable_table *table, const struct Packet_packet *packet);

/*
 *
 */
void HandlerTable_handlePacket(const struct HandlerTable_table *table, const struct Packet_packet *packet);

/*
 * Return vales:
 *            0: success
 *           -1: pointer null
 *           -2: filters invalid
 *           -3: table invalid
 */
int32_t HandlerTable_registerHandler(struct HandlerTable_table *table, struct HandlerTable_tableEntry *entry);

/*
 * Return values:
 *             0: success
 *            -1: pointer null
 *            -2: handler not found
 *            -3: table invalid
 */
int32_t HandlerTable_unregisterHandler(struct HandlerTable_table *table, const HandlerTable_packetHandler handler);

/*
 * Return values:
 *             0: success
 *            -1: pointer null
 *            -2: field invalid
 *            -3: field not in message
 */
int32_t HandlerTable_getOffsetIndex(uint32_t *resu, const enum HandlerTable_packetField field, const struct Packet_packet *packet);

#endif /* HANDLER_TABLE_H_ */
