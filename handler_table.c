
#include "handler_table.h"

#include <stdlib.h>

#include "headers/ethernet.h"


int HandlerTable_isPacketFieldValid(const enum HandlerTable_packetField value)
{
    return value == HandlerTable_packetField_HDR_ETH
         || value == HandlerTable_packetField_ETH_DST
         || value == HandlerTable_packetField_ETH_SRC
         || value == HandlerTable_packetField_ETH_TYPE
         || value == HandlerTable_packetField_VLAN_TCI
         || value == HandlerTable_packetField_NONE;
}

/*
 * Return values:
 *             1: success (packet did match)
 *             0: success (packet did not match)
 *            -1: pointer null
 *            -2: filters invalid
 *
 */
int32_t HandlerTable_matchPacketFilter(const struct HandlerTable_filterEntry *filters, const struct Packet_packet *packet)
{
    uint32_t i, j, fieldOffset;
    int matches;

    if(filters == NULL || packet == NULL || packet->packet == NULL)
        return -1;

    i = 0;

    while(filters[i].offsetField != HandlerTable_packetField_NONE)
    {
        if(HandlerTable_getOffsetIndex(&fieldOffset, filters[i].offsetField, packet) != 0)
            return -2;
        fieldOffset += filters[i].offset;
        if(packet->len < fieldOffset + filters[i].cnt)
            return -2;
        if(filters[i].cnt == 0)
            return -2;
        if(filters[i].machtTo == NULL || filters[i].mask == NULL)
            return -2;

        matches = 1;
        for(j = 0; j < filters[i].cnt; j++)
        {
            matches &= (packet->packet[fieldOffset + j] & filters[i].mask[j]) == filters[i].machtTo[j];
            if(!matches)
                break;
        }
        if(!matches)
            return 0;
        i++;
    }

    if(matches)
        return 1;
    else
        return 0;
}

/*
 * Return values:
 *          NULL: no handler found / other error
 *          else: table entry to handle packet
 */
struct HandlerTable_tableEntry *HandlerTable_getHandler(const struct HandlerTable_table *table, const struct Packet_packet *packet)
{
    uint32_t cnt = 0;
    int32_t resu;
    struct HandlerTable_tableEntry *curr = table->firstEntry;

    if(table == NULL || packet == NULL || packet->packet == NULL)
        return NULL;

    while(curr != NULL)
    {
        if(cnt >= table->cnt)
            return NULL;

        if(curr->handler == NULL || curr->filters == NULL)
            return NULL;

        resu = HandlerTable_matchPacketFilter(curr->filters, packet);
        if(resu < 0)
        {
            return NULL;
        }
        else if(resu == 1)
        {
            return curr;
        }
        else
        {
            cnt++;
            curr = curr->nextEntry;
        }
    }
    return NULL;
}

/*
 *
 */
void HandlerTable_handlePacket(const struct HandlerTable_table *table, const struct Packet_packet *packet)
{
    struct HandlerTable_tableEntry *entry = HandlerTable_getHandler(table, packet);
    if(entry != NULL && entry->handler != NULL)
        (*(entry->handler))(packet, entry->context);
}

/*
 * Return vales:
 *            0: success
 *           -1: pointer null
 *           -2: filters invalid
 *           -3: table invalid
 */
int32_t HandlerTable_registerHandler(struct HandlerTable_table *table, struct HandlerTable_tableEntry *entry)
{
    uint32_t i;
    struct HandlerTable_tableEntry *curr;

    if(table == NULL || entry == NULL || entry->filters == NULL || entry->handler == NULL)
        return -1;

    // check filters
    i = 0;
    while(entry->filters[i].offsetField != HandlerTable_packetField_NONE)
    {
        if(!HandlerTable_isPacketFieldValid(entry->filters[i].offsetField))
            return -2;
        if(entry->filters[i].cnt == 0)
            return -2;
        if(entry->filters[i].machtTo == NULL || entry->filters[i].mask == NULL)
            return -2;
        i++;
    }

    // check table
    i = 0;
    curr = table->firstEntry;
    while(curr != NULL)
    {
        i++;
        curr = curr->nextEntry;
    }
    if(i != table->cnt)
        return -3;

    // okay, add entry at the beginning
    entry->nextEntry = table->firstEntry;
    table->firstEntry = entry;
    table->cnt++;

    return 0;
}

/*
 * Return values:
 *             0: success
 *            -1: pointer null
 *            -2: handler not found
 *            -3: table invalid
 */
int32_t HandlerTable_unregisterHandler(struct HandlerTable_table *table, const HandlerTable_packetHandler handler)
{
    uint32_t i;
    struct HandlerTable_tableEntry *curr, *prev;

    if(table == NULL || handler == NULL)
        return -1;

    // check table
    i = 0;
    curr = table->firstEntry;
    while(curr != NULL)
    {
        i++;
        curr = curr->nextEntry;
    }
    if(i != table->cnt)
        return -3;

    curr = table->firstEntry;
    prev = NULL;
    i = 0;
    while(curr != NULL)
    {
        if(curr->handler == handler)
        {
            // okay, this should be removed
            if(prev == NULL)
            {
                table->firstEntry = curr->nextEntry;
            }
            else
            {
                prev->nextEntry = curr->nextEntry;
            }
            table->cnt--;
            i++;
            curr = curr->nextEntry;
        }
        else
        {
            prev = curr;
            curr = curr->nextEntry;
        }
    }
    if(i != 0)
        return 0;
    else
        return -2;
}

/*
 * Return values:
 *             0: success
 *            -1: pointer null
 *            -2: field invalid
 *            -3: field not in message
 */
int32_t HandlerTable_getOffsetIndex(uint32_t *resu, const enum HandlerTable_packetField field, const struct Packet_packet *packet)
{
    int isVLAN;

    if(resu == NULL || packet == NULL || packet->packet == NULL || packet->len == 0)
        return -1;

    isVLAN = Ethernet_isPacketVLAN(packet->packet, packet->len);

    switch(field)
    {
    case HandlerTable_packetField_HDR_ETH:
    case HandlerTable_packetField_ETH_DST:
        *resu = 0; return 0;

    case HandlerTable_packetField_ETH_SRC:
        *resu = 6; return 0;

    case HandlerTable_packetField_ETH_TYPE:
        if(isVLAN) *resu = 18;
        else       *resu = 12;
        return 0;

    case HandlerTable_packetField_VLAN_TCI:
        if(!isVLAN) return -3;
        *resu = 20; return 0;

    default:
        return -2;
    }
}
