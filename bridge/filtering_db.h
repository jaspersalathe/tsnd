/*
 * filtering_db.h
 *
 *  Created on: 20.08.2014
 *      Author: jasper
 */

#ifndef FILTERING_DB_H_
#define FILTERING_DB_H_

#include <inttypes.h>
#include "headers/ethernet.h"


enum FDB_EntryType
{
    FDB_EntryType_StaticFiltering,
    FDB_EntryType_StaticVLANRegistraiton,
    FDB_EntryType_DynamicFiltering,
    FDB_EntryType_MACAddressRegistration,
    FDB_EntryType_DynamicVLANRegistration,
    FDB_EntryType_DynamicReservation
};

enum FDB_AddressType
{
    FDB_AddressType_AllIndividual,
    FDB_AddressType_AllGroup,
    FDB_AddressType_AllUnregIndividual,
    FDB_AddressType_AllUnregGroup,
    FDB_AddressType_Individual,
    FDB_AddressType_Group
};

struct FDB_StaticFiltering
{
    uint8_t mac[ETHERNET_MAC_LEN];
    enum FDB_AddressType addrType;
};

struct FDB_StaticVLANRegistration
{

};

struct FDB_DynamicFiltering
{

};

struct FDB_MACAddressRegistration
{

};

struct FDB_DynamicVLANRegistration
{

};

struct FDB_DynamicReservation
{

};

struct FDB_entry
{
    enum FDB_EntryType type;
    union
    {
        struct FDB_StaticFiltering staticFiltering;
        struct FDB_StaticVLANRegistration staticVLANRegistration;
        struct FDB_DynamicFiltering dynamicFiltering;
        struct FDB_MACAddressRegistration macAddressRegistration;
        struct FDB_DynamicVLANRegistration dynamicVLANRegistration;
        struct FDB_DynamicReservation dynamicRegistration;
    } entry;
};


#endif /* FILTERING_DB_H_ */
