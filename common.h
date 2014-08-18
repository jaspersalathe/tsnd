/*
 * common.h
 *
 *  Created on: 28.04.2014
 *      Author: jasper
 */

#ifndef COMMON_H_
#define COMMON_H_

#include <inttypes.h>
#include <time.h>

#define PACKED __attribute__((packed))

struct Common_timestamp
{
    struct timespec t;
};

uint16_t Common_nToLu16(const uint16_t data);
uint16_t Common_lToNu16(const uint16_t data);
int16_t Common_nToLi16(const int16_t data);
int16_t Common_lToNi16(const int16_t data);

uint32_t Common_nToLu32(const uint32_t data);
uint32_t Common_lToNu32(const uint32_t data);
int32_t Common_nToLi32(const int32_t data);
int32_t Common_lToNi32(const int32_t data);

uint64_t Common_nToLu64(const uint64_t data);
uint64_t Common_lToNu64(const uint64_t data);
int64_t Common_nToLi64(const int64_t data);
int64_t Common_lToNi64(const int64_t data);

double Common_diffTimestamp(const struct Common_timestamp *start, const struct Common_timestamp *end);

#endif /* COMMON_H_ */
