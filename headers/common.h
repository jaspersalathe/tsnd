/*
 * common.h
 *
 *  Created on: 28.04.2014
 *      Author: jasper
 */

#ifndef COMMON_H_
#define COMMON_H_

#include <inttypes.h>

#define PACKED __attribute__((packed))

uint16_t Common_nToLu16(uint16_t data);
uint16_t Common_lToNu16(uint16_t data);
int16_t Common_nToLi16(int16_t data);
int16_t Common_lToNi16(int16_t data);

uint32_t Common_nToLu32(uint32_t data);
uint32_t Common_lToNu32(uint32_t data);
int32_t Common_nToLi32(int32_t data);
int32_t Common_lToNi32(int32_t data);

#endif /* COMMON_H_ */
