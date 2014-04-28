/*
 * common.c
 *
 *  Created on: 28.04.2014
 *      Author: jasper
 */

#include "common.h"


/*
 * network format is always LITTLE ENDIAN
 */

uint16_t Common_nToLu16(uint16_t data)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return data;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return ((data&0xFF) << 8) | ((data&0xFF) >> 8);
#else
#error unknown byteorder!
#endif
}

uint16_t Common_lToNu16(uint16_t data)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return data;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return ((data&0xFF) << 8) | ((data&0xFF) >> 8);
#else
#error unknown byteorder!
#endif
}

int16_t Common_nToLi16(int16_t data)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return data;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return ((data&0xFF) << 8) | ((data&0xFF) >> 8);
#else
#error unknown byteorder!
#endif
}

int16_t Common_lToNi16(int16_t data)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return data;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return ((data&0x00FF) << 8) | ((data&0xFF00) >> 8);
#else
#error unknown byteorder!
#endif
}


uint32_t Common_nToLu32(uint32_t data)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return data;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return ((data&0x000000FF) << 24) | ((data&0x0000FF00) << 8) | ((data&0x00FF0000) >> 8) | ((data&0xFF000000) >> 24);
#else
#error unknown byteorder!
#endif
}

uint32_t Common_lToNu32(uint32_t data)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return data;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return ((data&0x000000FF) << 24) | ((data&0x0000FF00) << 8) | ((data&0x00FF0000) >> 8) | ((data&0xFF000000) >> 24);
#else
#error unknown byteorder!
#endif
}

int32_t Common_nToLi32(int32_t data)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return data;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return ((data&0x000000FF) << 24) | ((data&0x0000FF00) << 8) | ((data&0x00FF0000) >> 8) | ((data&0xFF000000) >> 24);
#else
#error unknown byteorder!
#endif
}

int32_t Common_lToNi32(int32_t data)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return data;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return ((data&0x000000FF) << 24) | ((data&0x0000FF00) << 8) | ((data&0x00FF0000) >> 8) | ((data&0xFF000000) >> 24);
#else
#error unknown byteorder!
#endif
}
