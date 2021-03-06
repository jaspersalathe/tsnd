/*
 * common.c
 *
 *  Created on: 28.04.2014
 *      Author: jasper
 */

#include "common.h"

#include <endian.h>
#include <stdlib.h>


/*
 * network format is always LITTLE ENDIAN
 */

uint16_t Common_nToLu16(const uint16_t data)
{
#if __BYTE_ORDER == __BIG_ENDIAN
    return data;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    return (0xFF00 & (data << 8)) | (0x00FF & (data >> 8));
#else
#error unknown byteorder!
#endif
}

uint16_t Common_lToNu16(const uint16_t data)
{
#if __BYTE_ORDER == __BIG_ENDIAN
    return data;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    return (0xFF00 & (data << 8)) | (0x00FF & (data >> 8));
#else
#error unknown byteorder!
#endif
}

int16_t Common_nToLi16(const int16_t data)
{
#if __BYTE_ORDER == __BIG_ENDIAN
    return data;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    return (0xFF00 & (data << 8)) | (0x00FF & (data >> 8));
#else
#error unknown byteorder!
#endif
}

int16_t Common_lToNi16(const int16_t data)
{
#if __BYTE_ORDER == __BIG_ENDIAN
    return data;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    return (0xFF00 & (data << 8)) | (0x00FF & (data >> 8));
#else
#error unknown byteorder!
#endif
}


uint32_t Common_nToLu32(const uint32_t data)
{
#if __BYTE_ORDER == __BIG_ENDIAN
    return data;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    return (0xFF000000 & (data << 24)) | (0x00FF0000 & (data << 8)) | (0x0000FF00 & (data >> 8)) | (0x000000FF & (data >> 24));
#else
#error unknown byteorder!
#endif
}

uint32_t Common_lToNu32(const uint32_t data)
{
#if __BYTE_ORDER == __BIG_ENDIAN
    return data;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    return (0xFF000000 & (data << 24)) | (0x00FF0000 & (data << 8)) | (0x0000FF00 & (data >> 8)) | (0x000000FF & (data >> 24));
#else
#error unknown byteorder!
#endif
}

int32_t Common_nToLi32(const int32_t data)
{
#if __BYTE_ORDER == __BIG_ENDIAN
    return data;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    return (0xFF000000 & (data << 24)) | (0x00FF0000 & (data << 8)) | (0x0000FF00 & (data >> 8)) | (0x000000FF & (data >> 24));
#else
#error unknown byteorder!
#endif
}

int32_t Common_lToNi32(const int32_t data)
{
#if __BYTE_ORDER == __BIG_ENDIAN
    return data;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    return (0xFF000000 & (data << 24)) | (0x00FF0000 & (data << 8)) | (0x0000FF00 & (data >> 8)) | (0x000000FF & (data >> 24));
#else
#error unknown byteorder!
#endif
}


uint64_t Common_nToLu64(const uint64_t data)
{
#if __BYTE_ORDER == __BIG_ENDIAN
    return data;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    return (0xFF00000000000000 & (data << 56)) | (0x00FF000000000000 & (data << 40)) | (0x0000FF0000000000 & (data << 24)) | (0x000000FF00000000 & (data <<  8))
         | (0x00000000FF000000 & (data >>  8)) | (0x0000000000FF0000 & (data >> 24)) | (0x000000000000FF00 & (data >> 40)) | (0x00000000000000FF & (data >> 56));
#else
#error unknown byteorder!
#endif
}

uint64_t Common_lToNu64(const uint64_t data)
{
#if __BYTE_ORDER == __BIG_ENDIAN
    return data;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    return (0xFF00000000000000 & (data << 56)) | (0x00FF000000000000 & (data << 40)) | (0x0000FF0000000000 & (data << 24)) | (0x000000FF00000000 & (data <<  8))
         | (0x00000000FF000000 & (data >>  8)) | (0x0000000000FF0000 & (data >> 24)) | (0x000000000000FF00 & (data >> 40)) | (0x00000000000000FF & (data >> 56));
#else
#error unknown byteorder!
#endif
}

int64_t Common_nToLi64(const int64_t data)
{
#if __BYTE_ORDER == __BIG_ENDIAN
    return data;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    return (0xFF00000000000000 & (data << 56)) | (0x00FF000000000000 & (data << 40)) | (0x0000FF0000000000 & (data << 24)) | (0x000000FF00000000 & (data <<  8))
         | (0x00000000FF000000 & (data >>  8)) | (0x0000000000FF0000 & (data >> 24)) | (0x000000000000FF00 & (data >> 40)) | (0x00000000000000FF & (data >> 56));
#else
#error unknown byteorder!
#endif
}

int64_t Common_lToNi64(const int64_t data)
{
#if __BYTE_ORDER == __BIG_ENDIAN
    return data;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    return (0xFF00000000000000 & (data << 56)) | (0x00FF000000000000 & (data << 40)) | (0x0000FF0000000000 & (data << 24)) | (0x000000FF00000000 & (data <<  8))
         | (0x00000000FF000000 & (data >>  8)) | (0x0000000000FF0000 & (data >> 24)) | (0x000000000000FF00 & (data >> 40)) | (0x00000000000000FF & (data >> 56));
#else
#error unknown byteorder!
#endif
}

double Common_diffTimestamp(const struct Common_timestamp *start, const struct Common_timestamp *end)
{
    double resu;

    if(start == NULL || end == NULL)
        return 0;

    resu = end->t.tv_nsec / 1000000000.0 + end->t.tv_sec;
    resu -= start->t.tv_nsec / 1000000000.0 + start->t.tv_sec;

    return resu;
}
