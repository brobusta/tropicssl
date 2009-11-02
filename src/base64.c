/*
 *  RFC 1521 base64 encoding/decoding
 *
 *  Copyright (C) 2006  Christophe Devine
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License, version 2.1 as published by the Free Software Foundation.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <string.h>
#include <stdio.h>

#include "base64.h"

static uchar base64_enc_map[64] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static uchar base64_dec_map[128] =
{
    127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
    127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
    127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
    127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
    127, 127, 127,  62, 127, 127, 127,  63,  52,  53,
     54,  55,  56,  57,  58,  59,  60,  61, 127, 127,
    127,  64, 127, 127, 127,   0,   1,   2,   3,   4,
      5,   6,   7,   8,   9,  10,  11,  12,  13,  14,
     15,  16,  17,  18,  19,  20,  21,  22,  23,  24,
     25, 127, 127, 127, 127, 127, 127,  26,  27,  28,
     29,  30,  31,  32,  33,  34,  35,  36,  37,  38,
     39,  40,  41,  42,  43,  44,  45,  46,  47,  48,
     49,  50,  51, 127, 127, 127, 127, 127
};

/*
 * Encode buffer src of size slen into dst.
 *
 * Returns 0 if successful (dlen contains the # of bytes written) or
 *         ERR_BASE64_BUFFER_TOO_SMALL if *dlen is not large enough,
 *         in which case it is updated to contain the requested size.
 *
 * You may call this function with dst = NULL to determine how much
 * is needed for the destination buffer.
 */
int base64_encode( uchar *dst, uint *dlen, uchar *src, uint slen )
{
    uint i, n;
    uint C1, C2, C3;
    uchar *p;

    if( slen == 0 )
        return( 0 );

    n = ( slen << 3 ) / 6;

    switch( ( slen << 3 ) - ( n * 6 ) )
    {
        case  2: n += 3; break;
        case  4: n += 2; break;
        default: break;
    }

    if( *dlen < n + 1 || dst == NULL )
    {
        *dlen = n + 1;
        return( ERR_BASE64_BUFFER_TOO_SMALL );
    }

    n = ( slen / 3 ) * 3;

    for( i = 0, p = dst; i < n; i += 3 )
    {
        C1 = *src++;
        C2 = *src++;
        C3 = *src++;

        *p++ = base64_enc_map[( C1 >> 2 ) & 0x3F];
        *p++ = base64_enc_map[((( C1 &  3 ) << 4) + ( C2 >> 4 )) & 0x3F];
        *p++ = base64_enc_map[((( C2 & 15 ) << 2) + ( C3 >> 6 )) & 0x3F];
        *p++ = base64_enc_map[C3 & 0x3F];
    }

    if( i < slen )
    {
        C1 = *src++;
        C2 = ((i + 1) < slen) ? *src++ : 0;

        *p++ = base64_enc_map[( C1 >> 2 ) & 0x3F];
        *p++ = base64_enc_map[((( C1 & 3 ) << 4) + ( C2 >> 4 )) & 0x3F];
        *p++ = ((i + 1) < slen) ?
            base64_enc_map[((( C2 & 15 ) << 2)) & 0x3F] : '=';

        *p++ = '=';
    }

    *dlen = p - dst;

    return( *p = 0 );
}

/*
 * Decode buffer src of size slen into dst.
 *
 * Returns 0 if successful (dlen contains the # of bytes written)
 *         ERR_BASE64_INVALID_CHARACTER if an invalid char is found
 *         ERR_BASE64_BUFFER_TOO_SMALL if *dlen is not large enough,
 *         in which case it is updated to contain the requested size.
 *
 * You may call this function with dst = NULL to determine how much
 * is needed for the destination buffer.
 */
int base64_decode( uchar *dst, uint *dlen, uchar *src, uint slen )
{
    uint i, j, n;
    ulong x;
    uchar *p;

    for( i = j = n = 0; i < slen; i++ )
    {
        if( ( slen - i ) >= 2 &&
            src[i] == '\r' && src[i + 1] == '\n' )
            continue;

        if( src[i] == '\n' )
            continue;

        if( src[i] == '=' && ++j > 2 )
            return( ERR_BASE64_INVALID_CHARACTER );

        if( src[i] > 127 || base64_dec_map[src[i]] == 127 )
            return( ERR_BASE64_INVALID_CHARACTER );

        if( base64_dec_map[src[i]] < 64 && j != 0 )
            return( ERR_BASE64_INVALID_CHARACTER );

        n++;
    }

    if( n == 0 )
        return( 0 );

    n = ( ( n * 6 ) + 7 ) >> 3;

    if( *dlen < n || dst == NULL )
    {
        *dlen = n;
        return( ERR_BASE64_BUFFER_TOO_SMALL );
    }

   for( j = 3, n = x = 0, p = dst; i > 0; i--, src++ )
   {
        if( *src == '\r' || *src == '\n' )
            continue;

        j -= ( base64_dec_map[*src] == 64 );
        x  = ( x << 6 ) | ( base64_dec_map[*src] & 0x3F );

        if( ++n == 4 )
        {
            n = 0;
            *p++ = (uchar) ( x >> 16 );
            if( j > 1 ) *p++ = (uchar) ( x >> 8 );
            if( j > 2 ) *p++ = (uchar )  x;
        }
    }

    *dlen = p - dst;

    return( 0 );
}

#ifdef SELF_TEST

static uchar base64_test_dec[64] =
{
    0x24, 0x48, 0x6E, 0x56, 0x87, 0x62, 0x5A, 0xBD,
    0xBF, 0x17, 0xD9, 0xA2, 0xC4, 0x17, 0x1A, 0x01,
    0x94, 0xED, 0x8F, 0x1E, 0x11, 0xB3, 0xD7, 0x09,
    0x0C, 0xB6, 0xE9, 0x10, 0x6F, 0x22, 0xEE, 0x13,
    0xCA, 0xB3, 0x07, 0x05, 0x76, 0xC9, 0xFA, 0x31,
    0x6C, 0x08, 0x34, 0xFF, 0x8D, 0xC2, 0x6C, 0x38,
    0x00, 0x43, 0xE9, 0x54, 0x97, 0xAF, 0x50, 0x4B,
    0xD1, 0x41, 0xBA, 0x95, 0x31, 0x5A, 0x0B, 0x97
};

static uchar base64_test_enc[] =
    "JEhuVodiWr2/F9mixBcaAZTtjx4Rs9cJDLbpEG8i7hPK"
    "swcFdsn6MWwINP+Nwmw4AEPpVJevUEvRQbqVMVoLlw==";

/*
 * Checkup routine
 */
int b64_self_test( void )
{
    uint n;
    uchar buffer[128];

    printf( "  base64 encoding test: " );

    n = sizeof( buffer );

    if( base64_encode( buffer, &n, base64_test_dec, 64 ) != 0 ||
        strcmp( (char *) buffer, (char *) base64_test_enc ) != 0 )
    {
        printf( "failed\n" );
        return( 1 );
    }

    printf( "passed\n" );
    
    printf( "  base64 decoding test: " );

    n = sizeof( buffer );

    if( base64_decode( buffer, &n, base64_test_enc, 88 ) != 0 ||
        memcmp( buffer, base64_test_dec, 64 ) != 0 )
    {
        printf( "failed\n" );
        return( 1 );
    }

    printf( "passed\n\n" );

    return( 0 );
}
#else
int b64_self_test( void )
{
    printf( "base64 self-test not available\n\n" );
    return( 1 );
}
#endif