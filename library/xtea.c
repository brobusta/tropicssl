/*
 *	An 32-bit implementation of the XTEA algorithm
 *
 *	Copyright (C) 2009	Paul Bakker <polarssl_maintainer at polarssl dot org>
 *
 *	All rights reserved.
 *
 *	Redistribution and use in source and binary forms, with or without
 *	modification, are permitted provided that the following conditions
 *	are met:
 *
 *	  * Redistributions of source code must retain the above copyright
 *		notice, this list of conditions and the following disclaimer.
 *	  * Redistributions in binary form must reproduce the above copyright
 *		notice, this list of conditions and the following disclaimer in the
 *		documentation and/or other materials provided with the distribution.
 *	  * Neither the names of PolarSSL or XySSL nor the names of its contributors
 *		may be used to endorse or promote products derived from this software
 *		without specific prior written permission.
 *
 *	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *	"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *	LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 *	FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *	OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *	SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 *	TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 *	PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *	LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *	NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *	SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "tropicssl/config.h"

#if defined(TROPICSSL_XTEA_C)

#include "tropicssl/xtea.h"

#include <string.h>

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n,b,i)								\
	{													\
		(n) = ( (uint32_t) (b)[(i)	   ] << 24 )	\
			| ( (uint32_t) (b)[(i) + 1] << 16 )	\
			| ( (uint32_t) (b)[(i) + 2] <<	 8 )	\
			| ( (uint32_t) (b)[(i) + 3]	   );	\
	}
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n,b,i)								\
	{													\
		(b)[(i)	   ] = (uint8_t) ( (n) >> 24 );	\
		(b)[(i) + 1] = (uint8_t) ( (n) >> 16 );	\
		(b)[(i) + 2] = (uint8_t) ( (n) >>	 8 );	\
		(b)[(i) + 3] = (uint8_t) ( (n)	   );	\
	}
#endif

/*
 * XTEA key schedule
 */
void xtea_setup(xtea_context * ctx, uint8_t key[16])
{
	int i;

	memset(ctx, 0, sizeof(xtea_context));

	for (i = 0; i < 4; i++) {
		GET_UINT32_BE(ctx->k[i], key, i << 2);
	}
}

/*
 * XTEA encrypt function
 */
void xtea_crypt_ecb(xtea_context * ctx, int mode, const uint8_t input[8],
		    uint8_t output[8])
{
	uint32_t *k, v0, v1, i;

	k = ctx->k;

	GET_UINT32_BE(v0, input, 0);
	GET_UINT32_BE(v1, input, 4);

	if (mode == XTEA_ENCRYPT) {
		uint32_t sum = 0, delta = 0x9E3779B9;

		for (i = 0; i < 32; i++) {
			v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
			sum += delta;
			v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum >> 11) & 3]);
		}
	} else {		/* XTEA_DECRYPT */
		uint32_t delta = 0x9E3779B9, sum = delta * 32;

		for (i = 0; i < 32; i++) {
			v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum >> 11) & 3]);
			sum -= delta;
			v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
		}
	}

	PUT_UINT32_BE(v0, output, 0);
	PUT_UINT32_BE(v1, output, 4);
}

#if defined(TROPICSSL_SELF_TEST)

#include <string.h>
#include <stdio.h>

/*
 * XTEA tests vectors (non-official)
 */

static const uint8_t xtea_test_key[6][16] = {
	{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
	 0x0c, 0x0d, 0x0e, 0x0f},
	{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
	 0x0c, 0x0d, 0x0e, 0x0f},
	{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
	 0x0c, 0x0d, 0x0e, 0x0f},
	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00},
	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00},
	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	 0x00, 0x00, 0x00, 0x00}
};

static const uint8_t xtea_test_pt[6][8] = {
	{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48},
	{0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41},
	{0x5a, 0x5b, 0x6e, 0x27, 0x89, 0x48, 0xd7, 0x7f},
	{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48},
	{0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41},
	{0x70, 0xe1, 0x22, 0x5d, 0x6e, 0x4e, 0x76, 0x55}
};

static const uint8_t xtea_test_ct[6][8] = {
	{0x49, 0x7d, 0xf3, 0xd0, 0x72, 0x61, 0x2c, 0xb5},
	{0xe7, 0x8f, 0x2d, 0x13, 0x74, 0x43, 0x41, 0xd8},
	{0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41},
	{0xa0, 0x39, 0x05, 0x89, 0xf8, 0xb8, 0xef, 0xa5},
	{0xed, 0x23, 0x37, 0x5a, 0x82, 0x1a, 0x8c, 0x2d},
	{0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41}
};

/*
 * Checkup routine
 */
int xtea_self_test(int verbose)
{
	int i;
	uint8_t buf[8];
	xtea_context ctx;

	for (i = 0; i < 6; i++) {
		if (verbose != 0)
			printf("  XTEA test #%d: ", i + 1);

		memcpy(buf, xtea_test_pt[i], 8);

		xtea_setup(&ctx, (uint8_t *)xtea_test_key[i]);
		xtea_crypt_ecb(&ctx, XTEA_ENCRYPT, buf, buf);

		if (memcmp(buf, xtea_test_ct[i], 8) != 0) {
			if (verbose != 0)
				printf("failed\n");

			return (1);
		}

		if (verbose != 0)
			printf("passed\n");
	}

	if (verbose != 0)
		printf("\n");

	return (0);
}

#endif

#endif
