/**
 * \file arc4.h
 *
 *  Based on XySSL: Copyright (C) 2006-2008  Christophe Devine
 *
 *  Copyright (C) 2009  Paul Bakker <polarssl_maintainer at polarssl dot org>
 *
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the names of PolarSSL or XySSL nor the names of its contributors
 *      may be used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 *  FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 *  TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 *  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef TROPICSSL_ARC4_H
#define TROPICSSL_ARC4_H

#include "tropicssl/config.h"

#if defined(TROPICSSL_ARC4)
#include <inttypes.h>

/**
 * \brief          ARC4 context structure
 */
typedef struct {
	int x;			/*!< permutation index */
	int y;			/*!< permutation index */
	uint8_t m[256];	/*!< permutation table */
} arc4_context;

#ifdef __cplusplus
extern "C" {
#endif

	/**
	 * \brief          ARC4 key schedule
	 *
	 * \param ctx      ARC4 context to be initialized
	 * \param key      the secret key
	 * \param keylen   length of the key
	 */
	void arc4_setup(arc4_context * ctx, const uint8_t *key, unsigned int keylen);

	/**
	 * \brief          ARC4 cipher function
	 *
	 * \param ctx      ARC4 context
	 * \param buf      buffer to be processed
	 * \param buflen   amount of data in buf
	 */
	void arc4_crypt(arc4_context * ctx, uint8_t *buf, int buflen);

#if defined(TROPICSSL_SELF_TEST)
	/*
	 * \brief          Checkup routine
	 *
	 * \return         0 if successful, or 1 if the test failed
	 */
	int arc4_self_test(int verbose);
#endif

#ifdef __cplusplus
}
#endif

#endif              /* TROPICSSL_ARC4 */
#endif				/* arc4.h */
