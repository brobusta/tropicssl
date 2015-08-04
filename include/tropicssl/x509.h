/**
 * \file x509.h
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
#ifndef TROPICSSL_X509_H
#define TROPICSSL_X509_H

#include "tropicssl/config.h"

#if defined(TROPICSSL_X509_PARSE)
#include "tropicssl/rsa.h"

#define BADCERT_EXPIRED                 1
#define BADCERT_REVOKED                 2
#define BADCERT_CN_MISMATCH             4
#define BADCERT_NOT_TRUSTED             8

/*
 * DER constants
 */
#define ASN1_BOOLEAN                 0x01
#define ASN1_INTEGER                 0x02
#define ASN1_BIT_STRING              0x03
#define ASN1_OCTET_STRING            0x04
#define ASN1_NULL                    0x05
#define ASN1_OID                     0x06
#define ASN1_UTF8_STRING             0x0C
#define ASN1_SEQUENCE                0x10
#define ASN1_SET                     0x11
#define ASN1_PRINTABLE_STRING        0x13
#define ASN1_T61_STRING              0x14
#define ASN1_IA5_STRING              0x16
#define ASN1_UTC_TIME                0x17
#define ASN1_UNIVERSAL_STRING        0x1C
#define ASN1_BMP_STRING              0x1E
#define ASN1_PRIMITIVE               0x00
#define ASN1_CONSTRUCTED             0x20
#define ASN1_CONTEXT_SPECIFIC        0x80

/*
 * various object identifiers
 */
#define X520_COMMON_NAME                3
#define X520_COUNTRY                    6
#define X520_LOCALITY                   7
#define X520_STATE                      8
#define X520_ORGANIZATION              10
#define X520_ORG_UNIT                  11
#define PKCS9_EMAIL                     1

#define X509_OUTPUT_DER              0x01
#define X509_OUTPUT_PEM              0x02
#define PEM_LINE_LENGTH                72
#define X509_ISSUER                  0x01
#define X509_SUBJECT                 0x02

#define OID_X520                "\x55\x04"
#define OID_CN                  "\x55\x04\x03"
#define OID_PKCS1               "\x2A\x86\x48\x86\xF7\x0D\x01\x01"
#define OID_PKCS1_RSA           "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01"
#define OID_PKCS1_RSA_SHA       "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05"
#define OID_PKCS9               "\x2A\x86\x48\x86\xF7\x0D\x01\x09"
#define OID_PKCS9_EMAIL         "\x2A\x86\x48\x86\xF7\x0D\x01\x09\x01"

/*
 * Structures for parsing X.509 certificates
 */
typedef struct _x509_buf {
	int tag;
	size_t len;
	uint8_t *p;
} x509_buf;

typedef struct _x509_name {
	x509_buf oid;
	x509_buf val;
	struct _x509_name *next;
} x509_name;

typedef struct _x509_time {
	int year, mon, day;
	int hour, min, sec;
} x509_time;

typedef struct _x509_cert {
	x509_buf raw;
	x509_buf tbs;

	int version;
	x509_buf serial;
	x509_buf sig_oid1;

	x509_buf issuer_raw;
	x509_buf subject_raw;

	x509_name issuer;
	x509_name subject;

	x509_time valid_from;
	x509_time valid_to;

	x509_buf pk_oid;
	rsa_context rsa;

	x509_buf issuer_id;
	x509_buf subject_id;
	x509_buf v3_ext;

	int ca_istrue;
	int max_pathlen;

	x509_buf sig_oid2;
	x509_buf sig;

	struct _x509_cert *next;
} x509_cert;

/*
 * Structures for writing X.509 certificates
 */
typedef struct _x509_node {
	uint8_t *data;
	uint8_t *p;
	uint8_t *end;

	size_t len;
} x509_node;

typedef struct _x509_raw {
	x509_node raw;
	x509_node tbs;

	x509_node version;
	x509_node serial;
	x509_node tbs_signalg;
	x509_node issuer;
	x509_node validity;
	x509_node subject;
	x509_node subpubkey;

	x509_node signalg;
	x509_node sign;
} x509_raw;

#ifdef __cplusplus
extern "C" {
#endif

	/**
	 * \brief          Parse one or more certificates and add them
	 *                 to the chained list
	 *
	 * \param chain    points to the start of the chain
	 * \param buf      buffer holding the certificate data
	 * \param buflen   size of the buffer
	 *
	 * \return         0 if successful, or a specific X509 error code
	 */
	int x509parse_crt(x509_cert * crt, const uint8_t *buf, size_t buflen);

#if defined(TROPICSSL_FS_IO)
	/**
	 * \brief          Load one or more certificates and add them
	 *                 to the chained list
	 *
	 * \param chain    points to the start of the chain
	 * \param path     filename to read the certificates from
	 *
	 * \return         0 if successful, or a specific X509 error code
	 */
	int x509parse_crtfile(x509_cert * crt, const char *path);
#endif

	/**
	 * \brief          Parse a private RSA key
	 *
	 * \param rsa      RSA context to be initialized
	 * \param buf      input buffer
	 * \param buflen   size of the buffer
	 * \param pwd      password for decryption (optional)
	 * \param pwdlen   size of the password
	 *
	 * \return         0 if successful, or a specific X509 error code
	 */
	int x509parse_key(rsa_context * rsa,
			  const uint8_t *key, size_t keylen,
			  const uint8_t *pwd, size_t pwdlen);

#if defined(TROPICSSL_FS_IO)
	/**
	 * \brief          Load and parse a private RSA key
	 *
	 * \param rsa      RSA context to be initialized
	 * \param path     filename to read the private key from
	 * \param pwd      password to decrypt the file (can be NULL)
	 *
	 * \return         0 if successful, or a specific X509 error code
	 */
	int x509parse_keyfile(rsa_context * rsa, const char *path, const char *password);
#endif

	/**
	 * \brief          Store the certificate DN in printable form into buf;
	 *                 no more than (end - buf) characters will be written.
	 */
	int x509parse_dn_gets(char *buf, char *end, const x509_name * dn);

	/**
	 * \brief          Returns an informational string about the
	 *                 certificate.
	 */
	char *x509parse_cert_info(char *prefix, const x509_cert * crt);

	/**
	 * \brief          Return 0 if the certificate is still valid,
	 *                 or BADCERT_EXPIRED
	 */
	int x509parse_expired(const x509_cert * crt);

	/**
	 * \brief          Verify the certificate signature
	 *
	 * \param crt      a certificate to be verified
	 * \param trust_ca the trusted CA chain
	 * \param cn       expected Common Name (can be set to
	 *                 NULL if the CN must not be verified)
	 * \param flags    result of the verification
	 *
	 * \return         0 if successful or TROPICSSL_ERR_X509_SIG_VERIFY_FAILED,
	 *                 in which case *flags will have one or more of
	 *                 the following values set:
	 *                      BADCERT_EXPIRED --
	 *                      BADCERT_REVOKED --
	 *                      BADCERT_CN_MISMATCH --
	 *                      BADCERT_NOT_TRUSTED
	 *
	 * \note           TODO: add two arguments, depth and crl
	 */
	int x509parse_verify(x509_cert * crt,
			     x509_cert * trust_ca, const char *cn, int *flags);

	/**
	 * \brief          Unallocate all certificate data
	 */
	void x509_free(x509_cert * crt);

#if defined(TROPICSSL_SELF_TEST)
	/**
	 * \brief          Checkup routine
	 *
	 * \return         0 if successful, or 1 if the test failed
	 */
	int x509_self_test(int verbose);
#endif

#ifdef __cplusplus
}
#endif

#endif              /* TROPICSSL_X509_PARSE */
#endif				/* x509.h */
