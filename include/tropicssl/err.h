/**
 * \file err.h
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
#ifndef TROPICSSL_ERR_H
#define TROPICSSL_ERR_H

#define TROPICSSL_ERR_OKAY                                  0
#define TROPICSSL_ERR_BAD_ARG                               -0x01
#define TROPICSSL_ERR_FILE_IO_ERROR                         -0x02

#define TROPICSSL_ERR_NET_UNKNOWN_HOST                      -0x0F00
#define TROPICSSL_ERR_NET_SOCKET_FAILED                     -0x0F10
#define TROPICSSL_ERR_NET_CONNECT_FAILED                    -0x0F20
#define TROPICSSL_ERR_NET_BIND_FAILED                       -0x0F30
#define TROPICSSL_ERR_NET_LISTEN_FAILED                     -0x0F40
#define TROPICSSL_ERR_NET_ACCEPT_FAILED                     -0x0F50
#define TROPICSSL_ERR_NET_RECV_FAILED                       -0x0F60
#define TROPICSSL_ERR_NET_SEND_FAILED                       -0x0F70
#define TROPICSSL_ERR_NET_CONN_RESET                        -0x0F80
#define TROPICSSL_ERR_NET_TRY_AGAIN                         -0x0F90

#define TROPICSSL_ERR_MPI_INVALID_CHARACTER                 -0x0006
#define TROPICSSL_ERR_MPI_BUFFER_TOO_SMALL                  -0x0008
#define TROPICSSL_ERR_MPI_NEGATIVE_VALUE                    -0x000A
#define TROPICSSL_ERR_MPI_DIVISION_BY_ZERO                  -0x000C
#define TROPICSSL_ERR_MPI_NOT_ACCEPTABLE                    -0x000E
#define TROPICSSL_ERR_MPI_MALLOC_FAILED                     -0x0010

#define TROPICSSL_ERR_BASE64_BUFFER_TOO_SMALL               -0x0010
#define TROPICSSL_ERR_BASE64_INVALID_CHARACTER              -0x0012

#define TROPICSSL_ERR_DHM_READ_PARAMS_FAILED                -0x0490
#define TROPICSSL_ERR_DHM_MAKE_PARAMS_FAILED                -0x04A0
#define TROPICSSL_ERR_DHM_READ_PUBLIC_FAILED                -0x04B0
#define TROPICSSL_ERR_DHM_MAKE_PUBLIC_FAILED                -0x04C0
#define TROPICSSL_ERR_DHM_CALC_SECRET_FAILED                -0x04D0

#define TROPICSSL_ERR_RSA_INVALID_PADDING                   -0x0410
#define TROPICSSL_ERR_RSA_KEY_GEN_FAILED                    -0x0420
#define TROPICSSL_ERR_RSA_KEY_CHECK_FAILED                  -0x0430
#define TROPICSSL_ERR_RSA_PUBLIC_FAILED                     -0x0440
#define TROPICSSL_ERR_RSA_PRIVATE_FAILED                    -0x0450
#define TROPICSSL_ERR_RSA_VERIFY_FAILED                     -0x0460
#define TROPICSSL_ERR_RSA_OUTPUT_TO_LARGE                   -0x0470

#define TROPICSSL_ERR_SSL_FEATURE_UNAVAILABLE               -0x1000
#define TROPICSSL_ERR_SSL_INVALID_MAC                       -0x2000
#define TROPICSSL_ERR_SSL_INVALID_RECORD                    -0x2800
#define TROPICSSL_ERR_SSL_INVALID_MODULUS_SIZE              -0x3000
#define TROPICSSL_ERR_SSL_UNKNOWN_CIPHER                    -0x3800
#define TROPICSSL_ERR_SSL_NO_CIPHER_CHOSEN                  -0x4000
#define TROPICSSL_ERR_SSL_NO_SESSION_FOUND                  -0x4800
#define TROPICSSL_ERR_SSL_NO_CLIENT_CERTIFICATE             -0x5000
#define TROPICSSL_ERR_SSL_CERTIFICATE_TOO_LARGE             -0x5800
#define TROPICSSL_ERR_SSL_CERTIFICATE_REQUIRED              -0x6000
#define TROPICSSL_ERR_SSL_PRIVATE_KEY_REQUIRED              -0x6800
#define TROPICSSL_ERR_SSL_CA_CHAIN_REQUIRED                 -0x7000
#define TROPICSSL_ERR_SSL_UNEXPECTED_MESSAGE                -0x7800
#define TROPICSSL_ERR_SSL_FATAL_ALERT_MESSAGE               -0x8000
#define TROPICSSL_ERR_SSL_PEER_VERIFY_FAILED                -0x8800
#define TROPICSSL_ERR_SSL_PEER_CLOSE_NOTIFY                 -0x9000
#define TROPICSSL_ERR_SSL_BAD_HS_CLIENT_HELLO               -0x9800
#define TROPICSSL_ERR_SSL_BAD_HS_SERVER_HELLO               -0xA000
#define TROPICSSL_ERR_SSL_BAD_HS_CERTIFICATE                -0xA800
#define TROPICSSL_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST        -0xB000
#define TROPICSSL_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE        -0xB800
#define TROPICSSL_ERR_SSL_BAD_HS_SERVER_HELLO_DONE          -0xC000
#define TROPICSSL_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE        -0xC800
#define TROPICSSL_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY         -0xD000
#define TROPICSSL_ERR_SSL_BAD_HS_CHANGE_CIPHER_SPEC         -0xD800
#define TROPICSSL_ERR_SSL_BAD_HS_FINISHED                   -0xE000

#define TROPICSSL_ERR_ASN1_OUT_OF_DATA                      -0x0014
#define TROPICSSL_ERR_ASN1_UNEXPECTED_TAG                   -0x0016
#define TROPICSSL_ERR_ASN1_INVALID_LENGTH                   -0x0018
#define TROPICSSL_ERR_ASN1_LENGTH_MISMATCH                  -0x001A
#define TROPICSSL_ERR_ASN1_INVALID_DATA                     -0x001C

#define TROPICSSL_ERR_X509_FEATURE_UNAVAILABLE              -0x0020
#define TROPICSSL_ERR_X509_CERT_INVALID_PEM                 -0x0040
#define TROPICSSL_ERR_X509_CERT_INVALID_FORMAT              -0x0060
#define TROPICSSL_ERR_X509_CERT_INVALID_VERSION             -0x0080
#define TROPICSSL_ERR_X509_CERT_INVALID_SERIAL              -0x00A0
#define TROPICSSL_ERR_X509_CERT_INVALID_ALG                 -0x00C0
#define TROPICSSL_ERR_X509_CERT_INVALID_NAME                -0x00E0
#define TROPICSSL_ERR_X509_CERT_INVALID_DATE                -0x0100
#define TROPICSSL_ERR_X509_CERT_INVALID_PUBKEY              -0x0120
#define TROPICSSL_ERR_X509_CERT_INVALID_SIGNATURE           -0x0140
#define TROPICSSL_ERR_X509_CERT_INVALID_EXTENSIONS          -0x0160
#define TROPICSSL_ERR_X509_CERT_UNKNOWN_VERSION             -0x0180
#define TROPICSSL_ERR_X509_CERT_UNKNOWN_SIG_ALG             -0x01A0
#define TROPICSSL_ERR_X509_CERT_UNKNOWN_PK_ALG              -0x01C0
#define TROPICSSL_ERR_X509_CERT_SIG_MISMATCH                -0x01E0
#define TROPICSSL_ERR_X509_CERT_VERIFY_FAILED               -0x0200
#define TROPICSSL_ERR_X509_KEY_INVALID_PEM                  -0x0220
#define TROPICSSL_ERR_X509_KEY_INVALID_VERSION              -0x0240
#define TROPICSSL_ERR_X509_KEY_INVALID_FORMAT               -0x0260
#define TROPICSSL_ERR_X509_KEY_INVALID_ENC_IV               -0x0280
#define TROPICSSL_ERR_X509_KEY_UNKNOWN_ENC_ALG              -0x02A0
#define TROPICSSL_ERR_X509_KEY_PASSWORD_REQUIRED            -0x02C0
#define TROPICSSL_ERR_X509_KEY_PASSWORD_MISMATCH            -0x02E0
#define TROPICSSL_ERR_X509_POINT_ERROR                      -0x0300
#define TROPICSSL_ERR_X509_VALUE_TO_LENGTH                  -0x0320

#endif /* TROPICSSL_ERR_H */
