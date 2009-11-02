#ifndef _X509_H
#define _X509_H

#ifndef _STD_TYPES
#define _STD_TYPES

#define uchar   unsigned char
#define uint    unsigned int
#define ulong   unsigned long int

#endif

#include "rsa.h"

#define ERR_ASN1_OUT_OF_DATA                    0x0014
#define ERR_ASN1_UNEXPECTED_TAG                 0x0016
#define ERR_ASN1_INVALID_LENGTH                 0x0018
#define ERR_ASN1_LENGTH_MISMATCH                0x001A
#define ERR_ASN1_INVALID_DATA                   0x001C

#define ERR_X509_CERT_INVALID_PEM               0x0020
#define ERR_X509_CERT_INVALID_FORMAT            0x0040
#define ERR_X509_CERT_INVALID_VERSION           0x0060
#define ERR_X509_CERT_INVALID_SERIAL            0x0080
#define ERR_X509_CERT_INVALID_ALG               0x00A0
#define ERR_X509_CERT_INVALID_NAME              0x00C0
#define ERR_X509_CERT_INVALID_DATE              0x00E0
#define ERR_X509_CERT_INVALID_PUBKEY            0x0100
#define ERR_X509_CERT_INVALID_SIGNATURE         0x0120
#define ERR_X509_CERT_INVALID_EXTENSIONS        0x0140
#define ERR_X509_CERT_UNKNOWN_VERSION           0x0160
#define ERR_X509_CERT_UNKNOWN_SIG_ALG           0x0180
#define ERR_X509_CERT_UNKNOWN_PK_ALG            0x01A0
#define ERR_X509_CERT_SIG_MISMATCH              0x01C0
#define ERR_X509_KEY_INVALID_PEM                0x01E0
#define ERR_X509_KEY_INVALID_VERSION            0x0200
#define ERR_X509_KEY_INVALID_FORMAT             0x0220
#define ERR_X509_KEY_INVALID_ENC_IV             0x0240
#define ERR_X509_KEY_UNKNOWN_ENC_ALG            0x0260
#define ERR_X509_KEY_PASSWORD_REQUIRED          0x0280
#define ERR_X509_KEY_PASSWORD_MISMATCH          0x02A0
#define ERR_X509_SIG_VERIFY_FAILED              0x02C0

#define BADCERT_HAS_EXPIRED             1
#define BADCERT_CN_MISMATCH             2
#define BADCERT_NOT_TRUSTED             4

/*
 * some DER constants
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

#define OID_X520                "\x55\x04"
#define OID_PKCS1               "\x2A\x86\x48\x86\xF7\x0D\x01\x01"
#define OID_PKCS1_RSA           "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01"
#define OID_PKCS9               "\x2A\x86\x48\x86\xF7\x0D\x01\x09"

typedef struct
{
    uint tag;
    uint len;
    uchar *p;
}
x509_buf;

typedef struct
{
    x509_buf oid;
    x509_buf val;
    void *next;
}
x509_name;

typedef struct
{
    int year, mon, day;
    int hour, min, sec;
}
x509_time;

typedef struct
{
    x509_buf raw;
    x509_buf tbs;

    uint version;
    x509_buf serial;
    x509_buf sig_oid1;

    x509_name issuer;
    x509_time valid_from;
    x509_time valid_to;
    x509_name subject;

    x509_buf pk_oid;
    rsa_context rsa;

    x509_buf issuer_id;
    x509_buf subject_id;
    x509_buf v3_ext;

    uint ca_istrue;
    uint max_pathlen;

    x509_buf sig_oid2;
    x509_buf sig;

    void *next; 
}
x509_cert;

/*
 * Parse one or more certificate and add them to the chain.
 */
int x509_add_certs( x509_cert *chain, uchar *buf, uint buflen );

/*
 * Load a certificate from file, returns 0 if successful.
 */
int x509_read_crtfile( x509_cert *chain, char *filename );

/*
 * Parse a DER-encoded private key file.
 */
int x509_parse_key( rsa_context *rsa, uchar *buf, uint buflen,
                                      uchar *pwd, uint pwdlen );

/*
 * Load a private key from file, optionaly password-protected.
 */
int x509_read_keyfile( rsa_context *rsa, char *filename, char *password );

/*
 * Store the DN in printable form into buf; no more
 * than (end - buf) characters will be written.
 */
int dn_gets( char *buf, char *end, x509_name *dn );

/*
 * Returns an informational string about the certificate,
 * or NULL if memory allocation failed.
 */
char *x509_cert_info( x509_cert *crt );

/*
 * Returns 0 if certificate is still valid, or BADCERT_HAS_EXPIRED.
 */
int x509_is_cert_expired( x509_cert *crt );

/*
 * Verify the certificate validity; set cn to NULL if the subject
 * CommonName must not be verified.
 *
 * Returns 0 if successful or ERR_X509_SIG_VERIFY_FAILED,
 * in which case *flags will have one or more of the following
 * values set:
 *      BADCERT_HAS_EXPIRED
 *      BADCERT_CN_MISMATCH
 *      BADCERT_NOT_TRUSTED
 */
int x509_verify_cert( x509_cert *crt, x509_cert *trust_ca,
                      char *cn, uint *flags );

/*
 * Unallocate all certificate data
 */
void x509_free_cert( x509_cert *crt );

/*
 * Checkup routine
 */
int x509_self_test( void );

#endif /* x509.h */