#include <string.h>
#include <stdint.h>

#include "common.h"

#include "mbedtls/x509_crt.h"
#include "x509_internal.h"
#include "mbedtls/x509_crl.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/error.h"
#include "mbedtls/oid.h"
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/md.h"

#define CRL_ENTRY_BUF_SIZE      512

static int x509_write_crl_revoked_cert(unsigned char **p, unsigned char *start,
                                mbedtls_asn1_sequence *revoked)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(p, start, revoked->buf.p,
                                                            revoked->buf.len));
    // MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, revoked->buf.len - 1));

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SEQUENCE));

    return (int) len;
}

static int mbedtls_x509_write_rev_certs(unsigned char **p, unsigned char *start,
                                 mbedtls_x509_sequence *first)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t len = 0;
    mbedtls_x509_sequence *cur_revoked = first;

    while (cur_revoked != NULL)
    {
        MBEDTLS_ASN1_CHK_ADD(len, x509_write_crl_revoked_cert(p, start, cur_revoked));
        cur_revoked = cur_revoked->next;
    }

    return (int) len;    
}

/*  CRL ENTRY  */

// Init the mbedtls_x509write_crl_entry structure
void mbedtls_x509write_crl_entry_init(mbedtls_x509write_crl_entry *clx_entry)
{
    memset(clx_entry, 0, sizeof(mbedtls_x509write_crl_entry));
}

// Free the mbedtls_x509write_crl_entry structure
void mbedtls_x509write_crl_entry_free(mbedtls_x509write_crl_entry *clx_entry)
{
    mbedtls_asn1_free_named_data_list(&clx_entry->MBEDTLS_PRIVATE(entry_extensions));

    mbedtls_platform_zeroize(clx_entry, sizeof(mbedtls_x509write_crl_entry));
}

#if defined(MBEDTLS_BIGNUM_C) && !defined(MBEDTLS_DEPRECATED_REMOVED)
// Set the CRL ENTRY serial
int mbedtls_x509write_crl_entry_set_serial(mbedtls_x509write_crl_entry *clx_entry,
                                           const mbedtls_mpi *serial) 
{
    int ret;
    size_t tmp_len;

    /* Ensure that the MPI value fits into the buffer */
    tmp_len = mbedtls_mpi_size(serial);
    if (tmp_len > MBEDTLS_X509_RFC5280_MAX_SERIAL_LEN) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }

    clx_entry->MBEDTLS_PRIVATE(serial_len) = tmp_len;
    
    ret = mbedtls_mpi_write_binary(serial, clx_entry->MBEDTLS_PRIVATE(serial), tmp_len);
    if (ret < 0) {
        return ret;
    }

    return 0;
}
#endif // MBEDTLS_BIGNUM_C && !MBEDTLS_DEPRECATED_REMOVED

int mbedtls_x509write_crl_entry_set_serial_raw(mbedtls_x509write_crl_entry *clx_entry,
                                         unsigned char *serial, size_t serial_len)
{
    if (serial_len > MBEDTLS_X509_RFC5280_MAX_SERIAL_LEN) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }

    clx_entry->MBEDTLS_PRIVATE(serial_len) = serial_len;
    memcpy(clx_entry->MBEDTLS_PRIVATE(serial), serial, serial_len);

    return 0;
}

// Set the CRL ENTRY revocation date
int mbedtls_x509write_crl_entry_set_revocation(mbedtls_x509write_crl_entry *clx_entry, 
                                               const char *rev_date)
{
    if (strlen(rev_date) != MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }
    strncpy(clx_entry->MBEDTLS_PRIVATE(rev_date), rev_date, MBEDTLS_X509_RFC5280_UTC_TIME_LEN);
    clx_entry->MBEDTLS_PRIVATE(rev_date)[MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1] = 'Z';

    return 0;
}

// Set a CRL ENTRY extension
int mbedtls_x509write_crl_entry_set_extension(mbedtls_x509write_crl_entry *clx_entry,
                                              const char *oid, size_t oid_len,
                                              int critical,
                                              const unsigned char *val, size_t val_len) 
{
    return mbedtls_x509_set_extension(&clx_entry->MBEDTLS_PRIVATE(entry_extensions), oid, oid_len,
                                      critical, val, val_len);
}

/* CRL */

// Init the mbedtls_x509write_crl structure
void mbedtls_x509write_crl_init(mbedtls_x509write_crl *clx)
{
    memset(clx, 0, sizeof(mbedtls_x509write_crl));

    clx->version = MBEDTLS_X509_CRL_VERSION_2;
}

// Free the mbedtls_x509write_crl structure
void mbedtls_x509write_crl_free(mbedtls_x509write_crl *clx)
{
    mbedtls_asn1_free_named_data_list(&clx->issuer);
    mbedtls_asn1_free_named_data_list(&clx->crl_extensions);
    mbedtls_asn1_sequence_free(clx->revoked_crts.next);

    mbedtls_platform_zeroize(clx, sizeof(mbedtls_x509write_crl));
}

// Set the CRL version 
void mbedtls_x509write_crl_set_version(mbedtls_x509write_crl *clx, int version)
{
    clx->version = version;
}

void mbedtls_x509write_crl_set_md_alg(mbedtls_x509write_crl *clx,
                                      mbedtls_md_type_t md_alg)
{
    clx->md_alg = md_alg;
}

void mbedtls_x509write_crl_set_issuer_key(mbedtls_x509write_crl *clx,
                                           mbedtls_pk_context *key)
{
    clx->issuer_key = key;
}

// Set the CRL issuer name
int mbedtls_x509write_crl_set_issuer_name(mbedtls_x509write_crl *clx, const char *issuer_name)
{
    return mbedtls_x509_string_to_names(&clx->issuer, issuer_name);
}

// Set the CRL validity (last and next update)
int mbedtls_x509write_crl_set_validity(mbedtls_x509write_crl *clx, 
                                       const char *this_update,
                                       const char *next_update)
{
    if (strlen(this_update) != MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1 ||
        strlen(next_update)  != MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1) {
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    }
    strncpy(clx->this_update, this_update, MBEDTLS_X509_RFC5280_UTC_TIME_LEN);
    strncpy(clx->next_update, next_update, MBEDTLS_X509_RFC5280_UTC_TIME_LEN);
    clx->this_update[MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1] = 'Z';
    clx->next_update[MBEDTLS_X509_RFC5280_UTC_TIME_LEN - 1] = 'Z';

    return 0;
}

// Set the CRL exetensions
int mbedtls_x509write_crl_set_extension(mbedtls_x509write_crl *clx,
                                        const char *oid, size_t oid_len,
                                        int critical,
                                        const unsigned char *val, size_t val_len)
{
    return mbedtls_x509_set_extension(&clx->crl_extensions, oid, oid_len,
                                      critical, val, val_len);
}

int mbedtls_x509write_crl_set_revoked_crt(mbedtls_x509write_crl *clx,
                                          mbedtls_x509write_crl_entry *clx_entry)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    unsigned char *c;
    unsigned char buf[CRL_ENTRY_BUF_SIZE];

    // Pointer to revoked_certs, entry point of the list
    mbedtls_asn1_sequence *curr = &clx->revoked_crts;
    mbedtls_asn1_sequence* new;

    size_t len = 0, sub_len = 0;

    c = buf + CRL_ENTRY_BUF_SIZE;

    /*
     *  crlEntryExtension  ::=  SEQUENCE SIZE (1..MAX) OF Extension
     */    

    /* Only for v2 */
    if (clx->version == MBEDTLS_X509_CRL_VERSION_2) {
        MBEDTLS_ASN1_CHK_ADD(len,
                             mbedtls_x509_write_extensions(&c,
                                                           buf, clx_entry->entry_extensions));
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
        MBEDTLS_ASN1_CHK_ADD(len,
                             mbedtls_asn1_write_tag(&c, buf,
                                                    MBEDTLS_ASN1_CONSTRUCTED |
                                                    MBEDTLS_ASN1_SEQUENCE));
        // MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
        // MBEDTLS_ASN1_CHK_ADD(len,
        //                      mbedtls_asn1_write_tag(&c, buf,
        //                                             MBEDTLS_ASN1_CONTEXT_SPECIFIC |
        //                                             MBEDTLS_ASN1_CONSTRUCTED | 3));
    }

    /*
     *  revocationDate  ::=  Time
     */
    sub_len = 0; 

    MBEDTLS_ASN1_CHK_ADD(sub_len,
                         x509_write_time(&c, buf, clx_entry->rev_date,
                                         MBEDTLS_X509_RFC5280_UTC_TIME_LEN));
    len += sub_len;
    // MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, sub_len));
    // MBEDTLS_ASN1_CHK_ADD(len,
    //                      mbedtls_asn1_write_tag(&c, buf,
    //                                             MBEDTLS_ASN1_CONSTRUCTED |
    //                                             MBEDTLS_ASN1_SEQUENCE));

    /*
     *  userCertificate  ::=  CertificateSerialNumber (INTEGER) 
     *
     * Written data is:
     * - "ctx->serial_len" bytes for the raw serial buffer
     *   - if MSb of "serial" is 1, then prepend an extra 0x00 byte
     * - 1 byte for the length
     * - 1 byte for the TAG
     */
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(&c, buf,
                                                            clx_entry->serial, clx_entry->serial_len));

    if (*c & 0x80) {
        if (c - buf < 1) {
            return MBEDTLS_ERR_X509_BUFFER_TOO_SMALL;
        }
        *(--c) = 0x0;
        len++;
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf,
                                                         clx_entry->serial_len + 1));
    } else {
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf,
                                                         clx_entry->serial_len));
    }
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf,
                                                     MBEDTLS_ASN1_INTEGER));

    // Navigate the list and update the current node until curr->next == NULL
    while (curr->next != NULL) {
        curr = curr->next;
    }

    if(curr == &clx->revoked_crts && curr->buf.p == NULL) {
        new = curr;
    } else {
        // Allocate the new item of the revoked_certs list (it is a struct mbedtls_asn1_sequence)
        new = (mbedtls_asn1_sequence*)malloc(sizeof(mbedtls_asn1_sequence));
        if (new == NULL) {
            // Handle memory allocation failure
            return MBEDTLS_ERR_X509_ALLOC_FAILED;
        }
    }
    
    // Allocate memory for new->buf.p
    new->buf.p = (unsigned char*)malloc(len);
    if (new->buf.p == NULL) {
        // Handle memory allocation failure
        if(curr != new)
            free(new);
        return MBEDTLS_ERR_X509_ALLOC_FAILED;
    }

    // Write the buf filled with crl_entry and its lenght inside new->buf.p and new->buf.len
    memcpy(new->buf.p, buf + CRL_ENTRY_BUF_SIZE - len, len);
    new->buf.len = len;
    new->next = NULL;

    // Assing to the curr->next pointer the new mbedtls_asn1_sequence* created before.
    if(curr != new) {
        curr->next = new;
    }

    return 0;
}

int mbedtls_x509write_crl_der(mbedtls_x509write_crl *clx, unsigned char *buf, size_t size,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    const char *sig_oid;
    size_t sig_oid_len = 0;
    unsigned char *c; // Pointer to the buf where we want to write
    unsigned char *c2;
    unsigned char sig[MBEDTLS_PK_SIGNATURE_MAX_SIZE];
    size_t len = 0;
    size_t sub_len = 0, /*pub_len = 0,*/ sig_and_oid_len = 0, sig_len;
    mbedtls_pk_type_t pk_alg;
    int write_sig_null_par;
    size_t hash_length = 0;
    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_algorithm_t psa_algorithm;
#endif /* MBEDTLS_USE_PSA_CRYPTO */

    /*
     * Prepare data to be inserted at the end of the target buffer
     */
    c = buf + size;

    /* Signature algorithm needed in TBS, and later for actual signature */

    /* There's no direct way of extracting a signature algorithm
     * (represented as an element of mbedtls_pk_type_t) from a PK instance. */
    if (mbedtls_pk_can_do(clx->issuer_key, MBEDTLS_PK_RSA)) {
        pk_alg = MBEDTLS_PK_RSA;
    } else if (mbedtls_pk_can_do(clx->issuer_key, MBEDTLS_PK_ECDSA)) {
        pk_alg = MBEDTLS_PK_ECDSA;
    } else {
        return MBEDTLS_ERR_X509_INVALID_ALG;
    }

    // Retrive the sig_oid and sig_oid_len from pk_alg and md_alg
    if ((ret = mbedtls_oid_get_oid_by_sig_alg(pk_alg, clx->md_alg,
                                              &sig_oid, &sig_oid_len)) != 0) {
        return ret;
    }

    /*
     *  crlExtensions  ::=  [0] EXPLICIT Extensions OPTIONAL
     *                                 -- if present, version MUST be v2 
     */

    if (clx->version == MBEDTLS_X509_CRL_VERSION_2) {
        MBEDTLS_ASN1_CHK_ADD(len,
                             mbedtls_x509_write_extensions(&c,
                                                           buf, clx->crl_extensions));
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
        MBEDTLS_ASN1_CHK_ADD(len,
                             mbedtls_asn1_write_tag(&c, buf,
                                                    MBEDTLS_ASN1_CONSTRUCTED |
                                                    MBEDTLS_ASN1_SEQUENCE));
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
        MBEDTLS_ASN1_CHK_ADD(len,
                             mbedtls_asn1_write_tag(&c, buf,
                                                    MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                    MBEDTLS_ASN1_CONSTRUCTED | 0));
    }

    /*
     *  revokedCertificates ::= SEQUENCE OF SEQUENCE  {
     *       userCertificate         CertificateSerialNumber,
     *       revocationDate          Time,
     *       crlEntryExtensions      Extensions OPTIONAL
     *                                 -- if present, version MUST be v2
     *                             }  OPTIONAL
     */
    sub_len = 0;
    MBEDTLS_ASN1_CHK_ADD(sub_len, mbedtls_x509_write_rev_certs(&c, buf,
                                                           &clx->revoked_crts));

    len += sub_len;
    // MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
    // MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf,
    //                                                  MBEDTLS_ASN1_CONSTRUCTED |
    //                                                  MBEDTLS_ASN1_SEQUENCE));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, sub_len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf,
                                                     MBEDTLS_ASN1_SEQUENCE |
                                                     MBEDTLS_ASN1_CONSTRUCTED));

    /*
     *  nextUpdate  ::=  Time 
     */
    sub_len = 0;

    MBEDTLS_ASN1_CHK_ADD(sub_len,
                         x509_write_time(&c, buf, clx->next_update,
                                         MBEDTLS_X509_RFC5280_UTC_TIME_LEN));

    len += sub_len;
    // MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, sub_len));
    // MBEDTLS_ASN1_CHK_ADD(len,
    //                      mbedtls_asn1_write_tag(&c, buf,
    //                                             MBEDTLS_ASN1_CONSTRUCTED |
    //                                             MBEDTLS_ASN1_SEQUENCE));

    /*
     *  thisUpdate  ::=  Time 
     */
    sub_len = 0;

    MBEDTLS_ASN1_CHK_ADD(sub_len,
                         x509_write_time(&c, buf, clx->this_update,
                                         MBEDTLS_X509_RFC5280_UTC_TIME_LEN));

    len += sub_len;
    // MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, sub_len));
    // MBEDTLS_ASN1_CHK_ADD(len,
    //                      mbedtls_asn1_write_tag(&c, buf,
    //                                             MBEDTLS_ASN1_CONSTRUCTED |
    //                                             MBEDTLS_ASN1_SEQUENCE));

    /* 
     *  Issuer  ::=  Name
     */
    MBEDTLS_ASN1_CHK_ADD(len,
                         mbedtls_x509_write_names(&c, buf, clx->issuer));

    /*
     *  Signature   ::=  AlgorithmIdentifier
     */
    if (pk_alg == MBEDTLS_PK_ECDSA) {
        /*
         * The AlgorithmIdentifier's parameters field must be absent for DSA/ECDSA signature
         * algorithms, see https://www.rfc-editor.org/rfc/rfc5480#page-17 and
         * https://www.rfc-editor.org/rfc/rfc5758#section-3.
         */
        write_sig_null_par = 0;
    } else {
        write_sig_null_par = 1;
    }
    MBEDTLS_ASN1_CHK_ADD(len,
                         mbedtls_asn1_write_algorithm_identifier_ext(&c, buf,
                                                                     sig_oid, strlen(sig_oid),
                                                                     0, write_sig_null_par));

    /*
     *  Version ::= INTEGER {  v1(0), v2(1)  }
     */

    /* Can be omitted for v1 */
    if (clx->version != MBEDTLS_X509_CRL_VERSION_1) {
        sub_len = 0;
        MBEDTLS_ASN1_CHK_ADD(sub_len, 
                             mbedtls_asn1_write_int(&c, buf, clx->version));
        len += sub_len;
        // MBEDTLS_ASN1_CHK_ADD(len, 
        //                      mbedtls_asn1_write_len(&c, buf, sub_len));
        // MBEDTLS_ASN1_CHK_ADD(len,
        //                      mbedtls_asn1_write_tag(&c, buf,
        //                                             MBEDTLS_ASN1_CONTEXT_SPECIFIC |
        //                                             MBEDTLS_ASN1_CONSTRUCTED | 0));
    }

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len,
                         mbedtls_asn1_write_tag(&c, buf, MBEDTLS_ASN1_CONSTRUCTED |
                                                MBEDTLS_ASN1_SEQUENCE));

    /*
     * Make signature
     */

    /* Compute hash of CRL. */
    #if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_algorithm = mbedtls_md_psa_alg_from_type(clx->md_alg);

    status = psa_hash_compute(psa_algorithm,
                              c,
                              len,
                              hash,
                              sizeof(hash),
                              &hash_length);
    if (status != PSA_SUCCESS) {
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }
#else
    if ((ret = mbedtls_md(mbedtls_md_info_from_type(clx->md_alg), c,
                          len, hash)) != 0) {
        return ret;
    }
#endif /* MBEDTLS_USE_PSA_CRYPTO */


    if ((ret = mbedtls_pk_sign(clx->issuer_key, clx->md_alg,
                               hash, hash_length, sig, sizeof(sig), &sig_len,
                               f_rng, p_rng)) != 0) {
        return ret;
    }

    /* Move CRT to the front of the buffer to have space
     * for the signature. */
    memmove(buf, c, len);
    c = buf + len;

    /* Add signature at the end of the buffer,
     * making sure that it doesn't underflow
     * into the CRT buffer. */
    c2 = buf + size;
    MBEDTLS_ASN1_CHK_ADD(sig_and_oid_len, mbedtls_x509_write_sig(&c2, c,
                                                                 sig_oid, sig_oid_len,
                                                                 sig, sig_len, pk_alg));

    /*
     * Memory layout after this step:
     *
     * buf       c=buf+len                c2            buf+size
     * [CRT0,...,CRTn, UNUSED, ..., UNUSED, SIG0, ..., SIGm]
     */

    /* Move raw CRT to just before the signature. */
    c = c2 - len;
    memmove(c, buf, len);

    len += sig_and_oid_len;
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&c, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&c, buf,
                                                     MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SEQUENCE));

    return (int) len;
}
