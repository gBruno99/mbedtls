/**
 * \file x509_crl.h
 *
 * \brief X.509 certificate revocation list parsing
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_X509_CRL_H
#define MBEDTLS_X509_CRL_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include "mbedtls/x509.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \addtogroup x509_module
 * \{ */

/**
 * \name Structures and functions for parsing and writing CRLs
 * \{
 */

/**
 * Certificate revocation list entry.
 * Contains the CA-specific serial numbers and revocation dates.
 *
 * Some fields of this structure are publicly readable. Do not modify
 * them except via Mbed TLS library functions: the effect of modifying
 * those fields or the data that those fields points to is unspecified.
 */
typedef struct mbedtls_x509_crl_entry {
    /** Direct access to the whole entry inside the containing buffer. */
    mbedtls_x509_buf raw;
    /** The serial number of the revoked certificate. */
    mbedtls_x509_buf serial;
    /** The revocation date of this entry. */
    mbedtls_x509_time revocation_date;
    /** Direct access to the list of CRL entry extensions
     * (an ASN.1 constructed sequence).
     *
     * If there are no extensions, `entry_ext.len == 0` and
     * `entry_ext.p == NULL`. */
    mbedtls_x509_buf entry_ext;

    /** Next element in the linked list of entries.
     * \p NULL indicates the end of the list.
     * Do not modify this field directly. */
    struct mbedtls_x509_crl_entry *next;
}
mbedtls_x509_crl_entry;

/**
 * Certificate revocation list structure.
 * Every CRL may have multiple entries.
 */
typedef struct mbedtls_x509_crl {
    mbedtls_x509_buf raw;           /**< The raw certificate data (DER). */
    mbedtls_x509_buf tbs;           /**< The raw certificate body (DER). The part that is To Be Signed. */

    int version;            /**< CRL version (1=v1, 2=v2) */
    mbedtls_x509_buf sig_oid;       /**< CRL signature type identifier */

    mbedtls_x509_buf issuer_raw;    /**< The raw issuer data (DER). */

    mbedtls_x509_name issuer;       /**< The parsed issuer data (named information object). */

    mbedtls_x509_time this_update;
    mbedtls_x509_time next_update;

    mbedtls_x509_crl_entry entry;   /**< The CRL entries containing the certificate revocation times for this CA. */

    mbedtls_x509_buf crl_ext;

    mbedtls_x509_buf MBEDTLS_PRIVATE(sig_oid2);
    mbedtls_x509_buf MBEDTLS_PRIVATE(sig);
    mbedtls_md_type_t MBEDTLS_PRIVATE(sig_md);           /**< Internal representation of the MD algorithm of the signature algorithm, e.g. MBEDTLS_MD_SHA256 */
    mbedtls_pk_type_t MBEDTLS_PRIVATE(sig_pk);           /**< Internal representation of the Public Key algorithm of the signature algorithm, e.g. MBEDTLS_PK_RSA */
    void *MBEDTLS_PRIVATE(sig_opts);             /**< Signature options to be passed to mbedtls_pk_verify_ext(), e.g. for RSASSA-PSS */

    /** Next element in the linked list of CRL.
     * \p NULL indicates the end of the list.
     * Do not modify this field directly. */
    struct mbedtls_x509_crl *next;
}
mbedtls_x509_crl;

#define MBEDTLS_X509_CRL_VERSION_1  0
#define MBEDTLS_X509_CRL_VERSION_2  1

/**
 * Container for writing an entry of the CRL
 */
typedef struct mbedtls_x509write_crl_entry {
    unsigned char MBEDTLS_PRIVATE(serial)[MBEDTLS_X509_RFC5280_MAX_SERIAL_LEN];
    size_t MBEDTLS_PRIVATE(serial_len);

    char MBEDTLS_PRIVATE(rev_date)[MBEDTLS_X509_RFC5280_UTC_TIME_LEN + 1];

    mbedtls_asn1_named_data *MBEDTLS_PRIVATE(entry_extensions);
}
mbedtls_x509write_crl_entry;

/**
 * Container for writing a CRL
 */
typedef struct mbedtls_x509write_crl {
    int MBEDTLS_PRIVATE(version);

    mbedtls_pk_context *MBEDTLS_PRIVATE(issuer_key);
    mbedtls_md_type_t MBEDTLS_PRIVATE(md_alg);

    mbedtls_asn1_named_data *MBEDTLS_PRIVATE(issuer);

    char MBEDTLS_PRIVATE(this_update)[MBEDTLS_X509_RFC5280_UTC_TIME_LEN + 1];
    char MBEDTLS_PRIVATE(next_update)[MBEDTLS_X509_RFC5280_UTC_TIME_LEN + 1];

    mbedtls_asn1_named_data *MBEDTLS_PRIVATE(crl_extensions);
    mbedtls_x509_sequence MBEDTLS_PRIVATE(revoked_crts);
}
mbedtls_x509write_crl;

/**
 * \brief          Parse a DER-encoded CRL and append it to the chained list
 *
 * \note           If #MBEDTLS_USE_PSA_CRYPTO is enabled, the PSA crypto
 *                 subsystem must have been initialized by calling
 *                 psa_crypto_init() before calling this function.
 *
 * \param chain    points to the start of the chain
 * \param buf      buffer holding the CRL data in DER format
 * \param buflen   size of the buffer
 *                 (including the terminating null byte for PEM data)
 *
 * \return         0 if successful, or a specific X509 or PEM error code
 */
int mbedtls_x509_crl_parse_der(mbedtls_x509_crl *chain,
                               const unsigned char *buf, size_t buflen);
/**
 * \brief          Parse one or more CRLs and append them to the chained list
 *
 * \note           Multiple CRLs are accepted only if using PEM format
 *
 * \note           If #MBEDTLS_USE_PSA_CRYPTO is enabled, the PSA crypto
 *                 subsystem must have been initialized by calling
 *                 psa_crypto_init() before calling this function.
 *
 * \param chain    points to the start of the chain
 * \param buf      buffer holding the CRL data in PEM or DER format
 * \param buflen   size of the buffer
 *                 (including the terminating null byte for PEM data)
 *
 * \return         0 if successful, or a specific X509 or PEM error code
 */
int mbedtls_x509_crl_parse(mbedtls_x509_crl *chain, const unsigned char *buf, size_t buflen);

#if defined(MBEDTLS_FS_IO)
/**
 * \brief          Load one or more CRLs and append them to the chained list
 *
 * \note           Multiple CRLs are accepted only if using PEM format
 *
 * \note           If #MBEDTLS_USE_PSA_CRYPTO is enabled, the PSA crypto
 *                 subsystem must have been initialized by calling
 *                 psa_crypto_init() before calling this function.
 *
 * \param chain    points to the start of the chain
 * \param path     filename to read the CRLs from (in PEM or DER encoding)
 *
 * \return         0 if successful, or a specific X509 or PEM error code
 */
int mbedtls_x509_crl_parse_file(mbedtls_x509_crl *chain, const char *path);
#endif /* MBEDTLS_FS_IO */

#if !defined(MBEDTLS_X509_REMOVE_INFO)
/**
 * \brief          Returns an informational string about the CRL.
 *
 * \param buf      Buffer to write to
 * \param size     Maximum size of buffer
 * \param prefix   A line prefix
 * \param crl      The X509 CRL to represent
 *
 * \return         The length of the string written (not including the
 *                 terminated nul byte), or a negative error code.
 */
int mbedtls_x509_crl_info(char *buf, size_t size, const char *prefix,
                          const mbedtls_x509_crl *crl);
#endif /* !MBEDTLS_X509_REMOVE_INFO */

/**
 * \brief          Initialize a CRL (chain)
 *
 * \param crl      CRL chain to initialize
 */
void mbedtls_x509_crl_init(mbedtls_x509_crl *crl);

/**
 * \brief          Unallocate all CRL data
 *
 * \param crl      CRL chain to free
 */
void mbedtls_x509_crl_free(mbedtls_x509_crl *crl);

// CRL ENTRY
void mbedtls_x509write_crl_entry_init(mbedtls_x509write_crl_entry *clx_entry);

void mbedtls_x509write_crl_entry_free(mbedtls_x509write_crl_entry *clx_entry);

#if defined(MBEDTLS_BIGNUM_C) && !defined(MBEDTLS_DEPRECATED_REMOVED)
int mbedtls_x509write_crl_entry_set_serial(mbedtls_x509write_crl_entry *clx_entry,
                                           const mbedtls_mpi *serial);
#endif // MBEDTLS_BIGNUM_C && !MBEDTLS_DEPRECATED_REMOVED

int mbedtls_x509write_crl_entry_set_serial_raw(mbedtls_x509write_crl_entry *clx_entry,
                                         unsigned char *serial, size_t serial_len);

int mbedtls_x509write_crl_entry_set_revocation(mbedtls_x509write_crl_entry *clx_entry, 
                                               const char *rev_date);

int mbedtls_x509write_crl_entry_set_extension(mbedtls_x509write_crl_entry *clx_entry,
                                              const char *oid, size_t oid_len,
                                              int critical,
                                              const unsigned char *val, size_t val_len);

// CRL
void mbedtls_x509write_crl_init(mbedtls_x509write_crl *clx);

void mbedtls_x509write_crl_free(mbedtls_x509write_crl *clx);

void mbedtls_x509write_crl_set_version(mbedtls_x509write_crl *clx, int version);

void mbedtls_x509write_crl_set_md_alg(mbedtls_x509write_crl *clx, mbedtls_md_type_t md_alg);

void mbedtls_x509write_crl_set_issuer_key(mbedtls_x509write_crl *clx, mbedtls_pk_context *key);

int mbedtls_x509write_crl_set_issuer_name(mbedtls_x509write_crl *clx, const char *issuer_name);

int mbedtls_x509write_crl_set_validity(mbedtls_x509write_crl *clx, 
                                       const char *this_update,
                                       const char *next_update);

int mbedtls_x509write_crl_set_extension(mbedtls_x509write_crl *clx,
                                        const char *oid, size_t oid_len,
                                        int critical,
                                        const unsigned char *val, size_t val_len);

int mbedtls_x509write_crl_set_revoked_crt(mbedtls_x509write_crl *clx,
                                          mbedtls_x509write_crl_entry *clx_entry);

int mbedtls_x509write_crl_der(mbedtls_x509write_crl *clx, unsigned char *buf, size_t size,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng);

/** \} name Structures and functions for parsing and writing CRLs */
/** \} addtogroup x509_module */

#ifdef __cplusplus
}
#endif

#endif /* mbedtls_x509_crl.h */
