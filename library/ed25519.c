#include "mbedtls/ed25519.h"
#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/error.h"
#include <string.h>

// removed pk_get_ed25519pubkey

int pk_set_ed25519pubkey(unsigned char **p, mbedtls_ed25519_context *ed25519) {

    for (int i = 0; i < ED25519_PUBLIC_KEY_SIZE; i++) {
        ed25519->pub_key[i] = (*p)[i];
    }
    ed25519->len = ED25519_PUBLIC_KEY_SIZE;

    return 0;
}

int pk_set_ed25519privkey(unsigned char **p, mbedtls_ed25519_context *ed25519) {

    for (int i = 0; i < ED25519_PRIVATE_KEY_SIZE; i++) {
        ed25519->priv_key[i] = (*p)[i];
    }
    ed25519->len = ED25519_PRIVATE_KEY_SIZE;
    ed25519->has_priv_key = 1;

    return 0;
}

int pk_write_ed25519_pubkey(unsigned char **p, unsigned char *start, mbedtls_ed25519_context *ed25519) {

    // ------- OLD implementation -------
    size_t len = ED25519_PUBLIC_KEY_SIZE;
    unsigned char buf[ED25519_PUBLIC_KEY_SIZE];

    for (int i = 0; i < ED25519_PUBLIC_KEY_SIZE; i++) {
        buf[i] = ed25519->pub_key[i];
    }

    if (*p < start || (size_t)(*p - start) < len) {
        return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL;
    }
    *p -= len;

    memcpy(*p, buf, len);
    // ----------------------------------

    // ------- NEW implementation -------
    // int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    // size_t len = 0;
    // MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_bitstring(p, start, ed25519->pub_key, 8*ED25519_PUBLIC_KEY_SIZE));
    // ----------------------------------

    return (int) len;
}

int pk_parse_ed25519_pubkey(unsigned char **p, mbedtls_ed25519_context *ed25519) {
    int ret = pk_set_ed25519pubkey(p, ed25519);
    *p += 32;
    return ret;
}
