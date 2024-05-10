#ifndef MBEDTLS_ED25519_H
#define MBEDTLS_ED25519_H

#include <stddef.h>

#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#define ED25519_PUBLIC_KEY_SIZE     32
#define ED25519_PRIVATE_KEY_SIZE    64
#define ED25519_SIGNATURE_SIZE      64
#define ED25519_PARSE_PUBLIC_KEY    0
#define ED25519_PARSE_PRIVATE_KEY   1

typedef struct mbedtls_ed25519_context {
    int MBEDTLS_PRIVATE(ver);                   /*!<  Reserved for internal purposes.
                                                 *    Do not set this field in application
                                                 *    code. Its meaning might change without
                                                 *    notice. 
                                                 */
    size_t len;                                 /*!<  The size of \p N in Bytes. */
    unsigned char pub_key[ED25519_PUBLIC_KEY_SIZE];
    unsigned char priv_key[ED25519_PRIVATE_KEY_SIZE];
    int has_priv_key;

}
mbedtls_ed25519_context;

typedef void mbedtls_ed25519_restart_ctx;

// removed pk_get_ed25519pubkey
int pk_set_ed25519pubkey(unsigned char **p, mbedtls_ed25519_context *ed25519);
int pk_set_ed25519privkey(unsigned char **p, mbedtls_ed25519_context *ed25519);
int pk_write_ed25519_pubkey(unsigned char **p, unsigned char *start, mbedtls_ed25519_context *ed25519);
int pk_parse_ed25519_pubkey(unsigned char **p, mbedtls_ed25519_context *ed25519);

#endif