#include "mbedtls/ed25519.h"
#include "mbedtls/sha512.h"
#include "ed25519/ge.h"


void ed25519_create_keypair(unsigned char *public_key, unsigned char *private_key, const unsigned char *seed) {
    ge_p3 A;

    mbedtls_sha512_context hash;
    mbedtls_sha512_init(&hash);
    mbedtls_sha512_starts(&hash, 0);
    mbedtls_sha512_update(&hash, seed, 32);
    mbedtls_sha512_finish(&hash, private_key);
    mbedtls_sha512_free(&hash);

    private_key[0] &= 248;
    private_key[31] &= 63;
    private_key[31] |= 64;

    ge_scalarmult_base(&A, private_key);
    ge_p3_tobytes(public_key, &A);
}
