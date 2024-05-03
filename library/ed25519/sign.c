#include "ed25519/ed25519.h"
#include "mbedtls/sha512.h"
#include "ed25519/ge.h"
#include "ed25519/sc.h"


void ed25519_sign(unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key, const unsigned char *private_key) {
    mbedtls_sha512_context hash;
    unsigned char hram[64];
    unsigned char r[64];
    ge_p3 R;

    mbedtls_sha512_init(&hash);
    mbedtls_sha512_starts(&hash, 0);
    mbedtls_sha512_update(&hash, private_key + 32, 32);
    mbedtls_sha512_update(&hash, message, message_len);
    mbedtls_sha512_finish(&hash, r);
    mbedtls_sha512_free(&hash);

    sc_reduce(r);
    ge_scalarmult_base(&R, r);
    ge_p3_tobytes(signature, &R);

    mbedtls_sha512_init(&hash);
    mbedtls_sha512_starts(&hash, 0);
    mbedtls_sha512_update(&hash, signature, 32);
    mbedtls_sha512_update(&hash,  public_key, 32);
    mbedtls_sha512_update(&hash, message, message_len);
    mbedtls_sha512_finish(&hash, hram);
    mbedtls_sha512_free(&hash);

    sc_reduce(hram);
    sc_muladd(signature + 32, hram, private_key, r);
}
