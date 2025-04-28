#include "lea128.h"

cipher_ctx_t lea128_get_cipher_ctx(void) {
    cipher_ctx_t ctx = {
        .encrypt = (void (*)(uint8_t*, const uint8_t*, const void*))lea128_encrypt,
        .kexpand = (void (*)(void *, const uint8_t *))lea128_kexpand,
        .rkeys_size = 24*16,
    };
    return ctx;
}

extern void lea128_kexpand(uint8_t* round_keys, const uint8_t* key);
extern void lea128_encrypt(uint8_t* out, const uint8_t* in, const uint8_t* round_keys);
