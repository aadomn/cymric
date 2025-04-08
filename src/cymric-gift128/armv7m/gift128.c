#include "gift128.h"

cipher_ctx_t gift128_get_cipher_ctx(void) {
    cipher_ctx_t ctx = {
        .encrypt = giftb128_encrypt,
        .kexpand = gift128_keyschedule,
        .rkeys_size = sizeof(gift128_roundkeys_t),
    };
    return ctx;
}

extern void gift128_keyschedule(void* rkeys, const uint8_t* key);

extern void giftb128_encrypt(uint8_t* ctext, const uint8_t* ptext, const void* rkeys);
