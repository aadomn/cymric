#include "lea128.h"

cipher_ctx_t lea128_get_cipher_ctx(void) {
    cipher_ctx_t ctx = {
        .encrypt = lea128_encrypt,
        .kexpand = NULL,    // key is expanded on-the-fly => no kexpand func
        .rkeys_size = 16,   // key is expanded on-the-fly => rkeys = key
    };
    return ctx;
}

extern void lea128_encrypt(uint8_t* ctext, const uint8_t* ptext, const void* key);
