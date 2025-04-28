#include "gift128.h"


cipher_ctx_t gift128_get_cipher_ctx(void) {
    cipher_ctx_t ctx = {
        .encrypt = giftb128_encrypt,
        .kexpand = gift128_keyschedule,
        .rkeys_size = sizeof(gift128_roundkeys_t),
    };
    return ctx;
}
