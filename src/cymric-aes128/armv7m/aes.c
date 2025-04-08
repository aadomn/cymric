#include "aes.h"

cipher_ctx_t aes128_get_cipher_ctx() {
    cipher_ctx_t ctx = {
        .kexpand = aes128_keyschedule_sfs_lut,
        .encrypt = aes128_encrypt_sfs,
        .rkeys_size = sizeof(aes128_roundkeys_t),
    };
    return ctx;
}

extern void aes128_encrypt_sfs(unsigned char ctext0[16], unsigned char ctext1[16],
				const unsigned char ptext0[16], const unsigned char ptext1[16],
				const void* roundkeys);

extern void aes128_keyschedule_sfs_lut(void* roundkeys, const unsigned char key[16]);
