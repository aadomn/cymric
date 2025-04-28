#include "gift128.h"

cipher_ctx_t gift128_get_cipher_ctx(void) {
	cipher_ctx_t ctx = {
		.encrypt = (void (*)(uint8_t*, const uint8_t*, const void*))gift128_encrypt,
		.kexpand = (void (*)(void *, const uint8_t *))gift128_kexpand,
		.rkeys_size = 80*4,
	};
	return ctx;
}

extern void gift128_kexpand(unsigned char* rkeys, const unsigned char* key);
extern void gift128_encrypt(unsigned char* out_block, const unsigned char* in_block, const unsigned char* rkeys);
