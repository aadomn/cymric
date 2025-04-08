#include "rijndaelfast.h"

cipher_ctx_t aes128_get_cipher_ctx(void) {
	cipher_ctx_t ctx = {
		.encrypt = (void (*)(uint8_t*, const uint8_t*, const void*))encrypt_data,
		.kexpand = (void (*)(void *, const uint8_t *))expand_key,
		.rkeys_size = sizeof(aes128_roundkeys_t),
	};
	return ctx;
}

extern void expand_key(unsigned char *rkeys, const unsigned char* key);
extern void encrypt_data(unsigned char * out, const unsigned char *in, const unsigned char *expanded);

