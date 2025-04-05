#ifndef AES_H_
#define AES_H_

#include <wmmintrin.h>
#include <stdint.h>
#include "cipher_ctx.h"

typedef struct {
	__m128i rk[11];
} aes_roundkeys_t;

cipher_ctx_t aes_get_cipher_ctx(void);
void aes128_enc(uint8_t* out, const uint8_t* in, const void* rkeys);
void aes128_kexp(void* rkeys, const uint8_t* key);


#endif
