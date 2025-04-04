#ifndef BLOCK_CIPHER_H_
#define BLOCK_CIPHER_H_

#include <wmmintrin.h>
#include <stdint.h>
#include "cipher_ctx.h"

// In aes_impl.h
typedef struct {
	__m128i rk[11];   // For AES-128
} aes_roundkeys_t;

void aes128_enc(uint8_t* out, const uint8_t* in, const void* rkeys);
void aes128_kexp(void* rkeys, const uint8_t* key);

cipher_ctx_t aes_get_cipher_ctx(void);

#endif
