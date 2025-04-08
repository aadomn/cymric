#ifndef GIFT128_H_
#define GIFT128_H_

#include "../cipher_ctx.h"

typedef struct {uint32_t roundkeys[80];} gift128_roundkeys_t;

cipher_ctx_t gift128_get_cipher_ctx(void);

void gift128_keyschedule(void* rkeys, const uint8_t* key);
void giftb128_encrypt(uint8_t* ctext, const uint8_t* ptext, const void* rkeys);

#endif  // GIFT128_H_
