#ifndef GIFT128_H_
#define GIFT128_H_

#define GIFT128_KEY_SIZE    16
#define GIFT128_BLOCK_SIZE  16
#define GIFT128_KEY_SCHEDULE_WORDS  4

#include "../cipher_ctx.h"

typedef struct {uint8_t k[80*4];} gift128_roundkeys_t;

cipher_ctx_t gift128_get_cipher_ctx(void);

void gift128_kexpand(unsigned char* rkeys, const unsigned char* key);
void gift128_encrypt(unsigned char* out_block, const unsigned char* in_block, const unsigned char* rkeys);

#endif  // GIFT128_H_
