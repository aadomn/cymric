#ifndef LEA128_H_
#define LEA128_H_

#include "../cipher_ctx.h"

typedef struct {uint8_t k[24*16];} lea128_roundkeys_t;

cipher_ctx_t lea128_get_cipher_ctx(void);

void lea128_kexpand(uint8_t* round_keys, const uint8_t* key);
void lea128_encrypt(uint8_t* out, const uint8_t* in, const uint8_t* round_keys);

#endif /* LEA128_H_ */
