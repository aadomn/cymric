#ifndef LEA128_H_
#define LEA128_H_

#include "../cipher_ctx.h"

cipher_ctx_t lea128_get_cipher_ctx(void);

void lea128_encrypt(uint8_t* ctext, const uint8_t* ptext, const void* key);

#endif 	// LEA128_H_
