#ifndef _RIJNDAEL_FAST_H
#define _RIJNDAEL_FAST_H

#include "cipher_ctx.h"

typedef struct {unsigned char k[11*16];} aes128_roundkeys_t;

cipher_ctx_t aes128_get_cipher_ctx(void);

void expand_key(unsigned char *rkeys, const unsigned char* key);
void encrypt_data(unsigned char * out, const unsigned char *in, const unsigned char *expanded);

#endif