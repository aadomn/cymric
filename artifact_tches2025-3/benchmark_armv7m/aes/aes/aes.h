#ifndef AES_H_
#define AES_H_

#include <stdint.h>
#include "../modes/cymric/cipher_ctx.h"

#define BLOCKBYTES 16
#define KEYBYTES   16
#define RKEYSWORDS KEYBYTES/2*11

typedef struct {uint32_t rk[88];} aes128_roundkeys_t;

cipher_ctx_t aes128_get_cipher_ctx(void);

/* Semi-fixsliced encryption functions */
void aes128_encrypt_sfs(unsigned char ctext0[16], unsigned char ctext1[16],
				const unsigned char ptext0[16], const unsigned char ptext1[16],
				const void* roundkeys);

/* Semi-fixsliced key schedule functions (LUT-based) */
void aes128_keyschedule_sfs_lut(void* roundkeys, const unsigned char key[16]);

#endif 	// AES_H_
