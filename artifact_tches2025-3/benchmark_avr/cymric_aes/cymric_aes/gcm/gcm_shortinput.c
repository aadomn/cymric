#include <string.h>
#include <stdint.h>
#include "../aes/rijndaelfast.h"
#include "../ghash/ghash.h"
#include "gcm_shortinput.h"
#include "../utils.h"

static inline void AES_PUT_BE64(uint8_t *a, uint64_t val)
{
	a[0] = val >> 56;
	a[1] = val >> 48;
	a[2] = val >> 40;
	a[3] = val >> 32;
	a[4] = val >> 24;
	a[5] = val >> 16;
	a[6] = val >> 8;
	a[7] = val & 0xff;
}

int gcm_shortinput_encrypt(
	unsigned char*       ctext,
	const unsigned char* key,
	const unsigned char* iv,    unsigned int iv_len,
	const unsigned char* ptext, unsigned int ptext_len,
	const unsigned char* adata, unsigned int adata_len)
{
	uint8_t J0[AES_BLOCKBYTES];
	uint8_t S[AES_BLOCKBYTES];
	const unsigned char* H = key + AES_BLOCKBYTES;
	uint8_t rkeys[AES_BLOCKBYTES*11];
	uint8_t H_128[AES_BLOCKBYTES*16];
	
	expand_key(rkeys, key);
	
	/* We assume the following are precomputed
	 * memset(H, 0, AES_BLOCKBYTES);
	 * encrypt_data(H, H, rkeys);
	 */
	
	/* Precomputation for table-based ghash */
	gcm_ghash_gen_tbl(H_128, H);

	/* Only supports at most a single block of plaintext and associated data */
	if (ptext_len > AES_BLOCKBYTES || adata_len > AES_BLOCKBYTES) {
		return -1;
	}

	if (iv_len == 12) {
		/* Prepare block J_0 = IV || 0^31 || 1 [len(IV) = 96] */
		memcpy(J0, iv, iv_len);
		memset(J0 + iv_len, 0, AES_BLOCKBYTES - iv_len);
		J0[AES_BLOCKBYTES - 1] = 0x01;
	} else {
		/*
		 * s = 128 * ceil(len(IV)/128) - len(IV)
		 * J_0 = GHASH_H(IV || 0^(s+64) || [len(IV)]_64)
		 */
		memset(J0, 0x00, sizeof(uint8_t)*AES_BLOCKBYTES);
		gcm_ghash_mult_tbl(H_128, iv, J0);
		AES_PUT_BE64(S, 0);
		AES_PUT_BE64(S + 8, iv_len * 8);
		gcm_ghash_mult_tbl(H_128, S, J0);
	}
	
	encrypt_data(ctext + ptext_len, J0, rkeys);

	/* C = GCTR_K(inc_32(J_0), P) */
	if (ptext_len != 0) {
		J0[AES_BLOCKBYTES - 1] += 1;
		encrypt_data(J0, J0, rkeys);
		for (size_t i = 0; i < ptext_len; i++)
			ctext[i] = ptext[i] ^ J0[i];
	}

	memset(S, 0x00, 16);
	
	gcm_ghash_mult_tbl(H_128, adata, S);
	gcm_ghash_mult_tbl(H_128, ctext, S);
	AES_PUT_BE64(J0, adata_len * 8);
	AES_PUT_BE64(J0 + 8, ptext_len * 8);
	gcm_ghash_mult_tbl(H_128, J0, S);

	xor_bytes(ctext + ptext_len, ctext + ptext_len, S, AES_BLOCKBYTES);

	return 0;
}
