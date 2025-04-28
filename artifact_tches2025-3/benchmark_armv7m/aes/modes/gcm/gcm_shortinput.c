#include <string.h>
#include <stdint.h>
#include "../utils.h"
#include "../ghash.h"
#include "../../aes/aes.h"

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
	uint8_t J0[2*BLOCKBYTES];
	uint8_t S[BLOCKBYTES];
	uint32_t rkeys[RKEYSWORDS];
	const unsigned char* H = key + KEYBYTES;
	aes128_keyschedule_sfs_lut(rkeys, key);

	/* Only supports at most a single block of plaintext and associated data */
	if (ptext_len > BLOCKBYTES || adata_len > BLOCKBYTES) {
		return -1;
	}

	if (iv_len == 12) {
		/* Prepare block J_0 = IV || 0^31 || 1 [len(IV) = 96] */
		memcpy(J0, iv, iv_len);
		memset(J0 + iv_len, 0, BLOCKBYTES - iv_len);
		J0[BLOCKBYTES - 1] = 0x01;
	} else {
		/*
		 * s = 128 * ceil(len(IV)/128) - len(IV)
		 * J_0 = GHASH_H(IV || 0^(s+64) || [len(IV)]_64)
		 */
		memset(J0, 0x00, sizeof(uint8_t)*BLOCKBYTES);
		br_ghash_ctmul(J0, H, iv, iv_len);
		AES_PUT_BE64(S, 0);
		AES_PUT_BE64(S + 8, iv_len * 8);
		br_ghash_ctmul(J0, H, S, BLOCKBYTES);
	}

	/**
	 * memset(H, 0, BLOCKBYTES);
	 * aes128_encrypt_sfs(H, H, H, H, rkeys);
	 * The null block encryption is skipped because it assumes l_asterisk
	 * is pre-computed and provided along with the key
	 */

	memcpy(J0 + BLOCKBYTES, J0, BLOCKBYTES);
	J0[2*BLOCKBYTES - 1] += 1;
	aes128_encrypt_sfs(ctext + ptext_len, J0, J0, J0 + BLOCKBYTES, rkeys);

	/* C = GCTR_K(inc_32(J_0), P) */
	for (size_t i = 0; i < ptext_len; i++)
		ctext[i] = ptext[i] ^ J0[i];

	memset(S, 0x00, 16);
	br_ghash_ctmul(S, H, adata, adata_len);
	br_ghash_ctmul(S, H, ctext, ptext_len);
	AES_PUT_BE64(J0, adata_len * 8);
	AES_PUT_BE64(J0 + 8, ptext_len * 8);
	br_ghash_ctmul(S, H, J0, sizeof(J0));

	xor_bytes(ctext + ptext_len, ctext + ptext_len, S, BLOCKBYTES);

	return 0;
}
