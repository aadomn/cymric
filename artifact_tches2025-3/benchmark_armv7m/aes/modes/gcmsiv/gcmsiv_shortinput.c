#include <string.h>
#include <stdint.h>
#include "../utils.h"
#include "../ghash.h"
#include "../../aes/aes.h"
#include "gcmsiv_shortinput.h"

static inline void rev_bytes(uint8_t arr[16]) {
	for(int i = 0; i < 8; i++) {
		arr[i]    ^= arr[15-i];
		arr[15-i] ^= arr[i];
		arr[i]    ^= arr[15-i];
	}
}

static inline void mulx_ghash(uint8_t out[16], uint8_t in[16]) {
	uint8_t tmp[BLOCKBYTES];
	// to GHASH representation
	for(int i = 0; i < BLOCKBYTES; i++) {
		tmp[i] = 0;
		for(int b = 0; b < 8; b++) {
			tmp[i] <<= 1;
			tmp[i] |= ((in[i] >> b) & 1);
		}
	}

	// multiplication by x
	uint8_t lsb;
	uint8_t msb = tmp[0] & 0x80;
	lsb = msb >> 7;
	tmp[0] <<= 1;
	for(int i = 1; i < BLOCKBYTES; i++) {
		msb = tmp[i] & 0x80;
		tmp[i] = (tmp[i] << 1) | lsb;
		lsb = msb >> 7;
	}

	tmp[0] ^= (0x87 & (uint8_t)(0-lsb));

	// from GHASH representation
	for(int i = 0; i < BLOCKBYTES; i++) {
		out[i] = 0;
		for(int b = 0; b < 8; b++) {
			out[i] >>= 1;
			out[i] |= ((tmp[i] & (1 << (7-b))) << b);
		}
	}
}

int gcmsiv_shortinput_encrypt(
	unsigned char*       ctext,
	const unsigned char* key,
	const unsigned char* iv,    unsigned int iv_len,
	const unsigned char* ptext, unsigned int ptext_len,
	const unsigned char* adata, unsigned int adata_len)
{
	unsigned char tmp[2*BLOCKBYTES] = {0x00};
	unsigned char s[BLOCKBYTES] = {0x00};
	unsigned char tag[BLOCKBYTES];
	unsigned char auth_key[KEYBYTES];
	unsigned char enc_key[KEYBYTES];
	uint32_t rkeys[RKEYSWORDS];
	aes128_keyschedule_sfs_lut(rkeys, key);

	/* Only supports at most a single block of plaintext and associated data */
	if (ptext_len > BLOCKBYTES || adata_len > BLOCKBYTES) {
		return -1;
	}

	/* Compute auth and enc keys */
	memcpy(tmp+sizeof(uint32_t), iv, iv_len);
	memcpy(tmp+BLOCKBYTES+sizeof(uint32_t), iv, iv_len);
	tmp[BLOCKBYTES]++;
	aes128_encrypt_sfs(auth_key, enc_key, tmp, tmp + BLOCKBYTES, rkeys);
	memcpy(auth_key + BLOCKBYTES/2, enc_key, BLOCKBYTES/2);
	tmp[0] += 2;
	tmp[BLOCKBYTES] += 2;
	aes128_encrypt_sfs(enc_key, tmp, tmp, tmp + BLOCKBYTES, rkeys);
	memcpy(enc_key + BLOCKBYTES/2, tmp, BLOCKBYTES/2);

	aes128_keyschedule_sfs_lut(rkeys, enc_key);

	// POLYVAL
	rev_bytes(auth_key);
	mulx_ghash(auth_key, auth_key);
	if (adata_len > 0) {
		memset(tmp, 0x00, sizeof(tmp));
		memcpy(tmp, adata, adata_len);
		rev_bytes(tmp);
		br_ghash_ctmul(s, auth_key, tmp, BLOCKBYTES);
	}
	if (ptext_len > 0) {
		memset(tmp, 0x00, sizeof(tmp));
		memcpy(tmp, ptext, ptext_len);
		rev_bytes(tmp);
		br_ghash_ctmul(s, auth_key, tmp, BLOCKBYTES);
	}
	// reverseBytes(length_block)
	memset(tmp, 0x00, sizeof(tmp));
	tmp[15] = adata_len*8;
	tmp[07] = ptext_len*8;
	br_ghash_ctmul(s, auth_key, tmp, BLOCKBYTES);
	rev_bytes(s);

	for(int i = 0; i < 12; i++) {
		s[i] ^= iv[i];
	}
	s[15] &= 0x7f;
	aes128_encrypt_sfs(tag, tag, s, s, rkeys);
	memcpy(ctext + ptext_len, tag, BLOCKBYTES);
	// counter_block <- tag[0]::tag[1]::...::(tag[15] | 0x80)
	tag[15] |= 0x80;

	aes128_encrypt_sfs(tmp, tmp, tag, tag, rkeys);
	for(int i = 0; i < ptext_len; i++) {
		ctext[i] = ptext[i] ^ tmp[i];
	}

	return 0;
}
