#include <string.h>
#include <stdint.h>
#include "../aes/rijndaelfast.h"
#include "../ghash/ghash.h"
#include "gcmsiv_shortinput.h"
//#include "../utils.h"


static inline void rev_bytes(uint8_t arr[16]) {
	for(int i = 0; i < 8; i++) {
		arr[i]    ^= arr[15-i];
		arr[15-i] ^= arr[i];
		arr[i]    ^= arr[15-i];
	}
}

static inline void mulx_ghash(uint8_t out[16], uint8_t in[16]) {
	uint8_t tmp[AES_BLOCKBYTES];
	// to GHASH representation
	for(int i = 0; i < AES_BLOCKBYTES; i++) {
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
	for(int i = 1; i < AES_BLOCKBYTES; i++) {
		msb = tmp[i] & 0x80;
		tmp[i] = (tmp[i] << 1) | lsb;
		lsb = msb >> 7;
	}

	tmp[0] ^= (0x87 & (uint8_t)(0-lsb));

	// from GHASH representation
	for(int i = 0; i < AES_BLOCKBYTES; i++) {
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
	unsigned char tmp[AES_BLOCKBYTES] = {0x00};
	unsigned char s[AES_BLOCKBYTES] = {0x00};
	unsigned char tag[AES_BLOCKBYTES];
	unsigned char auth_key[AES_BLOCKBYTES];
	unsigned char enc_key[AES_BLOCKBYTES];
	unsigned char rkeys[AES_BLOCKBYTES*11];
	uint8_t H_128[AES_BLOCKBYTES*16];
	
	expand_key(rkeys, key);

	/* Only supports at most a single block of plaintext and associated data */
	if (ptext_len > AES_BLOCKBYTES || adata_len > AES_BLOCKBYTES) {
		return -1;
	}

	/* Compute auth and enc keys */
	memcpy(tmp+sizeof(uint32_t), iv, iv_len);
	encrypt_data(auth_key, tmp, rkeys);
	tmp[0]++;
	encrypt_data(enc_key, tmp, rkeys);
	memcpy(auth_key + AES_BLOCKBYTES/2, enc_key, AES_BLOCKBYTES/2);
	tmp[0]++;
	encrypt_data(enc_key, tmp, rkeys);
	tmp[0]++;
	encrypt_data(tmp, tmp, rkeys);
	memcpy(enc_key + AES_BLOCKBYTES/2, tmp, AES_BLOCKBYTES/2);

	expand_key(rkeys, enc_key);
	
	// POLYVAL
	rev_bytes(auth_key);
	gcm_ghash_gen_tbl(H_128, auth_key);
	mulx_ghash(auth_key, auth_key);
	if (adata_len > 0) {
		memset(tmp, 0x00, sizeof(tmp));
		memcpy(tmp, adata, adata_len);
		rev_bytes(tmp);
		gcm_ghash_mult_tbl(H_128, tmp, s);
	}
	if (ptext_len > 0) {
		memset(tmp, 0x00, sizeof(tmp));
		memcpy(tmp, ptext, ptext_len);
		rev_bytes(tmp);
		gcm_ghash_mult_tbl(H_128, tmp, s);
	}
	// reverseBytes(length_block)
	memset(tmp, 0x00, sizeof(tmp));
	tmp[15] = adata_len*8;
	tmp[07] = ptext_len*8;
	gcm_ghash_mult_tbl(H_128, tmp, s);
	rev_bytes(s);

	for(int i = 0; i < 12; i++) {
		s[i] ^= iv[i];
	}
	s[15] &= 0x7f;
	encrypt_data(tag, s, rkeys);
	memcpy(ctext + ptext_len, tag, AES_BLOCKBYTES);
	// counter_block <- tag[0]::tag[1]::...::(tag[15] | 0x80)
	tag[15] |= 0x80;

	encrypt_data(tmp, tag, rkeys);
	for(int i = 0; i < ptext_len; i++) {
		ctext[i] = ptext[i] ^ tmp[i];
	}

	return 0;
}
