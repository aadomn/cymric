#include <string.h>
#include "../aes/rijndaelfast.h"
#include "xocb_shortinput.h"
#include "../utils.h"

/* Doubling in GF(2^128) defined by x^128 + x^7 + x^2 + x + 1 */
static inline void double_arr(unsigned char out[16], const unsigned char in[16]) {
	unsigned char first_bit = -(in[0] >> 7);
	for (unsigned int i = 0; i < 15; i++) {
		out[i]  = in[i]     << 1;
		out[i] |= in[i + 1] >> 7;
	}
	out[15]   = in[15] << 1;
	out[15]  ^= first_bit & 135;
}

/* XEXX with 0^n for first XOR operand */
#define EXX(out, tmp, s, v, k)		({	\
	encrypt_data(tmp, s, k); 			\
	xor_bytes(out, tmp, s, AES_BLOCKBYTES); \
	xor_bytes(out, out, v, AES_BLOCKBYTES); \
})

int xocb_shortinput_encrypt(
	unsigned char* ctext,
	const unsigned char* key,
	const unsigned char* nonce, unsigned int nonce_len,
	const unsigned char* ptext, unsigned int ptext_len,
	const unsigned char* adata, unsigned int adata_len)
{
	unsigned char  tmp[AES_BLOCKBYTES] = {0x00};
	unsigned char  l[AES_BLOCKBYTES];
	unsigned char  delta[3*AES_BLOCKBYTES];
	unsigned char* delta1 = delta;
	unsigned char* delta2 = delta + AES_BLOCKBYTES;
	unsigned char* delta3 = delta + 2*AES_BLOCKBYTES;
	unsigned char rkeys[AES_BLOCKBYTES*11];
	expand_key(rkeys, key);

	if (ptext_len > AES_BLOCKBYTES || adata_len > AES_BLOCKBYTES) {
		return -1;
	}

	/* Delta1 = E_K(N || 0) ^ E_K(N || 1) */
	memcpy(tmp, nonce, nonce_len);
	encrypt_data(delta3, tmp, rkeys);
	tmp[nonce_len]++;
	encrypt_data(delta2, tmp, rkeys);
	xor_bytes(delta1, delta3, delta2, AES_BLOCKBYTES);

	/* Delta2 = E_K(N || 0) ^ E_K(N || 2) */
	tmp[nonce_len]++;
	encrypt_data(delta2, tmp, rkeys);
	xor_bytes(delta2, delta3, delta2, AES_BLOCKBYTES);

	/* Delta3 = E_K(N || 0) ^ E_K(N || 3) */
	tmp[nonce_len]++;
	encrypt_data(tmp, tmp, rkeys);
	xor_bytes(delta3, delta3, tmp, AES_BLOCKBYTES);

  	/* L = XEXX(0, Delta1 ^ Delta2, 0) */
 	xor_bytes(tmp, delta1, delta2, AES_BLOCKBYTES);
 	encrypt_data(l, tmp, rkeys);
  	xor_bytes(l, l, tmp, AES_BLOCKBYTES);
 	double_arr(delta1, delta1);

	/* C = XEXX(0, delta1, l) ^ M */
	EXX(tmp, tmp, delta1, l, rkeys);
	xor_bytes(ctext, tmp, ptext, ptext_len);
	ctext += ptext_len;

	/* Delta1* = Delta1 ^ Delta3 */
	memcpy(tmp, delta1, AES_BLOCKBYTES);
	xor_bytes(delta1, delta1, delta3, AES_BLOCKBYTES);

	/* Delta2* = Delta1 ^ 2*Delta3 */
	double_arr(delta3, delta3);
	xor_bytes(delta3, delta3, tmp, AES_BLOCKBYTES);

	/* Sigma = ozp(M) ^ delta2* */
	memcpy(ctext, ptext, ptext_len);
	ctext[ptext_len] = 0x80;
	xor_bytes(ctext, ctext, delta3, AES_BLOCKBYTES);

	/* T = XEXX(0, Delta1*, l) ^ XEXX(Sigma, Delta2*, l) */
	EXX(delta1, tmp, delta1, l, rkeys);
	EXX(ctext, tmp, ctext, l, rkeys);
	xor_bytes(ctext, ctext, delta1, AES_BLOCKBYTES);

	/* PHASH(A, Delta2) */
	double_arr(delta2, delta2);
	memset(tmp, 0x00, AES_BLOCKBYTES);
	memcpy(tmp, adata, adata_len);
	tmp[adata_len] = 0x80;
	encrypt_data(tmp, tmp, rkeys);

	/* T = T ^ PHASH(A, Delta2) */
	xor_bytes(ctext, ctext, tmp, AES_BLOCKBYTES);

	return 0;
}
