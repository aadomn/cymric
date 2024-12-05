#include <string.h>
#include "config.h"
#include "utils.h"
#if defined(MASKING)
#include "aes.h"
#else
#include "aes_ffs.h"
#endif 		/* defined(MASKING) */

#if !defined(PARALLEL)

/* XEXX with 0^n for first XOR operand */
#define EXX(out, tmp, s, v, k)		({	\
	AES_ENC_BLOCK(tmp, s, k); 			\
	xor_bytes(out, tmp, s, BLOCKBYTES); \
	xor_bytes(out, out, v, BLOCKBYTES); \
})

int xocb_shortinput_encrypt(
	unsigned char* ctext,
	const unsigned char* key,
	const unsigned char* nonce, unsigned int nonce_len,
	const unsigned char* ptext, unsigned int ptext_len,
	const unsigned char* adata, unsigned int adata_len)
{
	unsigned char  tmp[BLOCKBYTES] = {0x00};
	unsigned char  l[BLOCKBYTES];
	unsigned char  delta[3*BLOCKBYTES];
	unsigned char* delta1 = delta;
	unsigned char* delta2 = delta + BLOCKBYTES;
	unsigned char* delta3 = delta + 2*BLOCKBYTES;
#if defined(MASKING)
	const unsigned char* rkeys = key;
	unsigned char rnd_key[RANDOMBYTES];
	unsigned char rnd_block[RANDOMBYTES];
	unsigned int mode = MODE_KEYINIT | MODE_AESINIT_ENC | MODE_ENC;
	STRUCT_AES aes_struct;
#else
	uint32_t rkeys[RKEYSWORDS];
	AES_KEY_EXPANSION(rkeys, key);
#endif		/* defined(MASKING) */

	if (ptext_len > BLOCKBYTES || adata_len > BLOCKBYTES) {
		return -1;
	}

	/* Delta1 = E_K(N || 0) ^ E_K(N || 1) */
	memcpy(tmp, nonce, nonce_len);
	AES_ENC_BLOCK(delta3, tmp, rkeys);
	tmp[nonce_len]++;
	AES_ENC_BLOCK(delta2, tmp, rkeys);
	xor_bytes(delta1, delta3, delta2, BLOCKBYTES);

	/* Delta2 = E_K(N || 0) ^ E_K(N || 2) */
	tmp[nonce_len]++;
	AES_ENC_BLOCK(delta2, tmp, rkeys);
	xor_bytes(delta2, delta3, delta2, BLOCKBYTES);

	/* Delta3 = E_K(N || 0) ^ E_K(N || 3) */
	tmp[nonce_len]++;
	AES_ENC_BLOCK(tmp, tmp, rkeys);
	xor_bytes(delta3, delta3, tmp, BLOCKBYTES);

  	/* L = XEXX(0, Delta1 ^ Delta2, 0) */
 	xor_bytes(tmp, delta1, delta2, BLOCKBYTES);
 	AES_ENC_BLOCK(l, tmp, rkeys);
  	xor_bytes(l, l, tmp, BLOCKBYTES);
 	double_arr(delta1, delta1);

	/* C = XEXX(0, delta1, l) ^ M */
	EXX(tmp, tmp, delta1, l, rkeys);
	xor_bytes(ctext, tmp, ptext, ptext_len);
	ctext += ptext_len;

	/* Delta1* = Delta1 ^ Delta3 */
	memcpy(tmp, delta1, BLOCKBYTES);
	xor_bytes(delta1, delta1, delta3, BLOCKBYTES);

	/* Delta2* = Delta1 ^ 2*Delta3 */
	double_arr(delta3, delta3);
	xor_bytes(delta3, delta3, tmp, BLOCKBYTES);

	/* Sigma = ozp(M) ^ delta2* */
	memcpy(ctext, ptext, ptext_len);
	ctext[ptext_len] = 0x80;
	xor_bytes(ctext, ctext, delta3, BLOCKBYTES);

	/* T = XEXX(0, Delta1*, l) ^ XEXX(Sigma, Delta2*, l) */
	EXX(delta1, tmp, delta1, l, rkeys);
	EXX(ctext, tmp, ctext, l, rkeys);
	xor_bytes(ctext, ctext, delta1, BLOCKBYTES);

	/* PHASH(A, Delta2) */
	double_arr(delta2, delta2);
	memset(tmp, 0x00, BLOCKBYTES);
	memcpy(tmp, adata, adata_len);
	tmp[adata_len] = 0x80;
	AES_ENC_BLOCK(tmp, tmp, rkeys);

	/* T = T ^ PHASH(A, Delta2) */
	xor_bytes(ctext, ctext, tmp, BLOCKBYTES);

	return 0;
}

#else /* Fixsliced representation processing 2 blocks in parallel */

/* XEXX with 0^n for first XOR operand, on 2 blocks */
#define EXX(out0, out1, s0, s1, v0, v1, k)		({	\
	AES_ENC_BLOCKS(out0, out1, s0, s1, k); 			\
	xor_bytes(out0, out0, s0, BLOCKBYTES); \
	xor_bytes(out0, out0, v0, BLOCKBYTES); \
	xor_bytes(out1, out1, s1, BLOCKBYTES); \
	xor_bytes(out1, out1, v1, BLOCKBYTES); \
})

int xocb_shortinput_encrypt(
	unsigned char* ctext,
	const unsigned char* key,
	const unsigned char* nonce, unsigned int nonce_len,
	const unsigned char* ptext, unsigned int ptext_len,
	const unsigned char* adata, unsigned int adata_len)
{

	unsigned char  	tmp[BLOCKBYTES] = {0x00};
	unsigned char  	l[BLOCKBYTES];
	unsigned char  	delta[3*BLOCKBYTES];
	unsigned char* 	delta1 = delta + 0*BLOCKBYTES;
	unsigned char* 	delta2 = delta + 1*BLOCKBYTES;
	unsigned char* 	delta3 = delta + 2*BLOCKBYTES;
	uint32_t   		rkeys[RKEYSWORDS];
	AES_KEY_EXPANSION(rkeys, key);

	if (ptext_len > BLOCKBYTES || adata_len > BLOCKBYTES) {
		return -1;
	}

	/* Delta1 = E_K(N || 0) ^ E_K(N || 1) */
	memcpy(tmp, nonce, nonce_len);
	memcpy(l,   nonce, nonce_len);
	l[nonce_len]++;
	AES_ENC_BLOCKS(delta3, delta2, tmp, l, rkeys);
	xor_bytes(delta1, delta3, delta2, BLOCKBYTES);

	/* Delta2 = E_K(N || 0) ^ E_K(N || 2) */
	tmp[nonce_len] += 2;
	l[nonce_len] += 2;
	AES_ENC_BLOCKS(delta2, tmp, tmp, l, rkeys);
	xor_bytes(delta2, delta2, delta3, BLOCKBYTES);
	xor_bytes(delta3, delta3, tmp, BLOCKBYTES);

  	/* L = XEXX(0, Delta1 ^ Delta2, 0) */
 	xor_bytes(tmp, delta1, delta2, BLOCKBYTES);
 	double_arr(delta1, delta1);
 	AES_ENC_BLOCKS(l, ctext, tmp, delta1, rkeys);
  	xor_bytes(l, l, tmp, BLOCKBYTES);
  	xor_bytes(ctext, ctext, delta1, ptext_len);
  	xor_bytes(ctext, ctext, l, ptext_len);
	xor_bytes(ctext, ctext, ptext, ptext_len);
	ctext += ptext_len;

	/* Delta1* = Delta1 ^ Delta3 */
	memcpy(tmp, delta1, BLOCKBYTES);
	xor_bytes(delta1, delta1, delta3, BLOCKBYTES);

	/* Delta2* = Delta1 ^ 2*Delta3 */
	double_arr(delta3, delta3);
	xor_bytes(delta3, delta3, tmp, BLOCKBYTES);

	/* Sigma = ozp(M) ^ delta2* */
	memcpy(ctext, ptext, ptext_len);
	ctext[ptext_len] = 0x80;
	xor_bytes(ctext, ctext, delta3, BLOCKBYTES);

	/* T = XEXX(0, Delta1*, l) ^ XEXX(Sigma, Delta2*, l) */
	EXX(delta3, tmp, delta1, ctext, l, l, rkeys);
	xor_bytes(ctext, tmp, delta3, BLOCKBYTES);

	/* PHASH(A, Delta2) */
	double_arr(delta2, delta2);
	memset(tmp, 0x00, BLOCKBYTES);
	memcpy(tmp, adata, adata_len);
	tmp[adata_len] = 0x80;
	AES_ENC_BLOCKS(tmp, tmp, tmp, tmp, rkeys);

	/* T = T ^ PHASH(A, Delta2) */
	xor_bytes(ctext, ctext, tmp, BLOCKBYTES);
}

#endif /* !defined(PARALLEL) */
