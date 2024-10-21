#if defined(MASKING)
#include "aes.h"
#else
#include "aes_ffs.h"
#endif 		/* defined(MASKING) */
#include "string.h"
#include "config.h"
#include "utils.h"

#define BLOCKBYTES 16
#define KEYBYTES   16
#define RKEYSWORDS 16*11 

/* Doubling in GF(2^128) defined by x^128 + x^7 + x^2 + x + 1 */
static inline void double_arr(
	unsigned char       out[BLOCKBYTES],
	const unsigned char in[BLOCKBYTES])
{
	unsigned char first_bit = -(in[0] >> 7);
	for (unsigned int i = 0; i < BLOCKBYTES - 1; i++) {
		out[i]  = in[i]     << 1;
		out[i] |= in[i + 1] >> 7;
	}
	out[BLOCKBYTES - 1]   = in[BLOCKBYTES - 1] << 1;
	out[BLOCKBYTES - 1]  ^= first_bit & 135;
}

/* Bitshift on a byte array */
static inline void bitshift_bytes(
	unsigned char       out[BLOCKBYTES],
	const unsigned char in[3*BLOCKBYTES/2],
	unsigned char       bits)
{
	unsigned char offset = bits >> 3;
	unsigned char lshift = bits & 0x7;
	unsigned char rshift = 8 - bits;

	for (unsigned int i = 0; i < BLOCKBYTES; i++) {
		out[i] =
		(in[i + offset]     << lshift) |
		(in[i + offset + 1] >> rshift);
	}
}

/* Nonce initialization */
static inline void init_nonce(
	unsigned char out[BLOCKBYTES],
	const unsigned char* nonce, unsigned int nonce_len)
{
	unsigned char index = BLOCKBYTES - 1 - nonce_len;
	memset(out, 0x00, index);
	out[index++] = 1;
	for (unsigned int i = 0; i < nonce_len; i++)
		out[index++] = nonce[i];
}

#if !defined(PARALLEL)
int ocb_shortinput_encrypt(
	unsigned char*       ctext,
	const unsigned char* key,
	const unsigned char* nonce, unsigned int nonce_len,
	const unsigned char* ptext, unsigned int ptext_len,
	const unsigned char* adata, unsigned int adata_len)
{
	/* Mask values */
	unsigned char  l[2*BLOCKBYTES];
	const unsigned char* l_asterisk = key + KEYBYTES;
	unsigned char* l_dollar         = (unsigned char*)l + 0;
	unsigned char* l_zero           = (unsigned char*)l + BLOCKBYTES;
	/* Offset uses 32 bytes instead of 24 for the 2nd block to be used as tmp */
	unsigned char  offset[2*BLOCKBYTES];
	unsigned char* tmp = (unsigned char*)offset + BLOCKBYTES;
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

	/*
	 * memset(offset, 0x00, BLOCKBYTES);
	 * AES_ENC_BLOCK(l_asterisk, offset, rkeys);
	 * The null block encryption is skipped because it assumes l_asterisk
	 * is pre-computed and provided along with the key
	 */

	/* Nonce-dependent and per-encryption variables */
	double_arr(l_dollar, l_asterisk);
	double_arr(l_zero, l_dollar);

	/* Initialization */
	init_nonce(offset, nonce, nonce_len);
	unsigned char bottom = offset[15] & 0x1f;
	offset[BLOCKBYTES-1] ^= bottom;
	AES_ENC_BLOCK(offset, offset, rkeys);
	xor_bytes(offset+BLOCKBYTES, offset, offset+1, BLOCKBYTES/2);
	bitshift_bytes(offset, offset, bottom);

	/* Plaintext encryption */
	if (ptext_len == BLOCKBYTES) {
		xor_bytes(offset, offset,  l_zero, BLOCKBYTES);
		xor_bytes(tmp,    offset,  ptext,  BLOCKBYTES);
		AES_ENC_BLOCK(ctext, tmp, rkeys);
		xor_bytes(ctext,    ctext,    offset, BLOCKBYTES);
		xor_bytes(l_dollar, l_dollar, tmp,    BLOCKBYTES);

	} else if (ptext_len > 0) {
		xor_bytes(offset, offset, l_asterisk, BLOCKBYTES);
		AES_ENC_BLOCK(ctext, offset, rkeys);
		xor_bytes(ctext,  ctext,  ptext, ptext_len);
		xor_bytes(offset, offset, ptext, ptext_len);
		offset[ptext_len] ^= 0x80;	/* 10 padding */
		xor_bytes(l_dollar, l_dollar, offset, BLOCKBYTES);
	} else {
		xor_bytes(l_dollar, l_dollar, offset, BLOCKBYTES);
	}

	/* Initiate tag calculation */
	ctext += ptext_len;
	AES_ENC_BLOCK(ctext, l_dollar, rkeys);

	/* HASH(K,A) */
	if (adata_len == BLOCKBYTES) {
		xor_bytes(tmp, l_zero, adata, adata_len);
		AES_ENC_BLOCK(tmp, tmp, rkeys);
		xor_bytes(ctext, ctext, tmp, BLOCKBYTES);
	} else if (adata_len > 0) {
		memcpy(tmp, l_asterisk, BLOCKBYTES);
		xor_bytes(tmp, tmp, adata, adata_len);
		tmp[adata_len] ^= 0x80;	/* 10 padding */
		AES_ENC_BLOCK(tmp, tmp, rkeys);
		xor_bytes(ctext, ctext, tmp, BLOCKBYTES);
	}

	return 0;
}

#else /* Fixsliced representation processing 2 blocks in parallel */

int ocb_shortinput_encrypt(
	unsigned char*       ctext,
	const unsigned char* key,
	const unsigned char* nonce, unsigned int nonce_len,
	const unsigned char* ptext, unsigned int ptext_len,
	const unsigned char* adata, unsigned int adata_len)
{
	/* Mask values */
	unsigned char  l[2*BLOCKBYTES];
	const unsigned char* l_asterisk = key + KEYBYTES;
	unsigned char* l_dollar         = (unsigned char*)l + 0;
	unsigned char* l_zero           = (unsigned char*)l + BLOCKBYTES;
	/* Offset uses 32 bytes instead of 24 for the 2nd block to be used as tmp */
	unsigned char  offset[2*BLOCKBYTES];
	unsigned char* tmp = (unsigned char*)offset + BLOCKBYTES;
	uint32_t rkeys[RKEYSWORDS];
	AES_KEY_EXPANSION(rkeys, key);

	if (ptext_len > BLOCKBYTES || adata_len > BLOCKBYTES) {
		return -1;
	}

	/*
	 * memset(offset, 0x00, BLOCKBYTES);
	 * AES_ENC_BLOCK(l_asterisk, offset, rkeys);
	 * The null block encryption is skipped because it assumes l_asterisk
	 * is pre-computed and provided along with the key
	 */

	/* Nonce-dependent and per-encryption variables */
	double_arr(l_dollar, l_asterisk);
	double_arr(l_zero, l_dollar);

	/* Initialization and HASH(K,A) are interleaved to leverage parallel AES */
	init_nonce(offset, nonce, nonce_len);
	unsigned char bottom = offset[15] & 0x1f;
	offset[BLOCKBYTES-1] ^= bottom;
	/* HASH(K,A) */
	if (adata_len == BLOCKBYTES) {
		xor_bytes(tmp, l_zero, adata, adata_len);
		AES_ENC_BLOCKS(ctext + ptext_len, offset, tmp, offset, rkeys);
	} else if (adata_len > 0) {
		memcpy(tmp, l_asterisk, BLOCKBYTES);
		xor_bytes(tmp, tmp, adata, adata_len);
		tmp[adata_len] ^= 0x80;	/* 10 padding */
		AES_ENC_BLOCKS(ctext + ptext_len, offset, tmp, offset, rkeys);
	} else {
		AES_ENC_BLOCKS(offset, offset, offset, offset, rkeys);
		memset(ctext + ptext_len, 0x00, BLOCKBYTES);
	}
	xor_bytes(offset+BLOCKBYTES, offset, offset+1, BLOCKBYTES/2);
	bitshift_bytes(offset, offset, bottom);

	/* Plaintext encryption and tag init are interleaved to leverage parallel AES */
	if (ptext_len == BLOCKBYTES) {
		xor_bytes(offset, offset,  l_zero, BLOCKBYTES);
		xor_bytes(tmp,    offset,  ptext,  BLOCKBYTES);
		xor_bytes(l_dollar, l_dollar, tmp,    BLOCKBYTES);
		AES_ENC_BLOCKS(ctext, l_dollar, tmp, l_dollar, rkeys);
		xor_bytes(ctext,    ctext,    offset, BLOCKBYTES);
	} else if (ptext_len > 0) {
		xor_bytes(offset, offset, l_asterisk, BLOCKBYTES);
		xor_bytes(l_dollar, l_dollar, offset, BLOCKBYTES);
		xor_bytes(l_dollar, l_dollar, ptext,  ptext_len);
		l_dollar[ptext_len] ^= 0x80;	/* 10 padding */
		AES_ENC_BLOCKS(ctext, l_dollar, offset, l_dollar, rkeys);
		xor_bytes(ctext,  ctext,  ptext, ptext_len);
	} else {
		xor_bytes(l_dollar, l_dollar, offset, BLOCKBYTES);
		AES_ENC_BLOCKS(l_dollar, l_dollar, l_dollar, l_dollar, rkeys);
	}

	ctext += ptext_len;
	xor_bytes(ctext, ctext, l_dollar, BLOCKBYTES);

	return 0;
}

#endif /* !defined(PARALLEL) */
