#include <string.h>
#include "../utils.h"
#include "../../aes/aes.h"

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
	aes128_keyschedule_sfs_lut(rkeys, key);

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
		aes128_encrypt_sfs(ctext + ptext_len, offset, tmp, offset, rkeys);
	} else if (adata_len > 0) {
		memcpy(tmp, l_asterisk, BLOCKBYTES);
		xor_bytes(tmp, tmp, adata, adata_len);
		tmp[adata_len] ^= 0x80;	/* 10 padding */
		aes128_encrypt_sfs(ctext + ptext_len, offset, tmp, offset, rkeys);
	} else {
		aes128_encrypt_sfs(offset, offset, offset, offset, rkeys);
		memset(ctext + ptext_len, 0x00, BLOCKBYTES);
	}
	xor_bytes(offset+BLOCKBYTES, offset, offset+1, BLOCKBYTES/2);
	bitshift_bytes(offset, offset, bottom);

	/* Plaintext encryption and tag init are interleaved to leverage parallel AES */
	if (ptext_len == BLOCKBYTES) {
		xor_bytes(offset, offset,  l_zero, BLOCKBYTES);
		xor_bytes(tmp,    offset,  ptext,  BLOCKBYTES);
		xor_bytes(l_dollar, l_dollar, tmp,    BLOCKBYTES);
		aes128_encrypt_sfs(ctext, l_dollar, tmp, l_dollar, rkeys);
		xor_bytes(ctext,    ctext,    offset, BLOCKBYTES);
	} else if (ptext_len > 0) {
		xor_bytes(offset, offset, l_asterisk, BLOCKBYTES);
		xor_bytes(l_dollar, l_dollar, offset, BLOCKBYTES);
		xor_bytes(l_dollar, l_dollar, ptext,  ptext_len);
		l_dollar[ptext_len] ^= 0x80;	/* 10 padding */
		aes128_encrypt_sfs(ctext, l_dollar, offset, l_dollar, rkeys);
		xor_bytes(ctext,  ctext,  ptext, ptext_len);
	} else {
		xor_bytes(l_dollar, l_dollar, offset, BLOCKBYTES);
		aes128_encrypt_sfs(l_dollar, l_dollar, l_dollar, l_dollar, rkeys);
	}

	ctext += ptext_len;
	xor_bytes(ctext, ctext, l_dollar, BLOCKBYTES);

	return 0;
}
