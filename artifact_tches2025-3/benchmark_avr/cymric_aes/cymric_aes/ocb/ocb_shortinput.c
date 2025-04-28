#include <string.h>
#include "../aes/rijndaelfast.h"
#include "ocb_shortinput.h"
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

/* Bitshift on a byte array */
static inline void bitshift_bytes(
	unsigned char       out[AES_BLOCKBYTES],
	const unsigned char in[3*AES_BLOCKBYTES/2],
	unsigned char       bits)
{
	unsigned char offset = bits >> 3;
	unsigned char lshift = bits & 0x7;
	unsigned char rshift = 8 - bits;

	for (unsigned int i = 0; i < AES_BLOCKBYTES; i++) {
		out[i] =
		(in[i + offset]     << lshift) |
		(in[i + offset + 1] >> rshift);
	}
}

/* Nonce initialization */
static inline void init_nonce(
	unsigned char out[AES_BLOCKBYTES],
	const unsigned char* nonce, unsigned int nonce_len)
{
	unsigned char index = AES_BLOCKBYTES - 1 - nonce_len;
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
	unsigned char  l[2*AES_BLOCKBYTES];
	const unsigned char* l_asterisk = key + AES_BLOCKBYTES;
	unsigned char* l_dollar         = (unsigned char*)l + 0;
	unsigned char* l_zero           = (unsigned char*)l + AES_BLOCKBYTES;
	/* Offset uses 32 bytes instead of 24 for the 2nd block to be used as tmp */
	unsigned char  offset[2*AES_BLOCKBYTES];
	unsigned char* tmp = (unsigned char*)offset + AES_BLOCKBYTES;
	unsigned char rkeys[AES_BLOCKBYTES*11];
	expand_key(rkeys, key);

	if (ptext_len > AES_BLOCKBYTES || adata_len > AES_BLOCKBYTES) {
		return -1;
	}

	/*
	 * memset(offset, 0x00, AES_BLOCKBYTES);
	 * encrypt_data(l_asterisk, offset, rkeys);
	 * The null block encryption is skipped because it assumes l_asterisk
	 * is pre-computed and provided along with the key
	 */

	/* Nonce-dependent and per-encryption variables */
	double_arr(l_dollar, l_asterisk);
	double_arr(l_zero, l_dollar);

	/* Initialization */
	init_nonce(offset, nonce, nonce_len);
	unsigned char bottom = offset[15] & 0x1f;
	offset[AES_BLOCKBYTES-1] ^= bottom;
	encrypt_data(offset, offset, rkeys);
	xor_bytes(offset+AES_BLOCKBYTES, offset, offset+1, AES_BLOCKBYTES/2);
	bitshift_bytes(offset, offset, bottom);

	/* Plaintext encryption */
	if (ptext_len == AES_BLOCKBYTES) {
		xor_bytes(offset, offset,  l_zero, AES_BLOCKBYTES);
		xor_bytes(tmp,    offset,  ptext,  AES_BLOCKBYTES);
		encrypt_data(ctext, tmp, rkeys);
		xor_bytes(ctext,    ctext,    offset, AES_BLOCKBYTES);
		xor_bytes(l_dollar, l_dollar, tmp,    AES_BLOCKBYTES);

	} else if (ptext_len > 0) {
		xor_bytes(offset, offset, l_asterisk, AES_BLOCKBYTES);
		encrypt_data(ctext, offset, rkeys);
		xor_bytes(ctext,  ctext,  ptext, ptext_len);
		xor_bytes(offset, offset, ptext, ptext_len);
		offset[ptext_len] ^= 0x80;	/* 10 padding */
		xor_bytes(l_dollar, l_dollar, offset, AES_BLOCKBYTES);
	} else {
		xor_bytes(l_dollar, l_dollar, offset, AES_BLOCKBYTES);
	}

	/* Initiate tag calculation */
	ctext += ptext_len;
	encrypt_data(ctext, l_dollar, rkeys);

	/* HASH(K,A) */
	if (adata_len == AES_BLOCKBYTES) {
		xor_bytes(tmp, l_zero, adata, adata_len);
		encrypt_data(tmp, tmp, rkeys);
		xor_bytes(ctext, ctext, tmp, AES_BLOCKBYTES);
	} else if (adata_len > 0) {
		memcpy(tmp, l_asterisk, AES_BLOCKBYTES);
		xor_bytes(tmp, tmp, adata, adata_len);
		tmp[adata_len] ^= 0x80;	/* 10 padding */
		encrypt_data(tmp, tmp, rkeys);
		xor_bytes(ctext, ctext, tmp, AES_BLOCKBYTES);
	}

	return 0;
}
