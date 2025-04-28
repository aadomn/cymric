#include "ghash.h"
#include <string.h>

/*
 * Shoup's method for multiplication use this table with
 *      last4[x] = x times P^128
 * where x and last4[x] are seen as elements of GF(2^128) as in [MGV]
 */
static const uint16_t last4_gf128[16] = {
	0x0000, 0x1c20, 0x3840, 0x2460,
	0x7080, 0x6ca0, 0x48c0, 0x54e0,
	0xe100, 0xfd20, 0xd940, 0xc560,
	0x9180, 0x8da0, 0xa9c0, 0xb5e0
};

static inline void rshift(uint8_t out[], const uint8_t in[], size_t inlen, size_t b)
{
	uint8_t tmp;
	uint8_t mask = (1 << b) - 1;
	int     i = 0;

	out[0] = 0x00;

	// while we can manipulate plain bytes
	while (inlen >= 8) {
		tmp      = in[i];
		out[i]  |= tmp >> b;
		out[++i] = (tmp & mask) << (8-b);
		inlen   -= 8;
	}
	// if the input is not byte aligned, ignore the least significant bits
	if (inlen) {
		tmp     = in[i] & (0xff << (8-inlen));
		out[i] |= tmp >> b;
		if (inlen > 8-b)
		out[++i] = tmp << (8-b);
	}
}

void gcm_ghash_gen_tbl(uint8_t H_128[16*16], const uint8_t* k){
	int i, j;
	uint8_t tmp[16];
	uint8_t shift[16];
	uint8_t bit;

	memcpy(tmp, k, 16);
	memcpy(H_128 + 16*8, k, 16);
	memset(H_128, 0x00, 16);

	for (i = 4; i > 0; i >>= 1) {
		bit = tmp[15] & 1;
		uint8_t T = bit * 0xe1;
		rshift(shift, tmp, 128, 1);
		shift[0] ^= T;
		memcpy(tmp, shift, 16);
		memcpy(H_128 + 16*i, tmp, 16);
	}

	for (i = 2; i <= 8; i *= 2) {
		memcpy(tmp, H_128 + 16*i, 16);
		for (j = 1; j < i; j++) {
			for(int k = 0; k < 16; k++)
			H_128[16*(i+j)+k] = tmp[k] ^ H_128[16*j+k];
		}
	}
}

void gcm_ghash_mult_tbl(const uint8_t H_128[16*16], const unsigned char x[16],	unsigned char out[16])
{
	int i = 0;
	unsigned char lo, hi, rem;
	uint8_t tmp[16];

	lo = x[15] & 0xf;

	memcpy(out, H_128+16*lo, 16);

	for (i = 15; i >= 0; i--) {
		lo = x[i] & 0xf;
		hi = x[i] >> 4;

		if (i != 15) {
			rem = out[15] & 0xf;
			rshift(tmp, out, 128, 4);
			(tmp)[0] ^= last4_gf128[rem] >> 8;
			(tmp)[1] ^= last4_gf128[rem] & 0xff;
			for(int j = 0; j < 16; j++)
				out[j] = tmp[j] ^ H_128[16*lo + j];
		}

		rem = out[15] & 0xf;
		rshift(tmp, out, 128, 4);
		(tmp)[0] ^= last4_gf128[rem] >> 8;
		(tmp)[1] ^= last4_gf128[rem] & 0xff;
		for(int j = 0; j < 16; j++)
			out[j] = tmp[j] ^ H_128[16*hi + j];
	}
}

