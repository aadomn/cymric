#include <string.h>
#include <stdint.h>
#include "config.h"
#include "utils.h"
#include "gcmsiv.h"
#if defined(MASKING)
#include "aes.h"
#else
#include "aes_ffs.h"
#endif 		/* defined(MASKING) */

#define MUL(x, y)   ((uint64_t)(x) * (uint64_t)(y))

static inline void
br_enc32be(void *dst, uint32_t x)
{
	unsigned char *buf;
	buf = dst;
	buf[0] = (unsigned char)(x >> 24);
	buf[1] = (unsigned char)(x >> 16);
	buf[2] = (unsigned char)(x >> 8);
	buf[3] = (unsigned char)x;
}

static inline uint32_t
br_dec32be(const void *src)
{
	const unsigned char *buf;
	buf = src;
	return ((uint32_t)buf[0] << 24)
		| ((uint32_t)buf[1] << 16)
		| ((uint32_t)buf[2] << 8)
		| (uint32_t)buf[3];
}

/*
 * Simple multiplication in GF(2)[X], using 16 integer multiplications.
 */
static inline void
bmul(uint32_t *hi, uint32_t *lo, uint32_t x, uint32_t y)
{
	uint32_t x0, x1, x2, x3;
	uint32_t y0, y1, y2, y3;
	uint64_t z0, z1, z2, z3;
	uint64_t z;

	x0 = x & (uint32_t)0x11111111;
	x1 = x & (uint32_t)0x22222222;
	x2 = x & (uint32_t)0x44444444;
	x3 = x & (uint32_t)0x88888888;
	y0 = y & (uint32_t)0x11111111;
	y1 = y & (uint32_t)0x22222222;
	y2 = y & (uint32_t)0x44444444;
	y3 = y & (uint32_t)0x88888888;
	z0 = MUL(x0, y0) ^ MUL(x1, y3) ^ MUL(x2, y2) ^ MUL(x3, y1);
	z1 = MUL(x0, y1) ^ MUL(x1, y0) ^ MUL(x2, y3) ^ MUL(x3, y2);
	z2 = MUL(x0, y2) ^ MUL(x1, y1) ^ MUL(x2, y0) ^ MUL(x3, y3);
	z3 = MUL(x0, y3) ^ MUL(x1, y2) ^ MUL(x2, y1) ^ MUL(x3, y0);
	z0 &= (uint64_t)0x1111111111111111;
	z1 &= (uint64_t)0x2222222222222222;
	z2 &= (uint64_t)0x4444444444444444;
	z3 &= (uint64_t)0x8888888888888888;
	z = z0 | z1 | z2 | z3;
	*lo = (uint32_t)z;
	*hi = (uint32_t)(z >> 32);
}

/* see bearssl_hash.h */
static void
br_ghash_ctmul(void *y, const void *h, const void *data, size_t len)
{
	const unsigned char *buf, *hb;
	unsigned char *yb;
	uint32_t yw[4];
	uint32_t hw[4];

	/*
	 * Throughout the loop we handle the y and h values as arrays
	 * of 32-bit words.
	 */
	buf = data;
	yb = y;
	hb = h;
	yw[3] = br_dec32be(yb);
	yw[2] = br_dec32be(yb + 4);
	yw[1] = br_dec32be(yb + 8);
	yw[0] = br_dec32be(yb + 12);
	hw[3] = br_dec32be(hb);
	hw[2] = br_dec32be(hb + 4);
	hw[1] = br_dec32be(hb + 8);
	hw[0] = br_dec32be(hb + 12);
	while (len > 0) {
		const unsigned char *src;
		unsigned char tmp[16];
		int i;
		uint32_t a[9], b[9], zw[8];
		uint32_t c0, c1, c2, c3, d0, d1, d2, d3, e0, e1, e2, e3;

		/*
		 * Get the next 16-byte block (using zero-padding if
		 * necessary).
		 */
		if (len >= 16) {
			src = buf;
			buf += 16;
			len -= 16;
		} else {
			memcpy(tmp, buf, len);
			memset(tmp + len, 0, (sizeof tmp) - len);
			src = tmp;
			len = 0;
		}

		/*
		 * Decode the block. The GHASH standard mandates
		 * big-endian encoding.
		 */
		yw[3] ^= br_dec32be(src);
		yw[2] ^= br_dec32be(src + 4);
		yw[1] ^= br_dec32be(src + 8);
		yw[0] ^= br_dec32be(src + 12);

		/*
		 * We multiply two 128-bit field elements. We use
		 * Karatsuba to turn that into three 64-bit
		 * multiplications, which are themselves done with a
		 * total of nine 32-bit multiplications.
		 */

		/*
		 * y[0,1]*h[0,1] -> 0..2
		 * y[2,3]*h[2,3] -> 3..5
		 * (y[0,1]+y[2,3])*(h[0,1]+h[2,3]) -> 6..8
		 */
		a[0] = yw[0];
		b[0] = hw[0];
		a[1] = yw[1];
		b[1] = hw[1];
		a[2] = a[0] ^ a[1];
		b[2] = b[0] ^ b[1];

		a[3] = yw[2];
		b[3] = hw[2];
		a[4] = yw[3];
		b[4] = hw[3];
		a[5] = a[3] ^ a[4];
		b[5] = b[3] ^ b[4];

		a[6] = a[0] ^ a[3];
		b[6] = b[0] ^ b[3];
		a[7] = a[1] ^ a[4];
		b[7] = b[1] ^ b[4];
		a[8] = a[6] ^ a[7];
		b[8] = b[6] ^ b[7];

		for (i = 0; i < 9; i ++) {
			bmul(&b[i], &a[i], b[i], a[i]);
		}

		c0 = a[0];
		c1 = b[0] ^ a[2] ^ a[0] ^ a[1];
		c2 = a[1] ^ b[2] ^ b[0] ^ b[1];
		c3 = b[1];
		d0 = a[3];
		d1 = b[3] ^ a[5] ^ a[3] ^ a[4];
		d2 = a[4] ^ b[5] ^ b[3] ^ b[4];
		d3 = b[4];
		e0 = a[6];
		e1 = b[6] ^ a[8] ^ a[6] ^ a[7];
		e2 = a[7] ^ b[8] ^ b[6] ^ b[7];
		e3 = b[7];

		e0 ^= c0 ^ d0;
		e1 ^= c1 ^ d1;
		e2 ^= c2 ^ d2;
		e3 ^= c3 ^ d3;
		c2 ^= e0;
		c3 ^= e1;
		d0 ^= e2;
		d1 ^= e3;

		/*
		 * GHASH specification has the bits "reversed" (most
		 * significant is in fact least significant), which does
		 * not matter for a carryless multiplication, except that
		 * the 255-bit result must be shifted by 1 bit.
		 */
		zw[0] = c0 << 1;
		zw[1] = (c1 << 1) | (c0 >> 31);
		zw[2] = (c2 << 1) | (c1 >> 31);
		zw[3] = (c3 << 1) | (c2 >> 31);
		zw[4] = (d0 << 1) | (c3 >> 31);
		zw[5] = (d1 << 1) | (d0 >> 31);
		zw[6] = (d2 << 1) | (d1 >> 31);
		zw[7] = (d3 << 1) | (d2 >> 31);

		/*
		 * We now do the reduction modulo the field polynomial
		 * to get back to 128 bits.
		 */
		for (i = 0; i < 4; i ++) {
			uint32_t lw;

			lw = zw[i];
			zw[i + 4] ^= lw ^ (lw >> 1) ^ (lw >> 2) ^ (lw >> 7);
			zw[i + 3] ^= (lw << 31) ^ (lw << 30) ^ (lw << 25);
		}
		memcpy(yw, zw + 4, sizeof yw);
	}

	/*
	 * Encode back the result.
	 */
	br_enc32be(yb, yw[3]);
	br_enc32be(yb + 4, yw[2]);
	br_enc32be(yb + 8, yw[1]);
	br_enc32be(yb + 12, yw[0]);
}


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


#if !defined(PARALLEL)

int gcmsiv_shortinput_encrypt(
	unsigned char*       ctext,
	const unsigned char* key,
	const unsigned char* iv,    unsigned int iv_len,
	const unsigned char* ptext, unsigned int ptext_len,
	const unsigned char* adata, unsigned int adata_len)
{
	unsigned char tmp[BLOCKBYTES] = {0x00};
	unsigned char s[BLOCKBYTES] = {0x00};
	unsigned char tag[BLOCKBYTES];
	unsigned char auth_key[KEYBYTES];
	unsigned char enc_key[KEYBYTES];
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

	/* Only supports at most a single block of plaintext and associated data */
	if (ptext_len > BLOCKBYTES || adata_len > BLOCKBYTES) {
		return -1;
	}

	/* Compute auth and enc keys */
	memcpy(tmp+sizeof(uint32_t), iv, iv_len);
	AES_ENC_BLOCK(auth_key, tmp, rkeys);
	tmp[0]++;
	AES_ENC_BLOCK(enc_key, tmp, rkeys);
	memcpy(auth_key + BLOCKBYTES/2, enc_key, BLOCKBYTES/2);
	tmp[0]++;
	AES_ENC_BLOCK(enc_key, tmp, rkeys);
	tmp[0]++;
	AES_ENC_BLOCK(tmp, tmp, rkeys);
	memcpy(enc_key + BLOCKBYTES/2, tmp, BLOCKBYTES/2);

#ifdef MASKING
	rkeys = (unsigned char*)enc_key;
#else
	AES_KEY_EXPANSION(rkeys, enc_key);
#endif

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
	AES_ENC_BLOCK(tag, s, rkeys);
	memcpy(ctext + ptext_len, tag, BLOCKBYTES);
	// counter_block <- tag[0]::tag[1]::...::(tag[15] | 0x80)
	tag[15] |= 0x80;

	AES_ENC_BLOCK(tmp, tag, rkeys);
	for(int i = 0; i < ptext_len; i++) {
		ctext[i] = ptext[i] ^ tmp[i];
	}

	return 0;
}

#else /* Fixsliced representation processing 2 blocks in parallel */

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
	AES_KEY_EXPANSION(rkeys, key);

	/* Only supports at most a single block of plaintext and associated data */
	if (ptext_len > BLOCKBYTES || adata_len > BLOCKBYTES) {
		return -1;
	}

	/* Compute auth and enc keys */
	memcpy(tmp+sizeof(uint32_t), iv, iv_len);
	memcpy(tmp+BLOCKBYTES+sizeof(uint32_t), iv, iv_len);
	tmp[BLOCKBYTES]++;
	AES_ENC_BLOCKS(auth_key, enc_key, tmp, tmp + BLOCKBYTES, rkeys);
	memcpy(auth_key + BLOCKBYTES/2, enc_key, BLOCKBYTES/2);
	tmp[0] += 2;
	tmp[BLOCKBYTES] += 2;
	AES_ENC_BLOCKS(enc_key, tmp, tmp, tmp + BLOCKBYTES, rkeys);
	memcpy(enc_key + BLOCKBYTES/2, tmp, BLOCKBYTES/2);

	AES_KEY_EXPANSION(rkeys, enc_key);

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
	AES_ENC_BLOCKS(tag, tag, s, s, rkeys);
	memcpy(ctext + ptext_len, tag, BLOCKBYTES);
	// counter_block <- tag[0]::tag[1]::...::(tag[15] | 0x80)
	tag[15] |= 0x80;

	AES_ENC_BLOCKS(tmp, tmp, tag, tag, rkeys);
	for(int i = 0; i < ptext_len; i++) {
		ctext[i] = ptext[i] ^ tmp[i];
	}

	return 0;
}

#endif /* !defined(PARALLEL) */
