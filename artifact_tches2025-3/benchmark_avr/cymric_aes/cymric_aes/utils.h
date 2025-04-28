#ifndef UTILS_H_
#define UTILS_H_

inline void xor_bytes(unsigned char* out, const unsigned char* op0, const unsigned char* op1, int len) {
	for (int i = 0; i < len; i++) {
		out[i] = op0[i] ^ op1[i];
	}
}

/* Doubling in GF(2^128) defined by x^128 + x^7 + x^2 + x + 1 
inline void double_arr(unsigned char out[16], const unsigned char in[16]) {
	unsigned char first_bit = -(in[0] >> 7);
	for (unsigned int i = 0; i < 15; i++) {
		out[i]  = in[i]     << 1;
		out[i] |= in[i + 1] >> 7;
	}
	out[15]   = in[15] << 1;
	out[15]  ^= first_bit & 135;
}
*/

#endif /* UTILS_H_ */
