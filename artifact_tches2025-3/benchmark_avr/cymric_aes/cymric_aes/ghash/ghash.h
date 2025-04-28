#ifndef GHASH_H_
#define GHASH_H_
#include <stdint.h>

void gcm_ghash_mult_tbl(const uint8_t H_128[16*16], const unsigned char x[16], unsigned char out[16]);
void gcm_ghash_gen_tbl(uint8_t H_128[16*16], const uint8_t* k);

#endif /* GHASH_H_ */