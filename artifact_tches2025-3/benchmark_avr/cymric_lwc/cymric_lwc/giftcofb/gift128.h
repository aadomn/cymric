#ifndef GIFT128_H_
#define GIFT128_H_

#define GIFT128_KEY_SIZE    16
#define GIFT128_BLOCK_SIZE  16
#define GIFT128_KEY_SCHEDULE_WORDS  4

#include <stdint.h>

extern void gift128_keyschedule(const unsigned char* key, uint32_t* rkey);
extern void giftb128_encrypt_block(unsigned char* out_block, const uint32_t* rkey, const unsigned char* in_block);

extern void mygift128_kexp(unsigned char* rkeys, const unsigned char* key);
extern void mygift128_enc(unsigned char* out_block, const unsigned char* in_block, const unsigned char* rkeys);


#endif  // GIFT128_H_
