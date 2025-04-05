#include "aes.h"

cipher_ctx_t aes_get_cipher_ctx(void) {
    cipher_ctx_t ctx = {
        .encrypt = aes128_enc,
        .kexpand = aes128_kexp,
        .rkeys_size = sizeof(aes_roundkeys_t),
    };
    return ctx;
}

/**
 * Key schedule round function.
 */
static inline void keyschedule_roundfunc(__m128i *rkey, __m128i word)
{
  __m128i tmp;
  word  = _mm_shuffle_epi32(word, 0xff);
  tmp   = _mm_slli_si128(*rkey, 0x4);
  *rkey = _mm_xor_si128(*rkey, tmp);
  tmp   = _mm_slli_si128(tmp, 0x4);
  *rkey = _mm_xor_si128(*rkey, tmp);
  tmp   = _mm_slli_si128(tmp, 0x4);
  *rkey = _mm_xor_si128(*rkey, tmp);
  *rkey = _mm_xor_si128(*rkey, word);
}

/**
 * Precalculate all AES-128 round keys from an input encryption key.
 */
void aes128_kexp(void* roundkeys, const uint8_t* key)
{
  aes_roundkeys_t* rkeys = (aes_roundkeys_t*)roundkeys;
  __m128i rkey;
  rkey = _mm_load_si128((__m128i*)key);
  rkeys->rk[0] = rkey; 
  keyschedule_roundfunc(&rkey, _mm_aeskeygenassist_si128(rkey, 0x01));
  rkeys->rk[1] = rkey;
  keyschedule_roundfunc(&rkey, _mm_aeskeygenassist_si128(rkey, 0x02));
  rkeys->rk[2] = rkey;
  keyschedule_roundfunc(&rkey, _mm_aeskeygenassist_si128(rkey, 0x04));
  rkeys->rk[3] = rkey;
  keyschedule_roundfunc(&rkey, _mm_aeskeygenassist_si128(rkey, 0x08));
  rkeys->rk[4] = rkey;
  keyschedule_roundfunc(&rkey, _mm_aeskeygenassist_si128(rkey, 0x10));
  rkeys->rk[5] = rkey;
  keyschedule_roundfunc(&rkey, _mm_aeskeygenassist_si128(rkey, 0x20));
  rkeys->rk[6] = rkey;
  keyschedule_roundfunc(&rkey, _mm_aeskeygenassist_si128(rkey, 0x40));
  rkeys->rk[7] = rkey;
  keyschedule_roundfunc(&rkey, _mm_aeskeygenassist_si128(rkey, 0x80));
  rkeys->rk[8] = rkey;
  keyschedule_roundfunc(&rkey, _mm_aeskeygenassist_si128(rkey, 0x1b));
  rkeys->rk[9] = rkey;
  keyschedule_roundfunc(&rkey, _mm_aeskeygenassist_si128(rkey, 0x36));
  rkeys->rk[10] = rkey;
}

void aes128_enc(unsigned char* out, const unsigned char* in, const void* roundkeys)
{
  unsigned int i;
  __m128i state;
  const aes_roundkeys_t* aes_rkeys = (const aes_roundkeys_t*)roundkeys;
  const __m128i* rkeys = (const __m128i*)aes_rkeys->rk;

  state = _mm_load_si128((__m128i*)in);
  state = _mm_xor_si128(state, rkeys[0]);
  for(i = 1; i < 10; i++)
    state = _mm_aesenc_si128(state, rkeys[i]);
  state = _mm_aesenclast_si128(state, rkeys[i]);

  _mm_store_si128((__m128i*)out, state);
}

void aes128_dec(unsigned char* out, const unsigned char* in, const void* roundkeys)
{
  unsigned int i;
  __m128i state;
  const aes_roundkeys_t* aes_rkeys = (const aes_roundkeys_t*)roundkeys;
  const __m128i* rkeys = (const __m128i*)aes_rkeys->rk;

  state = _mm_load_si128((__m128i*)in);
  state = _mm_xor_si128(state, rkeys[10]);
  for(i = 9; i > 0; i--) 
    state = _mm_aesdec_si128(state, _mm_aesimc_si128(rkeys[i]));
  state = _mm_aesdeclast_si128(state, rkeys[i]);

  _mm_store_si128((__m128i*)out, state);
}
