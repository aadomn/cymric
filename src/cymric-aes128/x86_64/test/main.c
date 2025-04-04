#include <stdio.h>
#include <string.h>
#include "../cymric.h"
#include "../aes.h"

int main(void) {
    uint8_t ad[16]        = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    uint8_t nonce[16]     = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    uint8_t key[32]       = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
                             0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t ptext[16]     = {0x7f, 0x43, 0xf6, 0xaf, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
    uint8_t ctext[32]     = {0x00};
    size_t outlen;

    cipher_ctx_t aes_ctx = aes_get_cipher_ctx();
    aes_roundkeys_t aes_keys;
    aes_ctx.roundkeys = &aes_keys;

    int ret = cymric1_enc(ctext, &outlen, key, nonce, 12, ptext, 4, ad, 3, &aes_ctx);
    printf("manx1_enc (12, 4, 3) returned ret = %d and outlen = %ld\n", ret, outlen);
    for(size_t i = 0; i < outlen; i++)
      printf("%02x", ctext[i]);
    printf("\n");
    ret = cymric1_dec(ptext, &outlen, key, nonce, 12, ctext, outlen, ad, 3, &aes_ctx);
    printf("manx1_dec (12, 4, 3) returned %d and outlen = %ld\n", ret, outlen);
    for(size_t i = 0; i < outlen; i++)
      printf("%02x", ptext[i]);
    printf("\n");

    ret = cymric1_enc(ctext, &outlen, key, nonce, 8, ptext, 8, ad, 4, &aes_ctx);
    printf("manx1_enc (8, 8, 4) returned ret = %d and outlen = %ld\n", ret, outlen);
    for(size_t i = 0; i < outlen; i++)
      printf("%02x", ctext[i]);
    printf("\n");
    ret = cymric1_dec(ptext, &outlen, key, nonce, 8, ctext, outlen, ad, 4, &aes_ctx);
    printf("manx1_dec (8, 8, 4) returned %d and outlen = %ld\n", ret, outlen);
    for(size_t i = 0; i < outlen; i++)
      printf("%02x", ptext[i]);
    printf("\n");

    ret = cymric2_enc(ctext, &outlen, key, nonce, 12, ptext, 16, ad, 3, &aes_ctx);
    printf("manx2_enc (12, 16, 3) returned ret = %d and outlen = %ld\n", ret, outlen);
    for(size_t i = 0; i < outlen; i++)
      printf("%02x", ctext[i]);
    printf("\n");
    ret = cymric2_dec(ptext, &outlen, key, nonce, 12, ctext, outlen, ad, 3, &aes_ctx);
    printf("manx2_dec (12, 16, 3) returned %d and outlen = %ld\n", ret, outlen);
    for(size_t i = 0; i < outlen; i++)
      printf("%02x", ptext[i]);
    printf("\n");

    return 0;
}
