#include "../stm32f4/stm32wrapper.h"
#include <libopencm3/cm3/dwt.h>
#include <stdio.h>
#include <string.h>
// Cymric
#include "cymric/cymric.h"
#include "cymric/lea/lea128.h"
#include "cymric/gift/gift128.h"
// Ascon
#include "asconaead128/ascon.h"
// Xoodyak
#include "xoodyak/crypto_aead.h"
// Romulus-N
#include "romulusn/crypto_aead.h"
// PHOTON-Beetle-AEAD[128]
#include "photonbeetle/photon-beetle-aead.h"
// GIFT-COFB
#include "giftcofb/encrypt.h"

int main(void) {

    // Board setup
 	clock_setup();
 	gpio_setup();
 	usart_setup(115200);
	flash_setup();

 	// Activate cycle counter register
 	SCS_DEMCR |= SCS_DEMCR_TRCENA;
 	DWT_CYCCNT = 0;
 	DWT_CTRL |= DWT_CTRL_CYCCNTENA;
 	unsigned int oldcount, newcount;
 	char buffer[128];
 	char *buf = buffer;

    // Variables
    uint8_t ad[16]        = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    uint8_t nonce[16]     = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    uint8_t key[32]       = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
                             0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t ptext[16]     = {0x7f, 0x43, 0xf6, 0xaf, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
    uint8_t ctext[32]     = {0x00};
    long long unsigned int olen;
    size_t  clen;

    unsigned int bench_scenario1[11];
    unsigned int bench_scenario2[11];

    uint8_t gift_roundkeys[80*4*2];

    const char *bench_name[11];
    bench_name[0] = "LEA128-Cymric1";
    bench_name[1] = "LEA128-Cymric2";
    bench_name[2] = "GIFT128-Cymric1";
    bench_name[3] = "GIFT128-Cymric2";
    bench_name[4] = "GIFT128-Cymric1*";
    bench_name[5] = "GIFT128-Cymric2*";
    bench_name[6] = "Ascon-AEAD128";
    bench_name[7] = "Xoodyak";
    bench_name[8] = "Romulus-N";
    bench_name[9] = "PHOTON-Beetle-AEAD";
    bench_name[10] = "GIFT-COFB";

    // LEA-related variables
    cipher_ctx_t lea_ctx  = lea128_get_cipher_ctx();
    // GIFT-related variables
    cipher_ctx_t gift_ctx = gift128_get_cipher_ctx();
    gift128_roundkeys_t gift_rkeys;
    gift_ctx.roundkeys = &gift_rkeys;

    // ------------------- SCENARIO 1 -------------------
    // LEA128-Cymric1 encryption
    oldcount = DWT_CYCCNT;
    cymric1_enc(ctext, &clen, key, nonce, 12, ptext, 4, ad, 3, &lea_ctx);
    newcount = DWT_CYCCNT-oldcount;
    bench_scenario1[0] = newcount;
    // LEA128-Cymric2 encryption
    oldcount = DWT_CYCCNT;
    cymric2_enc(ctext, &clen, key, nonce, 12, ptext, 4, ad, 3, &lea_ctx);
    newcount = DWT_CYCCNT-oldcount;
    bench_scenario1[1] = newcount;
    // GIFT128-Cymric1 encryption
    oldcount = DWT_CYCCNT;
    cymric1_enc(ctext, &clen, key, nonce, 12, ptext, 4, ad, 3, &gift_ctx);
    newcount = DWT_CYCCNT-oldcount;
    bench_scenario1[2] = newcount;
    // GIFT128-Cymric2 encryption
    oldcount = DWT_CYCCNT;
    cymric2_enc(ctext, &clen, key, nonce, 12, ptext, 4, ad, 3, &gift_ctx);
    newcount = DWT_CYCCNT-oldcount;
    bench_scenario1[3] = newcount;
    // precomputed round keys
    gift128_keyschedule(gift_roundkeys, key);
    gift128_keyschedule(gift_roundkeys + 80*4, key+KEYBYTES);
    gift_ctx.kexpand = NULL;
    // GIFT128-Cymric1 encryption (precomputed roundkeys)
    oldcount = DWT_CYCCNT;
    cymric1_enc(ctext, &clen, key, nonce, 12, ptext, 4, ad, 3, &gift_ctx);
    newcount = DWT_CYCCNT-oldcount;
    bench_scenario1[4] = newcount;
    // GIFT128-Cymric2 encryption (precomputed roundkeys)
    oldcount = DWT_CYCCNT;
    cymric2_enc(ctext, &clen, key, nonce, 12, ptext, 4, ad, 3, &gift_ctx);
    newcount = DWT_CYCCNT-oldcount;
    bench_scenario1[5] = newcount;
    // Ascon-AEAD128 encryption
    oldcount = DWT_CYCCNT;
    ascon_aead_encrypt(ctext + 4, ctext, ptext, 4, ad, 3, nonce, key);
    newcount = DWT_CYCCNT-oldcount;
    bench_scenario1[6] = newcount;
    // Xoodyak encryption
    oldcount = DWT_CYCCNT;
    xoodyak_encrypt(ctext, &olen, ptext, 4, ad, 3, NULL, nonce, key);
    newcount = DWT_CYCCNT-oldcount;
    bench_scenario1[7] = newcount;
    // Romulus-N encryption
    oldcount = DWT_CYCCNT;
    romulusn_encrypt(ctext, &olen, ptext, 4, ad, 3, NULL, nonce, key);
    newcount = DWT_CYCCNT-oldcount;
    bench_scenario1[8] = newcount;
    // PHOTON-Beetle-AEAD[128] encryption
    oldcount = DWT_CYCCNT;
    photon_beetle_128_aead_encrypt(ctext, &clen, ptext, 4, ad, 3, nonce, key);
    newcount = DWT_CYCCNT-oldcount;
    bench_scenario1[9] = newcount;
    // GIFT-COFB encryption
    oldcount = DWT_CYCCNT;
    giftcofb_encrypt(ctext, &olen, ptext, 4, ad, 3, NULL, nonce, key);
    newcount = DWT_CYCCNT-oldcount;
    bench_scenario1[10] = newcount;


    // ------------------- SCENARIO 2 -------------------
    gift_ctx.kexpand = gift128_keyschedule;
    // LEA128-Cymric1 encryption
    bench_scenario2[0] = 0;
    // LEA128-Cymric2 encryption
    oldcount = DWT_CYCCNT;
    cymric2_enc(ctext, &clen, key, nonce, 15, ptext, 15, ad, 0, &lea_ctx);
    newcount = DWT_CYCCNT-oldcount;
    bench_scenario2[1] = newcount;
    // GIFT128-Cymric1 encryption
    bench_scenario2[2] = 0;
    // GIFT128-Cymric2 encryption
    oldcount = DWT_CYCCNT;
    cymric2_enc(ctext, &clen, key, nonce, 15, ptext, 15, ad, 0, &gift_ctx);
    newcount = DWT_CYCCNT-oldcount;
    bench_scenario2[3] = newcount;
    // precomputed round keys
    gift128_keyschedule(gift_roundkeys, key);
    gift128_keyschedule(gift_roundkeys + 80*4, key+KEYBYTES);
    gift_ctx.kexpand = NULL;
    // GIFT128-Cymric1 encryption (precomputed roundkeys)
    bench_scenario2[4] = 0;
    // GIFT128-Cymric2 encryption (precomputed roundkeys)
    oldcount = DWT_CYCCNT;
    cymric2_enc(ctext, &clen, key, nonce, 15, ptext, 15, ad, 0, &gift_ctx);
    newcount = DWT_CYCCNT-oldcount;
    bench_scenario2[5] = newcount;
    // Ascon-AEAD128 encryption
    oldcount = DWT_CYCCNT;
    ascon_aead_encrypt(ctext + 4, ctext, ptext, 15, ad, 0, nonce, key);
    newcount = DWT_CYCCNT-oldcount;
    bench_scenario2[6] = newcount;
    // Xoodyak encryption
    oldcount = DWT_CYCCNT;
    xoodyak_encrypt(ctext, &olen, ptext, 15, ad, 0, NULL, nonce, key);
    newcount = DWT_CYCCNT-oldcount;
    bench_scenario2[7] = newcount;
    // Romulus-N encryption
    oldcount = DWT_CYCCNT;
    romulusn_encrypt(ctext, &olen, ptext, 15, ad, 0, NULL, nonce, key);
    newcount = DWT_CYCCNT-oldcount;
    bench_scenario2[8] = newcount;
    // PHOTON-Beetle-AEAD[128] encryption
    oldcount = DWT_CYCCNT;
    photon_beetle_128_aead_encrypt(ctext, &clen, ptext, 15, ad, 0, nonce, key);
    newcount = DWT_CYCCNT-oldcount;
    bench_scenario2[9] = newcount;
    // GIFT-COFB encryption
    oldcount = DWT_CYCCNT;
    giftcofb_encrypt(ctext, &olen, ptext, 15, ad, 0, NULL, nonce, key);
    newcount = DWT_CYCCNT-oldcount;
    bench_scenario2[10] = newcount;


    sprintf(buf, "Benchmark results for Scenario 1:");
    send_USART_str(buf);
    for(int i = 0; i < 11; i++) {
        sprintf(buf, "%20s %5d cycles", bench_name[i], bench_scenario1[i]);
        send_USART_str(buf);
    }
    sprintf(buf, "\nBenchmark results for Scenario 2:");
    send_USART_str(buf);
    for(int i = 0; i < 11; i++) {
        sprintf(buf, "%20s %5d cycles", bench_name[i], bench_scenario2[i]);
        send_USART_str(buf);
    }




/*
    sprintf(buf, "%d cycles for lea128-cymric1 encryption (12,4,3) which returned %d\n", newcount, ret);
    send_USART_str(buf);
    // LEA128-Cymric1 decryption
    cymric1_dec(ptext_bis, &plen, key, nonce, 12, ctext, clen, ad, 3, &lea_ctx);
    if (cmp_bytes(ptext, ptext_bis, plen)) {
        sprintf(buf, "LEA128-Cymric1 decryption went wrong\n");
        send_USART_str(buf);
    }
    // LEA128-Cymric2 encryption
    oldcount = DWT_CYCCNT;
    ret = cymric2_enc(ctext, &clen, key, nonce, 12, ptext, 4, ad, 3, &lea_ctx);
    newcount = DWT_CYCCNT-oldcount;
    sprintf(buf, "%d cycles for lea128-cymric2 encryption (12,4,3) which returned %d\n", newcount, ret);
    send_USART_str(buf);
    // LEA128-Cymric2 decryption
    cymric2_dec(ptext_bis, &plen, key, nonce, 12, ctext, clen, ad, 3, &lea_ctx);
    if (cmp_bytes(ptext, ptext_bis, plen)) {
        sprintf(buf, "LEA128-Cymric2 decryption went wrong\n");
        send_USART_str(buf);
    }

    // GIFT128-Cymric1 encryption
    oldcount = DWT_CYCCNT;
    ret = cymric1_enc(ctext, &clen, key, nonce, 12, ptext, 4, ad, 3, &gift_ctx);
    newcount = DWT_CYCCNT-oldcount;
    sprintf(buf, "%d cycles for gift128-cymric1 encryption (12,4,3) which returned %d\n", newcount, ret);
    send_USART_str(buf);
    // GIFT128-Cymric1 decryption
    cymric1_dec(ptext_bis, &plen, key, nonce, 12, ctext, clen, ad, 3, &gift_ctx);
    if (cmp_bytes(ptext, ptext_bis, plen)) {
        sprintf(buf, "GIFT128-Cymric1 decryption went wrong\n");
        send_USART_str(buf);
    }
    // GIFT128-Cymric2 encryption
    oldcount = DWT_CYCCNT;
    ret = cymric2_enc(ctext, &clen, key, nonce, 12, ptext, 4, ad, 3, &gift_ctx);
    newcount = DWT_CYCCNT-oldcount;
    sprintf(buf, "%d cycles for gift128-cymric2 encryption (12,4,3) which returned %d\n", newcount, ret);
    send_USART_str(buf);
    // GIFT128-Cymric2 decryption
    cymric2_dec(ptext_bis, &plen, key, nonce, 12, ctext, clen, ad, 3, &gift_ctx);
    if (cmp_bytes(ptext, ptext_bis, plen)) {
        sprintf(buf, "GIFT128-Cymric1 decryption went wrong\n");
        send_USART_str(buf);
    }

    // precomputed round keys
    uint8_t gift_roundkeys[80*4*2];
    gift128_keyschedule(gift_roundkeys, key);
    gift128_keyschedule(gift_roundkeys + 80*4, key+KEYBYTES);
    gift_ctx.kexpand = NULL;
    // GIFT128-Cymric1 encryption
    oldcount = DWT_CYCCNT;
    ret = cymric1_enc(ctext, &clen, gift_roundkeys, nonce, 12, ptext, 4, ad, 3, &gift_ctx);
    newcount = DWT_CYCCNT-oldcount;
    sprintf(buf, "%d cycles for gift128-cymric1 encryption (12,4,3) which returned %d\n", newcount, ret);
    send_USART_str(buf);
    // GIFT128-Cymric1 decryption
    cymric1_dec(ptext_bis, &plen, gift_roundkeys, nonce, 12, ctext, clen, ad, 3, &gift_ctx);
    if (cmp_bytes(ptext, ptext_bis, plen)) {
        sprintf(buf, "GIFT128-Cymric1 decryption went wrong\n");
        send_USART_str(buf);
    }
    // GIFT128-Cymric2 encryption
    oldcount = DWT_CYCCNT;
    ret = cymric2_enc(ctext, &clen, gift_roundkeys, nonce, 12, ptext, 4, ad, 3, &gift_ctx);
    newcount = DWT_CYCCNT-oldcount;
    sprintf(buf, "%d cycles for gift128-cymric2 encryption (12,4,3) which returned %d\n", newcount, ret);
    send_USART_str(buf);
    // GIFT128-Cymric2 decryption
    cymric2_dec(ptext_bis, &plen, gift_roundkeys, nonce, 12, ctext, clen, ad, 3, &gift_ctx);
    if (cmp_bytes(ptext, ptext_bis, plen)) {
        sprintf(buf, "GIFT128-Cymric1 decryption went wrong\n");
        send_USART_str(buf);
    }
    */




 	return 0;
}
