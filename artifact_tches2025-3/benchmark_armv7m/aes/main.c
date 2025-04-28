#include "../stm32f4/stm32wrapper.h"
#include <libopencm3/cm3/dwt.h>
#include <stdio.h>
#include <string.h>
#include "aes/aes.h"
#include "modes/cymric/cymric.h"
#include "modes/ocb/ocb_shortinput.h"
#include "modes/gcm/gcm_shortinput.h"
#include "modes/xocb/xocb_shortinput.h"
#include "modes/gcmsiv/gcmsiv_shortinput.h"

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
    size_t  clen;

    unsigned int bench_scenario1[6];
    unsigned int bench_scenario2[6];

    const char *bench_name[6];
    bench_name[0] = "AES128-Cymric1";
    bench_name[1] = "AES128-Cymric2";
    bench_name[2] = "AES128-XOCB";
    bench_name[3] = "AES128-AES-GCM-SIV";
    bench_name[4] = "AES128-OCB";
    bench_name[5] = "AES128-GCM";

    // AES-related variables
    cipher_ctx_t aes_ctx  = aes128_get_cipher_ctx();
    aes128_roundkeys_t aes_rkeys;
    aes_ctx.roundkeys = &aes_rkeys;


    // ------------------- SCENARIO 1 -------------------
    // AES128-Cymric1 encryption
    oldcount = DWT_CYCCNT;
    cymric1_enc(ctext, &clen, key, nonce, 12, ptext, 4, ad, 3, &aes_ctx);
    newcount = DWT_CYCCNT-oldcount;
    bench_scenario1[0] = newcount;
    // AES128-Cymric2 encryption
    oldcount = DWT_CYCCNT;
    cymric2_enc(ctext, &clen, key, nonce, 12, ptext, 4, ad, 3, &aes_ctx);
    newcount = DWT_CYCCNT-oldcount;
    bench_scenario1[1] = newcount;
    // AES128-XOCB encryption
    oldcount = DWT_CYCCNT;
    xocb_shortinput_encrypt(ctext, key, nonce, 12, ptext, 4, ad, 3);
    newcount = DWT_CYCCNT-oldcount;
    bench_scenario1[2] = newcount;
    // AES128-AES-GCM-SIV encryption
    oldcount = DWT_CYCCNT;
    gcmsiv_shortinput_encrypt(ctext, key, nonce, 12, ptext, 4, ad, 3);
    newcount = DWT_CYCCNT-oldcount;
    bench_scenario1[3] = newcount;
    // AES128-OCB encryption
    oldcount = DWT_CYCCNT;
    ocb_shortinput_encrypt(ctext, key, nonce, 12, ptext, 4, ad, 3);
    newcount = DWT_CYCCNT-oldcount;
    bench_scenario1[4] = newcount;
    // AES128-GCM encryption
    oldcount = DWT_CYCCNT;
    gcm_shortinput_encrypt(ctext, key, nonce, 12, ptext, 4, ad, 3);
    newcount = DWT_CYCCNT-oldcount;
    bench_scenario1[5] = newcount;

    // ------------------- SCENARIO 2 -------------------
    // AES128-Cymric1 encryption
    bench_scenario2[0] = 0;
    // AES128-Cymric2 encryption
    oldcount = DWT_CYCCNT;
    cymric2_enc(ctext, &clen, key, nonce, 15, ptext, 15, ad, 0, &aes_ctx);
    newcount = DWT_CYCCNT-oldcount;
    bench_scenario2[1] = newcount;
    // AES128-XOCB encryption
    oldcount = DWT_CYCCNT;
    xocb_shortinput_encrypt(ctext, key, nonce, 15, ptext, 15, ad, 0);
    newcount = DWT_CYCCNT-oldcount;
    bench_scenario2[2] = newcount;
    // AES128-AES-GCM-SIV encryption
    oldcount = DWT_CYCCNT;
    gcmsiv_shortinput_encrypt(ctext, key, nonce, 15, ptext, 15, ad, 0);
    newcount = DWT_CYCCNT-oldcount;
    bench_scenario2[3] = newcount;
    // AES128-OCB encryption
    oldcount = DWT_CYCCNT;
    ocb_shortinput_encrypt(ctext, key, nonce, 15, ptext, 15, ad, 0);
    newcount = DWT_CYCCNT-oldcount;
    bench_scenario2[4] = newcount;
    // AES128-GCM encryption
    oldcount = DWT_CYCCNT;
    gcm_shortinput_encrypt(ctext, key, nonce, 15, ptext, 15, ad, 0);
    newcount = DWT_CYCCNT-oldcount;
    bench_scenario2[5] = newcount;

    sprintf(buf, "Benchmark results for Scenario 1:");
    send_USART_str(buf);
    for(int i = 0; i < 6; i++) {
        sprintf(buf, "%20s %5d cycles", bench_name[i], bench_scenario1[i]);
        send_USART_str(buf);
    }
    sprintf(buf, "\nBenchmark results for Scenario 2:");
    send_USART_str(buf);
    for(int i = 0; i < 6; i++) {
        sprintf(buf, "%20s %5d cycles", bench_name[i], bench_scenario2[i]);
        send_USART_str(buf);
    }

 	return 0;
}
