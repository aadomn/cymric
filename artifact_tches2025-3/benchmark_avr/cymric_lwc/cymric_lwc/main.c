#include <stdio.h>
#include <avr/io.h>

// Cymric
#include "cymric/cymric.h"
#include "cymric/lea/lea128.h"
#include "cymric/gift/gift128.h"
// Romulus-N
#include "romulusn/romulus-n-aead.h"
// Xoodyak
#include "xoodyak/xoodyak-aead.h"
// Photon-Beetle
#include "photonbeetle/photon-beetle-aead.h"
// GIFT-COFB
#include "giftcofb/giftcofb.h"
#include "giftcofb/gift128.h"
// Ascon
#include "asconaead/ascon.h"

int main(void)
{
	uint8_t ad[16]        = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
	uint8_t nonce[16]     = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
	uint8_t key[32]       = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
							0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
	uint8_t ptext[16]     = {0x7f, 0x43, 0xf6, 0xaf, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
	uint8_t ctext[32]     = {0x00};
	uint8_t ptext_bis[16] = {0x00};
	long long unsigned int olen;
	size_t  clen;
	size_t  plen;
	
	// LEA-related variables
	cipher_ctx_t lea_ctx  = lea128_get_cipher_ctx();
	lea128_roundkeys_t lea_rkeys;
	lea_ctx.roundkeys = &lea_rkeys;
	// GIFT-related variables
	cipher_ctx_t gift_ctx = gift128_get_cipher_ctx();
	gift128_roundkeys_t gift_rkeys;
	gift_ctx.roundkeys = &gift_rkeys;
	
	// ------------------- SCENARIO 1 -------------------
	// LEA128-Cymric1 encryption
	cymric1_enc(ctext, &clen, key, nonce, 12, ptext, 4, ad, 3, &lea_ctx);
	// LEA128-Cymric2 encryption
	cymric2_enc(ctext, &clen, key, nonce, 12, ptext, 4, ad, 3, &lea_ctx);
	// GIFT128-Cymric1 encryption
	cymric1_enc(ctext, &clen, key, nonce, 12, ptext, 4, ad, 3, &gift_ctx);
	// GIFT28-Cymric2 encryption
	cymric2_enc(ctext, &clen, key, nonce, 12, ptext, 4, ad, 3, &gift_ctx);
	// Round keys precomputation
	uint8_t lea_roundkeys[24*16*2];
	uint8_t gift_roundkeys[80*4*2];
	lea_ctx.kexpand = NULL;
	gift_ctx.kexpand = NULL;
	// LEA128-Cymric1* encryption
	cymric1_enc(ctext, &clen, lea_roundkeys, nonce, 12, ptext, 4, ad, 3, &lea_ctx);
	// LEA128-Cymric2* encryption
	//cymric2_enc(ctext, &clen, lea_roundkeys, nonce, 12 ptext, 4, ad, 3, &lea_ctx);
	// GIFT128-Cymric1* encryption
	cymric1_enc(ctext, &clen, lea_roundkeys, nonce, 12, ptext, 4, ad, 3, &gift_ctx);
	// GIFT128-Cymric2* encryption
	cymric2_enc(ctext, &clen, lea_roundkeys, nonce, 12, ptext, 4, ad, 3, &gift_ctx);

	// Ascon-AEAD128 encryption
	// Xoodyak encryption
	xoodyak_aead_encrypt(ctext,  &clen, ptext, 4, ad, 3, nonce, key);
	// Romulus-N encryption
	romulus_n_aead_encrypt(ctext,  &clen, ptext, 4, ad, 3, nonce, key);
	// PHOTON-Beetle-AEAD[128] encryption
	photon_beetle_128_aead_encrypt(ctext,  &clen, ptext, 4, ad, 3, nonce, key);
	// GIFT-COFB encryption
	giftcofb_encrypt(ctext,  &olen, ptext, 15, ad, 0, NULL, nonce, key);
	
	ascon_aead_encrypt(ctext + 4, ctext, ptext, 4, ad, 3, nonce, key);
	
	
	// ------------------- SCENARIO 2 -------------------
	// LEA128-Cymric1 encryption
	cymric1_enc(ctext, &clen, key, nonce, 15, ptext, 15, ad, 0, &lea_ctx);
	// LEA128-Cymric2 encryption
	cymric2_enc(ctext, &clen, key, nonce, 15, ptext, 15, ad, 0, &lea_ctx);
	// GIFT128-Cymric1 encryption
	cymric1_enc(ctext, &clen, key, nonce, 15, ptext, 15, ad, 0, &gift_ctx);
	// GIFT28-Cymric2 encryption
	cymric2_enc(ctext, &clen, key, nonce, 15, ptext, 15, ad, 0, &gift_ctx);
	lea_ctx.kexpand = NULL;
	gift_ctx.kexpand = NULL;
	// LEA128-Cymric1* encryption
	cymric1_enc(ctext, &clen, lea_roundkeys, nonce, 15, ptext, 15, ad, 0, &lea_ctx);
	// LEA128-Cymric2* encryption
	cymric2_enc(ctext, &clen, lea_roundkeys, nonce, 15, ptext, 15, ad, 0, &lea_ctx);
	// GIFT128-Cymric1* encryption
	cymric1_enc(ctext, &clen, lea_roundkeys, nonce, 15, ptext, 15, ad, 0, &gift_ctx);
	// GIFT128-Cymric2* encryption
	cymric2_enc(ctext, &clen, lea_roundkeys, nonce, 15, ptext, 15, ad, 0, &gift_ctx);

	// Ascon-AEAD128 encryption
	// Xoodyak encryption
	xoodyak_aead_encrypt(ctext,  &clen, ptext, 15, ad, 0, nonce, key);
	// Romulus-N encryption
	romulus_n_aead_encrypt(ctext,  &clen, ptext, 15, ad, 0, nonce, key);
	// PHOTON-Beetle-AEAD[128] encryption
	photon_beetle_128_aead_encrypt(ctext,  &clen, ptext, 15, ad, 0, nonce, key);
	// GIFT-COFB encryption
	giftcofb_encrypt(ctext,  &olen, ptext, 15, ad, 0, NULL, nonce, key);
	printf("%02x",ctext[0]);

}

