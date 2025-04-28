#include <avr/io.h>
#include <stddef.h>
#include <stdio.h>
#include "cymric/cymric.h"
#include "gcm/gcm_shortinput.h"
#include "gcmsiv/gcmsiv_shortinput.h"
#include "ocb/ocb_shortinput.h"
#include "xocb/xocb_shortinput.h"
#include "ghash/ghash.h"

int main(void)
{
	
	// Variables
	uint8_t ad[16]        = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
	uint8_t nonce[16]     = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
	uint8_t key[32]       = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
	0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
	uint8_t ptext[16]     = {0x7f, 0x43, 0xf6, 0xaf, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
	uint8_t ctext[32]     = {0x00};
	uint8_t ptext_bis[16] = {0x00};
	size_t  clen;
	
	// ------------------- SCENARIO 1 -------------------
	// AES128-Cymric1 encryption
	cymric1_enc(ctext, &clen, key, nonce, 12, ptext, 4, ad, 3);
	// AES128-Cymric2 encryption
	cymric2_enc(ctext, &clen, key, nonce, 12, ptext, 4, ad, 3);
	// AES128-XOCB encryption
	xocb_shortinput_encrypt(ctext, key, nonce, 12, ptext, 4, ad, 3);
	// AES128-AES-GCM-SIV encryption
	gcmsiv_shortinput_encrypt(ctext, key, nonce, 12, ptext, 4, ad, 3);
	// AES128-OCB encryption
	ocb_shortinput_encrypt(ctext, key, nonce, 12, ptext, 4, ad, 3);
	// AES128-GCM encryption
	gcm_shortinput_encrypt(ctext, key, nonce, 12, ptext, 4, ad, 3);
	
	// ------------------- SCENARIO 2 -------------------
	// AES128-Cymric1 encryption
	cymric1_enc(ctext, &clen, key, nonce, 15, ptext, 15, ad, 0);
	// AES128-Cymric2 encryption
	cymric2_enc(ctext, &clen, key, nonce, 15, ptext, 15, ad, 0);
	// AES128-XOCB encryption
	//xocb_shortinput_encrypt(ctext, key, nonce, 15, ptext, 15, ad, 0);
	// AES128-AES-GCM-SIV encryption
	gcmsiv_shortinput_encrypt(ctext, key, nonce, 12, ptext, 15, ad, 0);
	// AES128-OCB encryption
	//ocb_shortinput_encrypt(ctext, key, nonce, 15, ptext, 15, ad, 0);
	// AES128-GCM encryption
	gcm_shortinput_encrypt(ctext, key, nonce, 15, ptext, 15, ad, 0);
	printf("%02x", ctext[0]);
}

