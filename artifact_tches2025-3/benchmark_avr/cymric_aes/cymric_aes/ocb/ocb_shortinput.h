#ifndef OCB_SHORTINPUT_H_
#define OCB_SHORTINPUT_H_

/**
 * Encrypt and authenticate a plaintext w/ additional data 
 * (each limited to 128 bits at most).
 *
 * @param ctext     output that will be composed of ciphertext + tag
 * @param key 		128-bit encryption key + 128-bit l_asterisk
 * @param nonce     initialization vector     
 * @param nonce_len nonce length
 * @param ptext    	plaintext
 * @param ptext_len plaintext length
 * @param adata     additional data
 * @param adata_len additional data length
 */
int ocb_shortinput_encrypt(
	unsigned char*       ctext,
	const unsigned char* key,
	const unsigned char* nonce, unsigned int nonce_len,
	const unsigned char* ptext, unsigned int ptext_len,
	const unsigned char* adata, unsigned int adata_len);

#endif 	/* OCB_SHORTINPUT_H_ */
