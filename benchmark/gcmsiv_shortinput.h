#ifndef GCMSIV_H_
#define GCMSIV_H_

int gcmsiv_shortinput_encrypt(
	unsigned char*       ctext,
	const unsigned char* key,
	const unsigned char* iv,    unsigned int iv_len,
	const unsigned char* ptext, unsigned int ptext_len,
	const unsigned char* adata, unsigned int adata_len);

#endif