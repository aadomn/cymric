#ifndef _RIJNDAEL_FAST_H
#define _RIJNDAEL_FAST_H	//performs key expansion

#define AES_BLOCKBYTES 16
#define AES_BLOCKBITS  16*8

	struct data{
		unsigned char data[16];
	};

	//key is the key to expand in binary format
	//expanded points to a 176 byte array to hold the expanded key
	//extern void expand_key(const unsigned char *key, void *expanded);

	//transforms an expanded key to a key for decryption
	
	//expanded points to a 176 byte array to hold the expanded key
	extern void decrypt_key(void *expanded);
	
	extern void expand_key(unsigned char *rkeys, const unsigned char* key);

	extern void encrypt_data(unsigned char * out, const unsigned char *in, const unsigned char *expanded);
	extern void decrypt_data(unsigned char * out, const unsigned char *in, const unsigned char *expanded);
	//extern struct data decrypt_data(struct data ciphertext, void *expanded);

#endif