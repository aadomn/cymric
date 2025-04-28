#ifndef CYMRIC_H_
#define CYMRIC_H_

#include <stdint.h>

#define KEYBYTES   16
#define BLOCKBYTES 16
#define TAGBYTES   16

/**
 * @brief Authenticated encryption using Cymric1.
 *
 * @param c The output ciphertext (should be at least 16-byte long)
 * @param clen The length of the ciphertext
 * @param k The encryption key
 * @param n The nonce
 * @param nlen The nonce length (in bytes)
 * @param m The message to secure
 * @param mlen The message length (in bytes)
 * @param a The additional data to authenticate
 * @param alen The additional data length (in bytes)
 * 
 * @return 0 if successfully executed, error code otherwise
 */
int cymric1_enc(uint8_t c[], size_t *clen,
        const uint8_t k[],
        const uint8_t n[], size_t nlen,
        const uint8_t m[], size_t mlen,
        const uint8_t a[], size_t alen);

/**
 * @brief Authenticated decryption using Manx1.
 *
 * @param p The output plaintext
 * @param plen The length of the plaintext
 * @param k The encryption key
 * @param n The nonce
 * @param nlen The nonce length (in bytes)
 * @param c The ciphertext to decrypt/verify
 * @param clen The ciphertext length (in bytes)
 * @param a The additional data
 * @param alen The additional data length (in bytes)
 * 
 * @return 0 if successfully executed, error code otherwise
 */
int cymric1_dec(uint8_t p[], size_t *plen,
        const uint8_t k[],
        const uint8_t n[], size_t nlen,
        const uint8_t c[], size_t clen,
        const uint8_t a[], size_t alen);

/**
 * @brief Authenticated encryption using Cymric2.
 *
 * @param c The output ciphertext
 * @param clen The length of the ciphertext
 * @param k The encryption key
 * @param n The nonce
 * @param nlen The nonce length (in bytes)
 * @param m The message to secure
 * @param mlen The message length (in bytes)
 * @param a The additional data to authenticate
 * @param alen The additional data length (in bytes)
 * 
 * @return 0 if successfully executed, error code otherwise
 */
int cymric2_enc(uint8_t c[], size_t *clen,
        const uint8_t k[],
        const uint8_t n[], size_t nlen,
        const uint8_t m[], size_t mlen,
        const uint8_t a[], size_t alen);

/**
 * @brief Authenticated decryption using Manx2.
 *
 * @param p The output plaintext
 * @param plen The length of the plaintext
 * @param k The encryption key
 * @param n The nonce
 * @param nlen The nonce length (in bytes)
 * @param c The ciphertext to decrypt/verify
 * @param clen The ciphertext length (in bytes)
 * @param a The additional data
 * @param alen The additional data length (in bytes)
 * 
 * @return 0 if successfully executed, error code otherwise
 */
int cymric2_dec(uint8_t p[], size_t *plen,
        const uint8_t k[],
        const uint8_t n[], size_t nlen,
        const uint8_t c[], size_t clen,
        const uint8_t a[], size_t alen);

#endif