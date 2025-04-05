#ifndef CYMRIC_H_
#define CYMRIC_H_

#include <stdint.h>
#include "cipher_ctx.h"

#define KEYBYTES   16
#define BLOCKBYTES 16
#define TAGBYTES   16

/**
 * @brief Authenticated encryption using Cymric1.
 *
 * @param c The output ciphertext (should be at least TAGBYTES+mlen long)
 * @param clen The length of the ciphertext
 * @param k The encryption key
 * @param n The nonce
 * @param nlen The nonce length (in bytes)
 * @param m The message to secure
 * @param mlen The message length (in bytes)
 * @param a The additional data to authenticate
 * @param alen The additional data length (in bytes)
 * @param ctx The cipher context which contains the cipher-related functions
 *      and the round keys' material
 * 
 * @return 0 if successfully executed, error code otherwise
 */
int cymric1_enc(uint8_t c[], size_t *clen,
        const uint8_t k[],
        const uint8_t n[], size_t nlen,
        const uint8_t m[], size_t mlen,
        const uint8_t a[], size_t alen,
        const cipher_ctx_t* ctx);

/**
 * @brief Authenticated decryption using Cymric1.
 *
 * @param p The output plaintext (should be at least clen-TAGBYTES long)
 * @param plen The length of the plaintext
 * @param k The encryption key
 * @param n The nonce
 * @param nlen The nonce length (in bytes)
 * @param c The ciphertext to decrypt/verify
 * @param clen The ciphertext length (in bytes)
 * @param a The additional data
 * @param alen The additional data length (in bytes)
 * @param ctx The cipher context which contains the cipher-related functions
 *      and the round keys' material
 * 
 * @return 0 if successfully executed, error code otherwise
 */
int cymric1_dec(uint8_t p[], size_t *plen,
        const uint8_t k[],
        const uint8_t n[], size_t nlen,
        const uint8_t c[], size_t clen,
        const uint8_t a[], size_t alen,
        const cipher_ctx_t* ctx);

/**
 * @brief Authenticated encryption using Cymric2.
 *
 * @param c The output ciphertext (should be at least TAGBYTES+mlen long)
 * @param clen The length of the ciphertext
 * @param k The encryption key
 * @param n The nonce
 * @param nlen The nonce length (in bytes)
 * @param m The message to secure
 * @param mlen The message length (in bytes)
 * @param a The additional data to authenticate
 * @param alen The additional data length (in bytes)
 * @param ctx The cipher context which contains the cipher-related functions
 *      and the round keys' material
 * 
 * @return 0 if successfully executed, error code otherwise
 */
int cymric2_enc(uint8_t c[], size_t *clen,
        const uint8_t k[],
        const uint8_t n[], size_t nlen,
        const uint8_t m[], size_t mlen,
        const uint8_t a[], size_t alen,
        const cipher_ctx_t* ctx);

/**
 * @brief Authenticated decryption using Cymric2.
 *
 * @param p The output plaintext (should be at least clen-TAGBYTES long)
 * @param plen The length of the plaintext
 * @param k The encryption key
 * @param n The nonce
 * @param nlen The nonce length (in bytes)
 * @param c The ciphertext to decrypt/verify
 * @param clen The ciphertext length (in bytes)
 * @param a The additional data
 * @param alen The additional data length (in bytes)
 * @param ctx The cipher context which contains the cipher-related functions
 *      and the round keys' material
 * 
 * @return 0 if successfully executed, error code otherwise
 */
int cymric2_dec(uint8_t p[], size_t *plen,
        const uint8_t k[],
        const uint8_t n[], size_t nlen,
        const uint8_t c[], size_t clen,
        const uint8_t a[], size_t alen,
        const cipher_ctx_t* ctx);

#endif
