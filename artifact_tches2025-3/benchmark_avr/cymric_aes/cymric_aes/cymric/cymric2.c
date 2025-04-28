/**
 * @file cymric2.c
 * 
 * @brief Software implementation of the Cymric2 authenticated encryption scheme.
 * See the paper at for more details.
 *
 * @author Alexandre Adomnicai <alexandre@adomnicai.me>
 *
 * @date April 2025
 * 
 * ~~~
 *   |\/\
 *  /,  ~\                _
 * X      `-.....-------./ |
 *  ~-. ~  ~               |
 *     \              /    |
 *      \  /_        _\   /
 *      | /\ ~~~~~~~~ \  |
 *      | | \         || |
 *      | |\ \        || )
 *     (_/ (_/       ((_/
 * ~~~
 */
#include <string.h>
#include "cymric.h"
#include "cymric-common.h"
#include "../aes/rijndaelfast.h"

int cymric2_enc(uint8_t c[], size_t *clen,
            const uint8_t k[],
            const uint8_t n[], size_t nlen,
            const uint8_t m[], size_t mlen,
            const uint8_t a[], size_t alen)
{
    uint8_t tmp[2*AES_BLOCKBYTES] = {0x00};
    uint8_t* y0 = tmp + 1*AES_BLOCKBYTES;
    uint8_t* y1 = tmp + 0*AES_BLOCKBYTES;
    uint8_t b = 0x00;
	uint8_t roundkeys[AES_BLOCKBYTES*11];

    if (mlen > AES_BLOCKBYTES)
        return -1;
    if (nlen + alen > AES_BLOCKBYTES - 1)
        return -1;

    // if |M|== n then b = 1, else b = 0
    b = (mlen == AES_BLOCKBYTES) << 7;

    // compute round keys if online key expansion is required
    expand_key(roundkeys, k);

    // Y0 <- E_K(pad(N||A||b0))
    memcpy(tmp,        n, nlen);
    memcpy(tmp + nlen, a, alen);
    tmp[nlen + alen] = b | 0x20;
    encrypt_data(y0, tmp, roundkeys);

    // Y1 <- E_K(pad(N||A||b1))
    tmp[nlen + alen] |= 0x40;
	encrypt_data(y1, tmp, roundkeys);

    // C <- M ^ Y0 ^ Y1
    xor_bytes(c, y0, y1, mlen);
    xor_bytes(c,  c,  m, mlen);

    // T <- Y0 ^ pad(M)
    memset(tmp, 0x00, AES_BLOCKBYTES);
    memcpy(tmp, m, mlen);
    if (mlen != AES_BLOCKBYTES) {
        tmp[mlen] = 0x80;
    }
    xor_bytes(tmp, y0, tmp, AES_BLOCKBYTES);

    // T = msb(E_K'(T))
    expand_key(roundkeys, k + KEYBYTES);
    encrypt_data(tmp, tmp, roundkeys);
    memcpy(c + mlen, tmp, TAGBYTES);

    *clen = mlen + TAGBYTES;
    return 0;
}


int cymric2_dec(uint8_t m[], size_t *mlen,
            const uint8_t k[],
            const uint8_t n[], size_t nlen,
            const uint8_t c[], size_t clen,
            const uint8_t a[], size_t alen)
{
    uint8_t tmp[2*AES_BLOCKBYTES] = {0x00};
    uint8_t* y0 = tmp + 1*AES_BLOCKBYTES;
    uint8_t* y1 = tmp + 0*AES_BLOCKBYTES;
    uint8_t b = 0x00;
	uint8_t roundkeys[AES_BLOCKBYTES*11];

    clen -= TAGBYTES;

    if (clen > AES_BLOCKBYTES)
        return -1;
    if (nlen + alen > AES_BLOCKBYTES - 1)
        return -1;

    // if |N|+|M|== n then b = 1, else b = 0
    b = (clen == AES_BLOCKBYTES) << 7;

    // compute round keys if online key expansion is required
    expand_key(roundkeys, k);

    // Y0 <- E_K(pad(N||A||b0))
    memcpy(tmp,        n, nlen);
    memcpy(tmp + nlen, a, alen);
    tmp[nlen + alen] = b | 0x20;
    encrypt_data(y0, tmp, roundkeys);

    // Y1 <- E_K(pad(N||A||b1))
    tmp[nlen + alen] |= 0x40;
    encrypt_data(y1, tmp, roundkeys);

    // M <- C ^ Y0 ^ Y1
    xor_bytes(m, y0, y1, clen);
    xor_bytes(m,  m,  c, clen);

    // T <- Y0 ^ pad(M)
    memset(tmp, 0x00, AES_BLOCKBYTES);
    memcpy(tmp, m, clen);
    if (clen != AES_BLOCKBYTES) {
        tmp[clen] = 0x80;
    }
    xor_bytes(tmp, y0, tmp, AES_BLOCKBYTES);

    // T <- msb(E_K'(T))
    expand_key(roundkeys, k + KEYBYTES);
    encrypt_data(tmp, tmp, roundkeys);

    // do not release plaintext if erroneous tag
    if (sec_memcmp(tmp, c + clen, TAGBYTES) != 0) {
        memset(m, 0x00, clen);
        *mlen = 0;
        return 1;
    }
    
    *mlen = clen;
    return 0;
}
