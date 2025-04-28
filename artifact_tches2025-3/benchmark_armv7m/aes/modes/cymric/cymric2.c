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

int cymric2_enc(uint8_t c[], size_t *clen,
            const uint8_t k[],
            const uint8_t n[], size_t nlen,
            const uint8_t m[], size_t mlen,
            const uint8_t a[], size_t alen,
            const cipher_ctx_t* ctx)
{
    uint8_t tmp[2*BLOCKBYTES] = {0x00};
    uint8_t* y0 = tmp + 1*BLOCKBYTES;
    uint8_t* y1 = tmp + 0*BLOCKBYTES;
    uint8_t b = 0x00;

    if (mlen > BLOCKBYTES)
        return -1;
    if (nlen + alen > BLOCKBYTES - 1)
        return -1;

    // if |M|== n then b = 1, else b = 0
    b = (mlen == BLOCKBYTES) << 7;

    // compute round keys if online key expansion is required
    if (ctx->kexpand != NULL)
        ctx->kexpand(ctx->roundkeys, k);

    // Y0 <- E_K(padn(N||A||b0)) and Y1 <- E_K(padn(N||A||b1)) in parallel
    memcpy(tmp,        n, nlen);
    memcpy(tmp + nlen, a, alen);
    tmp[nlen + alen] = b | 0x20;
    memcpy(tmp + BLOCKBYTES, tmp, nlen + alen + 1);
    tmp[BLOCKBYTES + nlen + alen] |= 0x40;
    if (ctx->kexpand != NULL)
        ctx->encrypt(y0, y1, tmp, tmp + BLOCKBYTES, ctx->roundkeys);
    else
        ctx->encrypt(y0, y1, tmp, tmp + BLOCKBYTES, k);

    // C <- M ^ Y0 ^ Y1
    xor_bytes(c, y0, y1, mlen);
    xor_bytes(c,  c,  m, mlen);

    // T <- Y0 ^ pad(M)
    memset(tmp, 0x00, BLOCKBYTES);
    memcpy(tmp, m, mlen);
    if (mlen != BLOCKBYTES) {
        tmp[mlen] = 0x80;
    }
    xor_bytes(tmp, y0, tmp, BLOCKBYTES);

    // T = msb(E_K'(T))
    if (ctx->kexpand != NULL) {
        ctx->kexpand(ctx->roundkeys, k + KEYBYTES);
        ctx->encrypt(tmp, tmp, tmp, tmp, ctx->roundkeys);
    }
    else
        ctx->encrypt(tmp, tmp, tmp, tmp, k + ctx->rkeys_size);
    memcpy(c + mlen, tmp, TAGBYTES);

    *clen = mlen + TAGBYTES;
    return 0;
}


int cymric2_dec(uint8_t m[], size_t *mlen,
            const uint8_t k[],
            const uint8_t n[], size_t nlen,
            const uint8_t c[], size_t clen,
            const uint8_t a[], size_t alen,
            const cipher_ctx_t* ctx)
{
    uint8_t tmp[2*BLOCKBYTES] = {0x00};
    uint8_t* y0 = tmp + 1*BLOCKBYTES;
    uint8_t* y1 = tmp + 0*BLOCKBYTES;
    uint8_t b = 0x00;

    clen -= TAGBYTES;

    if (clen > BLOCKBYTES)
        return -1;
    if (nlen + alen > BLOCKBYTES - 1)
        return -1;

    // if |N|+|M|== n then b = 1, else b = 0
    b = (clen == BLOCKBYTES) << 7;

    // compute round keys if online key expansion is required
    if (ctx->kexpand != NULL)
        ctx->kexpand(ctx->roundkeys, k);

    // Y0 <- E_K(padn(N||A||b0)) and Y1 <- E_K(padn(N||A||b1)) in parallel
    memcpy(tmp,        n, nlen);
    memcpy(tmp + nlen, a, alen);
    tmp[nlen + alen] = b | 0x20;
    memcpy(tmp + BLOCKBYTES, tmp, nlen + alen + 1);
    tmp[BLOCKBYTES + nlen + alen] |= 0x40;
    if (ctx->kexpand != NULL)
        ctx->encrypt(y0, y1, tmp, tmp + BLOCKBYTES, ctx->roundkeys);
    else
        ctx->encrypt(y0, y1, tmp, tmp + BLOCKBYTES, k);

    // M <- C ^ Y0 ^ Y1
    xor_bytes(m, y0, y1, clen);
    xor_bytes(m,  m,  c, clen);

    // T <- Y0 ^ pad(M)
    memset(tmp, 0x00, BLOCKBYTES);
    memcpy(tmp, m, clen);
    if (clen != BLOCKBYTES) {
        tmp[clen] = 0x80;
    }
    xor_bytes(tmp, y0, tmp, BLOCKBYTES);

    // T <- msb(E_K'(T))
    if (ctx->kexpand != NULL) {
        ctx->kexpand(ctx->roundkeys, k + KEYBYTES);
        ctx->encrypt(tmp, tmp, tmp, tmp, ctx->roundkeys);
    }
    else
        ctx->encrypt(tmp, tmp, tmp, tmp, k + ctx->rkeys_size);

    // do not release plaintext if erroneous tag
    if (sec_memcmp(tmp, c + clen, TAGBYTES) != 0) {
        memset(m, 0x00, clen);
        *mlen = 0;
        return 1;
    }
    
    *mlen = clen;
    return 0;
}
