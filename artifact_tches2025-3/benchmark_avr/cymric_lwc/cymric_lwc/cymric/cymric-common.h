#ifndef CYMRIC_COMMON_H
#define CYMRIC_COMMON_H

static inline void xor_bytes(
    uint8_t*        a,
    const uint8_t*  b,
    const uint8_t*  c,
    size_t        len)
{
    for(unsigned int i = 0; i < len; i++)
        a[i] = b[i] ^ c[i];
}

/**
 * @brief Constant-time comparison between two byte arrays for a given number of bytes.
 * 
 * @param x The first byte array
 * @param y The second byte array
 * @param len  The number of bytes taken into account for the comparison
 * 
 * @return 0 if the two arrays are equal, non-zero value otherwise
 */
static inline int sec_memcmp(const uint8_t *x, const uint8_t *y, size_t len)
{
    size_t    i = 0;
    uint8_t ret = 0x00; 

    while(len) {
        ret |= x[i] ^ y[i];
        len--;
        i++;
    }

    return ret;
}

#endif
