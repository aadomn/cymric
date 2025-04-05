#ifndef CIPHER_CTX_H
#define CIPHER_CTX_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    void* roundkeys;
    void (*encrypt)(uint8_t*, const uint8_t*, const void*);
    void (*kexpand)(void*, const uint8_t*);  // Can be NULL for precomputed keys
    size_t rkeys_size;
} cipher_ctx_t;

#endif /* CIPHER_CTX_H */