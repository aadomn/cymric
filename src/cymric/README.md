# Generic implementations of Cymric1 and Cymric2

## Guidelines
The Cymric implementations provided in this repository are cipher-agnostic and can be plugged with any block cipher by meeting the following requirements:
- The encryption function must be compliant with the function prototype `void (*encrypt)(uint8_t* ctext, const uint8_t* ptext, const void* rkeys);` defined in `cipher_ctx.h`.
- If there is a need for a key expansion function, then it must be compliant with the function prototype `void (*kexpand)(void* rkeys, const uint8_t* key);`  defined in `cipher_ctx.h`.
- It is recommended to implement a `get_cipher_ctx` function to easily instantiate a cipher context to be passed as input argument to the Cymric encryption/decryption functions.

Still, the implementations provided in this repository assume a 128-bit block cipher with a 128-bit key by defining `BLOCKBYTES` and `TAGBYTES` to `16` in `cymric.h`.
If you want to plug a block cipher with different characteristics, you must adapt these preprocessor variables to your needs.

See the provided instantiations (e.g., `cymric-aes128/x86_64`) as examples.

## Skipping key expansion

Note that the `cipher_ctx_t.kexpand` structure field can be set as `NULL` if one wants to use pre-computed round keys or if the encryption function does not require external key-related calculations (e.g., it computes the round keys on-the-fly). In that case, all the key material must be stored in the encryption key passed as argument to the Cymric functions and the `cipher_ctx_t.rkeys_size` structure field must be set appropriately to point to the second key material for the final encryption call.


