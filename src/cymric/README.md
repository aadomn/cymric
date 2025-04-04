# Generic implementations of Cymric1 and Cymric2 authenticated encryption modes

## General information

Our Manx implementations take as input parameters the functions related to the block cipher (i.e. key expansion and block encryption/decryption). This implies that the block cipher implementation should meet some requirements described below.
The round keys are pre-computed at the beginning of the mode so that they are not computed twice in case of two cipher calls. 
If for some reason the key expansion function of your favorite block cipher is not defined (e.g. it is computed on the fly during encryption/decryption), a possible workaround could be to define a dummy function that simply copies the key.
Also note that, since the Manx modes have been designed to process very short inputs, all the input lengths are expected to be specified in bit-length.

## Configuration parameters

In `manx-config.h` there are few preprocessor variables that can be adjusted to test different configurations:
- The maximum length of the additional data has to be defined by `MANX1_ALPHAMAX`/`MANX2_ALPHAMAX`.
- The length of the additional data can be fixed so that it is not necessary to pad it. This can be done by setting `MANX1_VARIABLE_ADLEN`/`MANX2_VARIABLE_ADLEN` to `0`.

## Requirements on the block cipher implementation

- The cipher implementation should come with a header named `block_cipher.h`.
- `block_cipher.h` should define the preprocessor variable `BLOCKBYTES` which refers to the block size in and bytes.
- `block_cipher.h` should define a structure `roundkeys_t` to store the round key material.
- The block cipher API should be compliant with the function types `kexp_func`, `enc_func` and `dec_func` defined in `manx.h`. Note that it is possible to move the precomputation of the round key material outside the Manx AE modes: passing the `kexp_func` input parameter as `NULL` treats the `k` input parameter as round keys directly.

## Hardcoding internal calls to the block cipher

If for some reason it is more convenient to not pass the block cipher functions as arguments, it should be simple to adapt the code in order to hardcode the calls to the cipher of your choice.
This is done in `manx-aes128/armv7m` for instance, where the AES API did not follow the requirements.
