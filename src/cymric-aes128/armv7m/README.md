# Cymric instantiated with AES-128 on ARMv7M

## Leveraging parallelization capabilities
Contrary to the code under the `x86_64` and `avr8` repositories where Cymric processes all block cipher calls in a serial manner, here Cymric modes differ by leveraging the parallelization capabilities of the underlying AES implementation.
Indeed, because the optimized bitsliced (or fixsliced) AES implementation considered on ARMv7M can process two blocks at a time, Cymric is adjusted to take advantage of it by computing the first two block cipher calls in parallel.
