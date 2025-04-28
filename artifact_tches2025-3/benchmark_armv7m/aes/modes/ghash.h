#ifndef GHASH_H_
#define GHASH_H_

void br_ghash_ctmul(void *y, const void *h, const void *data, size_t len);

#endif