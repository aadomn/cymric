/****************************************************************************
* ARMv7M assembly implementation of the LEA-128 block cipher where key 
* expansion is performed on-the-fly.
* @author   Alexandre Adomnicai
* @date     April 2025
****************************************************************************/
.syntax unified
.thumb

k   .req r2
x   .req r1

// key
k0  .req r0
k1  .req r1
k2  .req r3
k3  .req r4 

// data
x0  .req r5
x1  .req r6
x2  .req r7
x3  .req r8

// constants
g0  .req r9
g1  .req r10
g2  .req r11
g3  .req r12

.macro lea_round rconst
  // calculate round keys on-the-fly
  add     k0, \rconst, k0, ror #31
  add     k1, k1, \rconst, ror #31
  ror     k1, #29
  add     k2, k2, \rconst, ror #30
  ror     k2, #26
  add     k3, k3, \rconst, ror #29
  ror     k3, #21
  // save x0  
  ror     lr, x0, #23
  // x0 = ROTR32((x0 ^ k0) + (x1 ^ k1),23);
  eor     r2, k1, x1, ror #5
  eor     x0, x0, k0, ror #8
  add     x0, r2, x0, ror #23
  // x1 = ROTR32((x1 ^ k2) + (x2 ^ k1), 5);
  eor     r2, k1, x2, ror #3
  eor     x1, k2, x1, ror #5
  add     x1, r2
  // x2 = ROTR32((x2 ^ k3) + (x3 ^ k1), 3);
  eor     r2, x3, k1
  eor     x2, k3, x2, ror #3
  add     x2, r2
  // x3 = x0;
  mov     x3, lr
  ror     \rconst, #28
.endm

lea_quadruple_round:
  push  {lr}
  lea_round g0
  lea_round g1
  lea_round g2
  lea_round g3
  pop   {lr}
  bx    lr
  .size lea_quadruple_round, .-lea_quadruple_round

.global lea128_encrypt
.type   lea128_encrypt,%function
.align 4
lea128_encrypt:
  // save registers
  push    {r0-r12, lr}
  // load rconsts
  movw    g0, #0xe9db
  movt    g0, #0xc3ef
  movw    g1, #0xd604
  movt    g1, #0x88c4
  movw    g2, #0xf229
  movt    g2, #0xe789
  movw    g3, #0x8763
  movt    g3, #0xc6f9
  // load ptext
  ldr.w   x0, [x, #0]
  ldr.w   x1, [x, #4]
  ldr.w   x2, [x, #8]
  ldr.w   x3, [x, #12] 
  // load key
  ldr.w   k0, [k, #0]
  ldr.w   k1, [k, #4]
  ldr.w   k2, [k, #8]
  ldr.w   k3, [k, #12]
  // rotations to match lea_round alignments
  ror     k0, #1
  ror     x0, #9
  ror     x1, #27
  ror     x2, #29
  // perform encryption  
  bl      lea_quadruple_round
  bl      lea_quadruple_round
  bl      lea_quadruple_round
  bl      lea_quadruple_round
  bl      lea_quadruple_round
  bl      lea_quadruple_round
  // save 128-bit cipher text
  ldr.w   r0, [sp], #4
  ror     x0, #23
  ror     x1, #5
  ror     x2, #3
  str.w   x0, [r0, #0]
  str.w   x1, [r0, #4]
  str.w   x2, [r0, #8]
  str.w   x3, [r0, #12]
  // restore registers
  pop     {r1-r12, lr}
  bx      lr
  .size lea128_encrypt, .-lea128_encrypt
