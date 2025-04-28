; Argument registers for function calls
#define ARG1 r24
#define ARG2 r22
#define ARG3 r20

/**
 * push_registers macro:
 *
 * Pushes a given range of registers in ascending order
 * To be called like: push_registers 0,15
 */
.macro push_registers from:req, to:req
  push \from
  .if \to-\from
    push_registers "(\from+1)",\to
  .endif
.endm

/**
 * pop_registers macro:
 *
 * Pops a given range of registers in descending order
 * To be called like: pop_registers 0,15
 */
.macro pop_registers from:req, to:req
  pop \to
  .if \to-\from
    pop_registers \from,"(\to-1)"
  .endif
.endm

/**
 * sbox macro:
 *
 * Computes the S-box layer in a bitsliced manner on a quarter of the state
 */
.macro sbox x0, x1, x2, x3
	mov r16, \x0
	and r16, \x2
	eor \x1, r16
	mov r16, \x1
	and r16, \x3
	eor \x0, r16
	mov r16, \x0
	or  r16, \x1
	eor \x2, r16
	eor \x3, \x2
	eor \x1, \x3
	com \x3
	mov r16, \x0
	and r16, \x1
	eor \x2, r16
.endm

/**
 * llayer1 macro:
 *
 * Computes the linear layer on a quarter of the state for the 1st round
 * within the quintuple round routine
 */
.macro llayer1 x1, x2, x3
	// NIBBLE_ROR2
	mov r16, \x1
	lsr r16
	lsr r16
	and r16, r17
	and \x1, r17
	lsl \x1
	lsl \x1
	or  \x1, r16
	// NIBBLE_ROR1
	mov r16, \x3
	lsr r16
	cbr r16, 136
	and \x3, r18
	lsl \x3
	lsl \x3
	lsl \x3
	or  \x3, r16
	//NIBBLE_ROR3
	mov r16, \x2
	lsr \x2
	lsr \x2
	lsr \x2
	and \x2, r18
	cbr r16, 136
	lsl r16
	or  \x2, r16
.endm

/**
 * half_ror_4 macro:
 *
 * Rotates a 16-bit word by 4 bits to the right.
 * Assumes r18 contains 0x0f.
 */
.macro half_ror_4 hi, lo
	swap \hi
	swap \lo
	movw r16, \hi
	cbr  r16, 15
	and  \hi, r18
	cbr  r17, 15
	and  \lo, r18
	or	 \hi, r17
	or   \lo, r16
.endm

/**
 * half_ror_12 macro:
 *
 * Rotates a 16-bit word by 12 bits to the right
 */
.macro half_ror_12 hi, lo
	swap \hi
	swap \lo
	movw r16, \hi
	cbr  r16, 240
	and  \hi, r18
	cbr  r17, 240
	and  \lo, r18
	or	 \hi, r17
	or   \lo, r16
.endm

/**
 * byte_ror_2 macro:
 *
 * Rotates a byte by 2 bits to the right
 */
.macro byte_ror_2 x
	bst		\x, 0
	lsr		\x
	bld     \x, 7
	bst		\x, 0
	lsr		\x
	bld     \x, 7
.endm

/**
 * byte_rol_2 macro:
 *
 * Rotates a byte by 2 bits to the left
 */
.macro byte_rol_2 x, zero
	lsl		\x
	adc		\x, \zero
	lsl		\x
	adc		\x, \zero
.endm

/**
 * add_round_key macro:
 *
 * Adds a round key to half of the state
 */
.macro add_round_key x0, x1, x2, x3, x4, x5, x6, x7
	ld   r16, X+
	ld   r17, X+
	eor	 \x0, r16
	eor  \x1, r17
	ld   r16, X+
	ld   r17, X+
	eor	 \x2, r16
	eor  \x3, r17
	ld   r16, X+
	ld   r17, X+
	eor	 \x4, r16
	eor  \x5, r17
	ld   r16, X+
	ld   r17, X+
	eor	 \x6, r16
	eor  \x7, r17
.endm

/**
 * add_rconst macro:
 *
 * Adds round constants to a quarter of the state
 */
.macro add_rconst x0, x1, x2, x3
	ld  r16, Z+
	ld  r17, Z+
	eor \x0, r16
	eor \x1, r17
	ld  r16, Z+
	ld  r17, Z+
	eor \x2, r16
	eor \x3, r17
.endm

/**
 * add_rconst0 macro:
 *
 * Same as add_rconst but w/ a specificity for rounds r s.t.
 * r = 0 mod 5: the last rconst byte is always 0x10 so we hardcode it 
 */
.macro add_rconst0 x0, x1, x2, x3
	ld  r16, Z+
	ld  r17, Z+
	eor \x0, r16
	eor \x1, r17
	ld  r16, Z+
	ldi r17, 16
	eor \x2, r16
	eor \x3, r17
.endm

/**
 * add_rconst1 macro:
 *
 * Same as add_rconst but w/ a specificity for rounds r s.t.
 * r = 1 mod 5: the 1st and 3rd rconst bytes are always 0x00 and 0x01
 * respectively so we hardcode them 
 */
.macro add_rconst1 x1, x2, x3
	ld  r16, Z+
	ldi  r17, 1
	eor \x1, r16
	eor \x2, r17
	ld  r16, Z+
	eor \x3, r16
.endm

/**
 * add_rconst2 macro:
 *
 * Same as add_rconst but w/ a specificity for rounds r s.t.
 * r = 2 mod 5: the first two bytes are always 0x02 and 0x00
 * respectively so we hardcode them 
 */
.macro add_rconst2 x0, x2, x3
	ldi  r16, 2
	ld  r17, Z+
	eor \x0, r16
	eor \x2, r17
	ld  r16, Z+
	eor \x3, r16
.endm

/**
 * llayer3 macro:
 *
 * Computes the linear layer on a quarter of the state for the 3rd round
 * within the quintuple round routine
 */
.macro llayer3 x1, x2
	movw r16, \x1
	movw r28, \x1
	lsr  r28
	lsr  r29
	eor  r16, r28
	eor  r17, r29
	andi r16, 85
	andi r17, 85
	eor  \x1, r16
	eor  \x2, r17
	lsl  r16
	lsl  r17
	eor  \x1, r16
	eor  \x2, r17
.endm

.macro kexp_round k0, k1, k2, k3
	; k0||k1 >>> 2
	bst  \k1, 0
	ror  \k0
	ror  \k1
	bld  \k0, 7
	bst  \k1, 0
	ror  \k0
	ror  \k1
	bld  \k0, 7
	; k2||k3 <<< 4
	mov  r30, \k3
	mul  \k2, r20
	mov  \k2, r1
	mov  \k3, r0
	mul  r30, r20
	or   \k2, r0
	or   \k3, r1
	eor  \k2, \k3
	eor  \k3, \k2
	eor  \k2, \k3
.endm

.macro rearrange_rkey0 a, b, c, d
	mov r22, \a
	mov r23, \b
	mov r24, \c
	mov r25, \d
	// SWAPMOVE(x, x, 0x00550055, 9) : x & 550055 <-> x & aa00aa00
	mov  r28, \a
	mov  r30, \c
	lsr  r28
	lsr  r30
	eor  r28, \b
	eor  r30, \d
	andi r28, 85
	andi r30, 85
	eor  r23, r28
	eor  r25, r30
	lsl  r28
	lsl  r30
	eor  r22, r28
	eor  r24, r30
	// SWAPMOVE(x, x, 0x000f000f, 12) : x & 000f000f <-> x & f000f000
	movw r28, r22
	mov  r30, r24
	mov  r31, r25
	swap r28
	swap r29
	swap r30
	swap r31
	andi r28, 15
	andi r29, 240
	andi r30, 15
	andi r31, 240
	and r22, r19
	and r23, r18
	and r24, r19
	and r25, r18
	or  r22, r29
	or  r23, r28
	or  r24, r31
	or  r25, r30
	// SWAPMOVE(x, x, 0x00003333, 18) : x & 00003333 <-> x & cccc0000
	movw r30, r22
	lsr  r30
	lsr  r30
	lsr  r31
	lsr  r31
	eor  r30, r24
	eor  r31, r25
	andi r30, 51
	andi r31, 51
	eor  r24, r30
	eor  r25, r31
	lsl  r30
	lsl  r30
	lsl  r31
	lsl  r31
	eor  r22, r30
	eor  r23, r31
	// SWAPMOVE(x, x, 0x000000ff, 24)
	st X+, r22
	st X+, r24
	st X+, r23
	st X+, r25
.endm

.macro swap_4bits reg, tmp, src0, dst0, src1, dst1
	mov \tmp, \reg
	bst \reg, \src0
	bld \reg, \dst0
	bst \reg, \src1
	bld \reg, \dst1
	bst \tmp, \dst0
	bld \reg, \src0
	bst \tmp, \dst1
	bld \reg, \src1
.endm

.macro rearrange_rkey1 a, b, c, d
	mov r22, \a
	mov r23, \b
	mov r24, \c
	mov r25, \d
	// SWAPMOVE(x, x, 0x11111111, 3) : x & 11111111 <-> x & 88888888
	swap_4bits r22, r28, 0, 3, 4, 7
	swap_4bits r23, r28, 0, 3, 4, 7
	swap_4bits r24, r28, 0, 3, 4, 7
	swap_4bits r25, r28, 0, 3, 4, 7
	// SWAPMOVE(x, x, 0x03030303, 6) :  x & 03030303 <-> x & c0c0c0c0
	swap_4bits r22, r28, 0, 6, 1, 7
	swap_4bits r23, r28, 0, 6, 1, 7
	swap_4bits r24, r28, 0, 6, 1, 7
	swap_4bits r25, r28, 0, 6, 1, 7
	// SWAPMOVE(x, x, 0x000f000f, 12) : x & 000f000f <-> x & f000f000
	movw r28, r22
	mov  r30, r24
	mov  r31, r25
	swap r28
	swap r29
	swap r30
	swap r31
	andi r28, 15
	andi r29, 240
	andi r30, 15
	andi r31, 240
	and r22, r19
	and r23, r18
	and r24, r19
	and r25, r18
	or  r22, r29
	or  r23, r28
	or  r24, r31
	or  r25, r30
	// SWAPMOVE(x, x, 0x000000ff, 24)
	st X+, r22
	st X+, r24
	st X+, r23
	st X+, r25
.endm

.macro rearrange_rkey2 a, b, c, d
	mov r22, \a
	mov r23, \b
	mov r24, \c
	mov r25, \d
	// SWAPMOVE(x, x, 0x0000aaaa, 15) : x & 0000aaaa <-> x & 
	movw r28, \a
	lsl  r29
	lsl  r28
	eor  r28, \c
	eor  r29, \d
	andi r28, 170
	andi r29, 170
	eor  r24, r28
	eor  r25, r29
	lsr r28
	lsr r29
	eor  r22, r28
	eor  r23, r29
	// SWAPMOVE(x, x, 0x00003333, 18) : x & 00003333 <-> x & cccc0000
	movw r30, r22
	lsr  r30
	lsr  r30
	lsr  r31
	lsr  r31
	eor  r30, r24
	eor  r31, r25
	andi r30, 51
	andi r31, 51
	eor  r24, r30
	eor  r25, r31
	lsl  r30
	lsl  r30
	lsl  r31
	lsl  r31
	eor  r22, r30
	eor  r23, r31
	// SWAPMOVE(x, x, 0x0000f0f0, 12) : x & 000f000f <-> x & f000f000
	movw r28, r22
	movw r30, r24
	swap r28
	swap r29
	swap r30
	swap r31
	andi r28, 240
	andi r29, 240
	andi r30, 15
	andi r31, 15
	and r22, r18
	and r23, r18
	and r24, r19
	and r25, r19
	or  r22, r30
	or  r23, r31
	or  r24, r28
	or  r25, r29
	// SWAPMOVE(x, x, 0x000000ff, 24)
	st X+, r22
	st X+, r24
	st X+, r23
	st X+, r25
.endm

.macro rearrange_rkey3 a, b, c, d
	mov r22, \a
	mov r23, \b
	mov r24, \c
	mov r25, \d
	// SWAPMOVE(x, x, 0x0a0a0a0a, 3) : x & 11111111 <-> x & 88888888
	swap_4bits r22, r28, 1, 4, 3, 6
	swap_4bits r23, r28, 1, 4, 3, 6
	swap_4bits r24, r28, 1, 4, 3, 6
	swap_4bits r25, r28, 1, 4, 3, 6
	// SWAPMOVE
	mov  r28, r22
	mov  r30, r24
	lsl  r28
	lsl  r28
	lsl  r30
	lsl  r30
	eor  r28, r23
	eor  r30, r25
	andi r28, 204
	andi r30, 204
	eor  r23, r28
	eor  r25, r30
	lsr  r28
	lsr  r28
	lsr  r30
	lsr  r30
	eor  r22, r28
	eor  r24, r30
	// SWAPMOVE(x, x, 0x0000f0f0, 12) : x & 000f000f <-> x & f000f000
	movw r28, r22
	movw r30, r24
	swap r28
	swap r29
	swap r30
	swap r31
	andi r28, 240
	andi r29, 240
	andi r30, 15
	andi r31, 15
	and r22, r18
	and r23, r18
	and r24, r19
	and r25, r19
	or  r22, r30
	or  r23, r31
	or  r24, r28
	or  r25, r29
	// SWAPMOVE(x, x, 0x000000ff, 24)
	st X+, r22
	st X+, r24
	st X+, r23
	st X+, r25
.endm

.macro swap_bytes x, y
	eor \x, \y
	eor \y, \x
	eor \x, \y
.endm

.global gift128_kexpand
gift128_kexpand:
	; Save r2-r17,r28-r31
	push_registers 2,17
	push_registers 28,31
	push_registers 24,25
.L__stack_usage = 22
	; Save the argument pointers to Z (key) and X (round keys)
	movw XL, ARG1
	movw YL, ARG2
	; Load the key given by argument to register 2-17 instead of 0-15 because
	; the mul instruction inconditionally overwrites registers r1:r0.
	.irp param,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11,r12,r13,r14,r15,r16,r17
	ld \param, Y+
	.endr
	; Constants for efficient bitshifts
	ldi r18, 240
	ldi r19, 15
	ldi r20, 16
	rearrange_rkey0 r14, r15, r16, r17
	rearrange_rkey0 r6, r7, r8, r9
	rearrange_rkey1 r10, r11, r12, r13
	rearrange_rkey1 r2, r3, r4, r5
	rearrange_rkey2 r6, r7, r8, r9
	kexp_round		r14, r15, r16, r17
	rearrange_rkey2 r14, r15, r16, r17
	rearrange_rkey3 r2, r3, r4, r5
	kexp_round		r10, r11, r12, r13
	rearrange_rkey3 r10, r11, r12, r13
	st X+, r17
	st X+, r16
	st X+, r15
	st X+, r14
	kexp_round		r6, r7, r8, r9
	st X+, r9
	st X+, r8
	st X+, r7
	st X+, r6
	; Save loop counter
	ldi r21, 7
	kexp_loop:
		cpi r21, 4
		brne skip_swap_start
		swap_bytes r10, r2
		swap_bytes r11, r3
		swap_bytes r12, r4
		swap_bytes r13, r5
		skip_swap_start:
		rearrange_rkey0 r10, r11, r12, r13
		kexp_round		r2, r3, r4, r5
		rearrange_rkey0 r2, r3, r4, r5
		rearrange_rkey1 r6, r7, r8, r9
		kexp_round		r14, r15, r16, r17
		rearrange_rkey1 r14, r15, r16, r17
		rearrange_rkey2 r2, r3, r4, r5
		kexp_round		r10, r11, r12, r13
		rearrange_rkey2 r10, r11, r12, r13
		rearrange_rkey3 r14, r15, r16, r17
		kexp_round		r6, r7, r8, r9
		rearrange_rkey3 r6, r7, r8, r9
		st X+, r13
		st X+, r12
		st X+, r11
		st X+, r10
		kexp_round		r2, r3, r4, r5
		st X+, r5
		st X+, r4
		st X+, r3
		st X+, r2
		swap_bytes r10, r14
		swap_bytes r11, r15
		swap_bytes r12, r16
		swap_bytes r13, r17
		swap_bytes r2,  r6
		swap_bytes r3,  r7
		swap_bytes r4,  r8
		swap_bytes r5,  r9
		cpi r21, 4
		brne skip_swap_end
		swap_bytes r10, r2
		swap_bytes r11, r3
		swap_bytes r12, r4
		swap_bytes r13, r5
		skip_swap_end:
		// decrement loop counter
		subi r21, 1
		cpi  r21, 0
		breq kexp_exit
		rjmp kexp_loop
	kexp_exit:
	; Restore r2-r19,r28-r29
	pop_registers 24,25
	pop_registers 28,31
	pop_registers 2,17
	ret
	.size gift128_kexpand, .-gift128_kexpand


.global gift128_encrypt
gift128_encrypt:
	; Save r2-r17,r28-r29
	push_registers 2,17
	push_registers 28,29
.L__stack_usage = 18
	; Save the argument pointers to Z (key) and X (plaintext)
	movw XL, ARG2
	; Load the plaintext given by argument to register 2-17 instead of 0-15 because
	; the mul instruction inconditionally overwrites registers r1:r0.
	.irp param,r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11,r12,r13,r14,r15
	ld \param, X+
	.endr
	
	ldi ZL, lo8(rconst)
	ldi ZH, hi8(rconst)
	movw XL, ARG3
	// for byte_rol_2
	ldi r20, 0
	// Save loop counter
	ldi r19, 8
	quintuple_round:
		// 1st_round
		sbox r0, r4, r8,  r12
		sbox r1, r5, r9,  r13
		sbox r2, r6, r10, r14
		sbox r3, r7, r11, r15
		ldi r17, 51
		ldi r18, 17
		llayer1 r4, r8,  r12
		llayer1 r5, r9,  r13
		llayer1 r6, r10, r14
		llayer1 r7, r11, r15
		add_round_key	r4, r5, r6, r7, r8, r9, r10, r11
		add_rconst0		r0, r1, r2, r3
		// 2nd round
		sbox r12, r4, r8,  r0
		sbox r13, r5, r9,  r1
		sbox r14, r6, r10, r2
		sbox r15, r7, r11, r3
		subi r18, 2
		half_ror_4  r0,  r1
		half_ror_4  r2,  r3
		ldi r18, 240
		half_ror_12  r8,  r9
		half_ror_12  r10, r11
		add_round_key	r5, r4, r7, r6, r8, r9, r10, r11
		add_rconst1		r13, r14, r15
		// 3rd round
		sbox r0, r5, r8,  r12
		sbox r1, r4, r9,  r13
		sbox r2, r7, r10, r14
		sbox r3, r6, r11, r15
		llayer3 r4, r5
		llayer3 r6, r7
		llayer3 r10, r11
		llayer3 r12, r13
		add_round_key	r5, r4, r7, r6, r10, r11, r8, r9
		add_rconst2		r0, r2, r3
		// 4th round
		sbox r14, r5, r10, r0
		sbox r15, r4, r11, r1
		sbox r12, r7, r8,  r2
		sbox r13, r6, r9,  r3
		// byte_ror_6
		byte_rol_2 r0, r20
		byte_rol_2 r1, r20
		byte_rol_2 r2, r20
		byte_rol_2 r3, r20
		// byte_ror_4
		swap	r4
		swap	r5
		swap	r6
		swap	r7
		// byte_ror_2
		byte_ror_2 r8
		byte_ror_2 r9
		byte_ror_2 r10
		byte_ror_2 r11
		add_round_key	r5, r4, r7, r6, r10, r11, r8, r9
		add_rconst		r14, r15, r12, r13
		// 5th round
		sbox r0, r5, r10, r14
		sbox r1, r4, r11, r15
		sbox r2, r7, r8,  r12
		sbox r3, r6, r9,  r13
		// swap state[0] w/ ROR(state[3], 24)
		movw r16, r0
		mov r0, r13
		mov r1, r14
		mov r13, r17
		mov r14, r2
		mov r17, r3
		mov r2, r15
		mov r3, r12
		mov r15, r17
		mov r12, r16
		// state[1] = ROR(state[1], 16)
		movw r16, r4
		mov r4, r7
		mov r7, r16
		mov r5, r6
		mov r6, r17
		// state[2] = ROR(state[2], 8)
		movw  r16, r10
		mov  r10, r9
		mov  r9, r8
		mov  r8, r17
		mov  r11, r16
		add_round_key	r4, r5, r6, r7, r8, r9, r10, r11
		// last rconst is always formed as 800000xx
		ld	 r16, Z+
		eor	 r12, r16
		ldi  r16, 128
		eor  r15, r16
		// decrement loop counter
		subi r19, 1
		cpi  r19, 0
		breq exit
		rjmp quintuple_round
	exit:
	; Store output
	movw YL, ARG1
	st Y+, r0
	st Y+, r1
	st Y+, r2
	st Y+, r3
	st Y+, r4
	st Y+, r5
	st Y+, r6
	st Y+, r7
	st Y+, r8
	st Y+, r9
	st Y+, r10
	st Y+, r11
	st Y+, r12
	st Y+, r13
	st Y+, r14
	st Y+, r15
	; Restore r2-r19,r28-r29
	pop_registers 28,29
	pop_registers 2,17
	ret
	.size gift128_encrypt, .-gift128_encrypt

.data
rconst:
.byte 0x08, 0x00, 0x00, 0x80, 0x80, 0x00, 0x54, 0x81, 0x01, 0x01, 0x01, 0x1f
.byte 0x80, 0x88, 0x88, 0xe0, 0x60, 0x50, 0x51, 0x80, 0x01, 0x03, 0x03, 0x2f
.byte 0x80, 0x88, 0x08, 0x60, 0x60, 0x50, 0x41, 0x80, 0x00, 0x03, 0x03, 0x27
.byte 0x80, 0x88, 0x00, 0xe0, 0x40, 0x50, 0x11, 0x80, 0x01, 0x02, 0x03, 0x2b
.byte 0x80, 0x08, 0x08, 0x40, 0x60, 0x40, 0x01, 0x80, 0x00, 0x02, 0x02, 0x21
.byte 0x80, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x51, 0x80, 0x01, 0x01, 0x03, 0x2e
.byte 0x00, 0x88, 0x08, 0x20, 0x60, 0x50, 0x40, 0x80, 0x00, 0x03, 0x01, 0x06
.byte 0x08, 0x88, 0x00, 0xa0, 0xc0, 0x50, 0x14, 0x81, 0x01, 0x02, 0x01, 0x1a
/*
.byte 0x08, 0x00, 0x00, 0x10, 0x00, 0x80, 0x01, 0x80, 0x02, 0x00, 0x00, 0x54, 0x81, 0x01, 0x01, 0x01, 0x1f, 0x00, 0x00, 0x80
.byte 0x80, 0x88, 0x88, 0x10, 0x00, 0xe0, 0x01, 0x60, 0x02, 0x00, 0x50, 0x51, 0x80, 0x01, 0x03, 0x03, 0x2f, 0x00, 0x00, 0x80
.byte 0x80, 0x88, 0x08, 0x10, 0x00, 0x60, 0x01, 0x60, 0x02, 0x00, 0x50, 0x41, 0x80, 0x00, 0x03, 0x03, 0x27, 0x00, 0x00, 0x80
.byte 0x80, 0x88, 0x00, 0x10, 0x00, 0xe0, 0x01, 0x40, 0x02, 0x00, 0x50, 0x11, 0x80, 0x01, 0x02, 0x03, 0x2b, 0x00, 0x00, 0x80
.byte 0x80, 0x08, 0x08, 0x10, 0x00, 0x40, 0x01, 0x60, 0x02, 0x00, 0x40, 0x01, 0x80, 0x00, 0x02, 0x02, 0x21, 0x00, 0x00, 0x80
.byte 0x80, 0x00, 0x00, 0x10, 0x00, 0xc0, 0x01, 0x00, 0x02, 0x00, 0x00, 0x51, 0x80, 0x01, 0x01, 0x03, 0x2e, 0x00, 0x00, 0x80
.byte 0x00, 0x88, 0x08, 0x10, 0x00, 0x20, 0x01, 0x60, 0x02, 0x00, 0x50, 0x40, 0x80, 0x00, 0x03, 0x01, 0x06, 0x00, 0x00, 0x80
.byte 0x08, 0x88, 0x00, 0x10, 0x00, 0xa0, 0x01, 0xc0, 0x02, 0x00, 0x50, 0x14, 0x81, 0x01, 0x02, 0x01, 0x1a, 0x00, 0x00, 0x80
*/
