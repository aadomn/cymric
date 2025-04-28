
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
 * ldi_w macro:
 *
 * Load immediate for 16-bit values
 */
.macro ldi_w reg:req, val:req
	ldi \reg, lo8(\val)
	ldi "(\reg+1)", hi8(\val)
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

.global lea128_kexpand
lea128_kexpand:
	; Save r2-r17,r28-r31
	push_registers 2,17
	push_registers 28,31
	push_registers 24,25
	; Save the argument pointers to Z (key) and X (round keys)
	movw XL, ARG1
	movw ZL, ARG2
	; Allocate 16 bytes on the stack and save pointer to Y
	in r28, 0x3d
	in r29, 0x3e
	sbiw r28, 16
	in r0, 0x3f
	cli
	out 0x3e, r29
	out 0x3f, r0
	out 0x3d, r28
.L__stack_usage = 42
	; Load the key given by argument to register 2-17 instead of 0-15 because
	; the mul instruction inconditionally overwrites registers r1:r0.
	.irp param,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11,r12,r13,r14,r15,r16,r17
	ld \param, Z+
	.endr
	; Save loop counter
	ldi r18, 24
	; Constants for efficient bitshifts
	ldi r19, 64
	ldi r20, 8
	; Save round constants to the stack
	ldi r22, lo8(0xf4ed)
	ldi r23, hi8(0xf4ed)
	ldi r24, lo8(0xe1f7)
	ldi r25, hi8(0xe1f7)
	std Y+0, r22
	std Y+1, r23
	std Y+2, r24
	std Y+3, r25
	ldi r22, lo8(0x6b02)
	ldi r23, hi8(0x6b02)
	ldi r24, lo8(0x4462)
	ldi r25, hi8(0x4462)
	std Y+4, r22
	std Y+5, r23
	std Y+6, r24
	std Y+7, r25
	ldi r22, lo8(0xf914)
	ldi r23, hi8(0xf914)
	ldi r24, lo8(0xf3c4)
	ldi r25, hi8(0xf3c4)
	std Y+8, r22
	std Y+9, r23
	std Y+10, r24
	std Y+11, r25
	ldi r22, lo8(0xc3b1)
	ldi r23, hi8(0xc3b1)
	ldi r24, lo8(0xe37c)
	ldi r25, hi8(0xe37c)
	std Y+12, r22
	std Y+13, r23
	std Y+14, r24
	std Y+15, r25
	loop_kexp:
		; Load round constant rc
		ldd r22, Y+0
		ldd r23, Y+1
		ldd r24, Y+2
		ldd r25, Y+3
		; First round key word
		; rc <<< 1
		bst  r25, 7
		rol  r22
		rol  r23
		rol  r24
		rol  r25
		bld  r22, 0
		; T[0] = T[0] + rc
		add r2, r22
		adc r3, r23
		adc r4, r24
		adc r5, r25
		; T[0] <<< 1
		bst  r5, 7
		rol  r2
		rol  r3
		rol  r4
		rol  r5
		bld  r2, 0
		; Second round key word
		; rc <<< 1
		bst  r25, 7
		rol  r22
		rol  r23
		rol  r24
		rol  r25
		bld  r22, 0
		; T[1] = T[1] + rc
		add r6, r22
		adc r7, r23
		adc r8, r24
		adc r9, r25
		; T[1] <<< 3
		mov  r30, r7
		mov  r31, r9
		mul  r6, r20
		movw r6, r0
		mul  r8, r20
		movw r8, r0
		mul  r30, r20
		eor  r7, r0
		eor  r8, r1
		mul  r31, r20
		eor  r9, r0
		eor  r6, r1
		; Third round key word
		; rc <<< 1
		bst  r25, 7
		rol  r22
		rol  r23
		rol  r24
		rol  r25
		bld  r22, 0
		; T[2] = T[2] + rc
		add r10, r22
		adc r11, r23
		adc r12, r24
		adc r13, r25
		; T[2] <<< 6
		mov  r30, r11
		mov  r31, r13
		mul  r10, r19
		movw r10, r0
		mul  r12, r19
		movw r12, r0
		mul  r30, r19
		eor  r11, r0
		eor  r12, r1
		mul  r31, r19
		eor  r13, r0
		eor  r10, r1
		; Fourth round key word
		; rc <<< 1
		bst  r25, 7
		rol  r22
		rol  r23
		rol  r24
		rol  r25
		bld  r22, 0
		; T[3] = T[3] + rc
		add r14, r22
		adc r15, r23
		adc r16, r24
		adc r17, r25
		; T[3] << 11
		mov  r30, r14
		mov  r14, r17
		mov  r17, r16
		mov  r16, r15
		mov  r15, r30
		mov  r31, r17
		mul  r14, r20
		movw r14, r0
		mul  r16, r20
		movw r16, r0
		mul  r30, r20
		eor  r15, r0
		eor  r16, r1
		mul  r31, r20
		eor  r17, r0
		eor  r14, r1
		; Store the round key
		st X+, r2
		st X+, r3
		st X+, r4
		st X+, r5
		st X+, r6
		st X+, r7
		st X+, r8
		st X+, r9
		st X+, r10
		st X+, r11
		st X+, r12
		st X+, r13
		st X+, r14
		st X+, r15
		st X+, r16
		st X+, r17
		; Store the updated round constant
		st Y+, r22
		st Y+, r23
		st Y+, r24
		st Y+, r25
		
		; Decrement loop counter
		subi r18, 1
		; If counter != 0 mod 4, no need to wrap round constant
		mov  r21, r18
		andi r21, 3
		cpi  r21, 0
		brne no_wrap_rc
		sbiw Y, 16
		no_wrap_rc:
		cpi  r18, 0
		breq exit_kexp
		rjmp loop_kexp
	exit_kexp:
	adiw r28, 16
	in r0, 0x3f
	cli
	out 0x3e, r29
	out 0x3f, r0
	out 0x3d, r28
	pop_registers 24,25
	; Restore r2-r19,r28-r31
	pop_registers 28,31
	pop_registers 2,17
	ret
	.size lea128_kexpand, .-lea128_kexpand

.global lea128_encrypt
lea128_encrypt:
	; Save r2-r17,r28-r29
	push_registers 2,17
	push_registers 28,29
	push_registers 24,25
.L__stack_usage = 20
	; Save the argument pointers to Z (key) and X (plaintext)
	movw XL, ARG2
	movw ZL, ARG3
	; Load the plaintext given by argument to register 2-17 instead of 0-15 because
	; the mul instruction inconditionally overwrites registers r1:r0.
	.irp param,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11,r12,r13,r14,r15,r16,r17
	ld \param, X+
	.endr
	ldi r18, 24
	ldi r19, 32
	ldi r20, 8
	loop:
		// save x[0]
		movw r22, r2
		movw r24, r4
		// x[0] ^= k[0]
		ld   r26, Z+
		ld   r27, Z+
		ld   r28, Z+
		ld   r29, Z+
		eor  r2, r26
		eor  r3, r27
		eor  r4, r28
		eor  r5, r29
		// x[0] += (x[1] ^ k[1])
		ld   r26, Z+
		ld   r27, Z+
		ld   r28, Z+
		ld   r29, Z+
		movw r0, r26
		eor  r0, r6
		eor  r1, r7
		add  r2, r0
		adc  r3, r1
		movw r0, r28
		eor  r0, r8
		eor  r1, r9
		adc  r4, r0
		adc  r5, r1
		// x[1] ^= k[2]
		ld   r0, Z+
		ld   r1, Z+
		eor  r6, r0
		eor  r7, r1
		ld   r0, Z+
		ld   r1, Z+
		eor  r8, r0
		eor  r9, r1
		// x[1] += (x[2] ^ k[3])
		movw r0, r26
		eor  r0, r10
		eor  r1, r11
		add  r6, r0
		adc  r7, r1
		movw r0, r28
		eor  r0, r12
		eor  r1, r13
		adc  r8, r0
		adc  r9, r1
		// x[3] ^= k[5]
		eor  r14, r26
		eor  r15, r27
		eor  r16, r28
		eor  r17, r29
		// x[2] ^= k[4]
		ld   r26, Z+
		ld   r27, Z+
		ld   r28, Z+
		ld   r29, Z+
		eor  r10, r26
		eor  r11, r27
		eor  r12, r28
		eor  r13, r29
		// x[2] += x[3]
		add  r10, r14
		adc  r11, r15
		adc  r12, r16
		adc  r13, r17
		// x[0] <<<= 9
		mov  r28, r5
		mov  r5, r4
		mov  r4, r3
		mov  r3, r2
		mov  r2, r28
		bst  r5, 7
		rol  r2
		rol  r3
		rol  r4
		rol  r5
		bld  r2, 0
		// x[1] <<<= 27
		mov  r28, r6
		mov  r6, r7
		mov  r7, r8
		mov  r8, r9
		mov  r9, r28
		mov  r29, r7
		mul  r6, r20
		movw r6, r0
		mul  r8, r20
		movw r8, r0
		mul  r29, r20
		eor  r7, r0
		eor  r8, r1
		mul  r28, r20
		eor  r9, r0
		eor  r6, r1
		// x[2] <<<= 29
		mov  r28, r10
		mov  r10, r11
		mov  r11, r12
		mov  r12, r13
		mov  r13, r28
		mov  r29, r11
		mul  r10, r19
		movw r10, r0
		mul  r12, r19
		movw r12, r0
		mul  r29, r19
		eor  r11, r0
		eor  r12, r1
		mul  r28, r19
		eor  r13, r0
		eor  r10, r1
		// x[3] = x[0]
		movw r14, r22
		movw r16, r24
		; Decrement loop counter
		subi r18, 1
		cpi  r18, 0
		breq exit
		rjmp loop
	exit:
	; Store output
	pop_registers 24,25
	movw YL, ARG1
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
	st Y+, r16
	st Y+, r17
	; Restore r2-r19,r28-r29
	pop_registers 28,29
	pop_registers 2,17
	ret
	.size lea128_encrypt, .-lea128_encrypt
