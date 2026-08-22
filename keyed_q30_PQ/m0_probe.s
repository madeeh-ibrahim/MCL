	.text
	.syntax unified
	.eabi_attribute	67, "2.09"	@ Tag_conformance
	.cpu	cortex-m0
	.eabi_attribute	6, 12	@ Tag_CPU_arch
	.eabi_attribute	7, 77	@ Tag_CPU_arch_profile
	.eabi_attribute	8, 0	@ Tag_ARM_ISA_use
	.eabi_attribute	9, 1	@ Tag_THUMB_ISA_use
	.eabi_attribute	34, 0	@ Tag_CPU_unaligned_access
	.eabi_attribute	17, 1	@ Tag_ABI_PCS_GOT_use
	.eabi_attribute	20, 1	@ Tag_ABI_FP_denormal
	.eabi_attribute	21, 0	@ Tag_ABI_FP_exceptions
	.eabi_attribute	23, 3	@ Tag_ABI_FP_number_model
	.eabi_attribute	24, 1	@ Tag_ABI_align_needed
	.eabi_attribute	25, 1	@ Tag_ABI_align_preserved
	.eabi_attribute	38, 1	@ Tag_ABI_FP_16bit_format
	.eabi_attribute	18, 4	@ Tag_ABI_PCS_wchar_t
	.eabi_attribute	26, 2	@ Tag_ABI_enum_size
	.eabi_attribute	14, 0	@ Tag_ABI_PCS_R9_use
	.file	"m0_codegen_probe.c"
	.globl	mcl_arg                         @ -- Begin function mcl_arg
	.p2align	1
	.type	mcl_arg,%function
	.code	16                              @ @mcl_arg
	.thumb_func
mcl_arg:
	.fnstart
@ %bb.0:
	.save	{r4, r6, r7, lr}
	push	{r4, r6, r7, lr}
	.setfp	r7, sp, #8
	add	r7, sp, #8
	mov	r1, r0
	mov	r0, r2
	mov	r2, r1
	bl	__aeabi_lmul
	mov	r4, r0
	ldr	r0, [r7, #16]
	ldr	r2, [r7, #8]
	bl	__aeabi_lmul
	subs	r0, r4, r0
	pop	{r4, r6, r7, pc}
.Lfunc_end0:
	.size	mcl_arg, .Lfunc_end0-mcl_arg
	.cantunwind
	.fnend
                                        @ -- End function
	.globl	mcl_arg_w32                     @ -- Begin function mcl_arg_w32
	.p2align	1
	.type	mcl_arg_w32,%function
	.code	16                              @ @mcl_arg_w32
	.thumb_func
mcl_arg_w32:
	.fnstart
@ %bb.0:
	muls	r2, r3, r2
	muls	r0, r1, r0
	subs	r0, r0, r2
	bx	lr
.Lfunc_end1:
	.size	mcl_arg_w32, .Lfunc_end1-mcl_arg_w32
	.cantunwind
	.fnend
                                        @ -- End function
	.globl	mcl_inc                         @ -- Begin function mcl_inc
	.p2align	1
	.type	mcl_inc,%function
	.code	16                              @ @mcl_inc
	.thumb_func
mcl_inc:
	.fnstart
@ %bb.0:
	.save	{r4, r6, r7, lr}
	push	{r4, r6, r7, lr}
	.setfp	r7, sp, #8
	add	r7, sp, #8
	mov	r3, r1
	mov	r4, r0
	asrs	r1, r2, #31
	mov	r0, r2
	mov	r2, r4
	bl	__aeabi_lmul
	lsls	r1, r1, #2
	lsrs	r0, r0, #30
	adds	r0, r0, r1
	pop	{r4, r6, r7, pc}
.Lfunc_end2:
	.size	mcl_inc, .Lfunc_end2-mcl_inc
	.cantunwind
	.fnend
                                        @ -- End function
	.globl	mcl_osc1                        @ -- Begin function mcl_osc1
	.p2align	1
	.type	mcl_osc1,%function
	.code	16                              @ @mcl_osc1
	.thumb_func
mcl_osc1:
	.fnstart
@ %bb.0:
	.save	{r4, r5, r6, r7, lr}
	push	{r4, r5, r6, r7, lr}
	.setfp	r7, sp, #12
	add	r7, sp, #12
	.pad	#4
	sub	sp, #4
	str	r0, [sp]                        @ 4-byte Spill
	ldr	r0, [r7, #68]
	asrs	r1, r0, #31
	ldr	r4, [r7, #56]
	ldr	r5, [r7, #60]
	mov	r2, r4
	mov	r3, r5
	bl	__aeabi_lmul
	lsls	r1, r1, #2
	lsrs	r0, r0, #30
	adds	r6, r0, r1
	ldr	r0, [r7, #64]
	asrs	r1, r0, #31
	mov	r2, r4
	mov	r3, r5
	bl	__aeabi_lmul
	lsls	r1, r1, #2
	lsrs	r0, r0, #30
	adds	r0, r0, r1
	ldr	r1, [r7, #76]
	ldr	r2, [sp]                        @ 4-byte Reload
	adds	r1, r1, r2
	adds	r0, r1, r0
	adds	r6, r0, r6
	ldr	r0, [r7, #72]
	asrs	r1, r0, #31
	mov	r2, r4
	mov	r3, r5
	bl	__aeabi_lmul
	lsls	r1, r1, #2
	lsrs	r0, r0, #30
	adds	r0, r0, r1
	adds	r0, r6, r0
	add	sp, #4
	pop	{r4, r5, r6, r7, pc}
.Lfunc_end3:
	.size	mcl_osc1, .Lfunc_end3-mcl_osc1
	.cantunwind
	.fnend
                                        @ -- End function
	.ident	"Apple clang version 16.0.0 (clang-1600.0.26.6)"
	.section	".note.GNU-stack","",%progbits
	.addrsig
	.eabi_attribute	30, 1	@ Tag_ABI_optimization_goals
