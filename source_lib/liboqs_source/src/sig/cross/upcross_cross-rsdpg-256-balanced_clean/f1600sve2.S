
.macro round
    // -----------------------------------------------------------------
    // Theta Step
    // -----------------------------------------------------------------
    movprfx z25, z0
    eor3    z25.d, z25.d, z5.d, z10.d
    movprfx z26, z1
    eor3    z26.d, z26.d, z6.d, z11.d
    movprfx z27, z2
    eor3    z27.d, z27.d, z7.d, z12.d
    movprfx z28, z3
    eor3    z28.d, z28.d, z8.d, z13.d
    movprfx z29, z4
    eor3    z29.d, z29.d, z9.d, z14.d

    eor3    z25.d, z25.d, z15.d, z20.d
    eor3    z26.d, z26.d, z16.d, z21.d
    eor3    z27.d, z27.d, z17.d, z22.d
    eor3    z28.d, z28.d, z18.d, z23.d
    eor3    z29.d, z29.d, z19.d, z24.d

    // D calculations (using movprfx where possible, z31 as temp where needed)
    mov     z30.d, z29.d
    rax1    z30.d, z30.d, z26.d                 // D[0]

    mov     z31.d, z27.d
    rax1    z31.d, z31.d, z29.d
    mov     z29.d, z31.d                        // D[3]

    mov     z31.d, z25.d
    rax1    z31.d, z31.d, z27.d
    mov     z27.d, z31.d                        // D[1]

    mov     z31.d, z28.d
    rax1    z31.d, z31.d, z25.d
    mov     z25.d, z31.d                        // D[4]

    mov     z31.d, z26.d
    rax1    z31.d, z31.d, z28.d
    mov     z28.d, z31.d                        // D[2]

    // Apply D[0] (the only explicit Theta update; others are folded into Rho/Pi)
    eor     z0.d, z0.d, z30.d

    // -----------------------------------------------------------------
    // Rho and Pi (replaced mov + destructive with movprfx + destructive)
    // -----------------------------------------------------------------
    mov     z31.d, z1.d                         // save original z1 for final step

    movprfx z1,  z6
    xar     z1.d,  z1.d,  z27.d, #20
    movprfx z6,  z9
    xar     z6.d,  z6.d,  z25.d, #44
    movprfx z9,  z22
    xar     z9.d,  z9.d,  z28.d, #3
    movprfx z22, z14
    xar     z22.d, z22.d, z25.d, #25
    movprfx z14, z20
    xar     z14.d, z14.d, z30.d, #46
    movprfx z20, z2
    xar     z20.d, z20.d, z28.d, #2
    movprfx z2,  z12
    xar     z2.d,  z2.d,  z28.d, #21
    movprfx z12, z13
    xar     z12.d, z12.d, z29.d, #39
    movprfx z13, z19
    xar     z13.d, z13.d, z25.d, #56
    movprfx z19, z23
    xar     z19.d, z19.d, z29.d, #8
    movprfx z23, z15
    xar     z23.d, z23.d, z30.d, #23
    movprfx z15, z4
    xar     z15.d, z15.d, z25.d, #37
    movprfx z4,  z24
    xar     z4.d,  z4.d,  z25.d, #50
    movprfx z24, z21
    xar     z24.d, z24.d, z27.d, #62
    movprfx z21, z8
    xar     z21.d, z21.d, z29.d, #9
    movprfx z8,  z16
    xar     z8.d,  z8.d,  z27.d, #19
    movprfx z16, z5
    xar     z16.d, z16.d, z30.d, #28
    movprfx z5,  z3
    xar     z5.d,  z5.d,  z29.d, #36
    movprfx z3,  z18
    xar     z3.d,  z3.d,  z29.d, #43
    movprfx z18, z17
    xar     z18.d, z18.d, z28.d, #49
    movprfx z17, z11
    xar     z17.d, z17.d, z27.d, #54
    movprfx z11, z7
    xar     z11.d, z11.d, z28.d, #58
    movprfx z7,  z10
    xar     z7.d,  z7.d,  z30.d, #61
    movprfx z10, z31
    xar     z10.d, z10.d, z27.d, #63

    // -----------------------------------------------------------------
    // Chi Step (replaced mov + bcax with movprfx + bcax for temps)
    // -----------------------------------------------------------------
    movprfx z25, z0
    bcax    z25.d, z25.d, z2.d, z1.d
    movprfx z26, z1
    bcax    z26.d, z26.d, z3.d, z2.d
    bcax    z2.d,  z2.d,  z4.d, z3.d
    bcax    z3.d,  z3.d,  z0.d, z4.d
    bcax    z4.d,  z4.d,  z1.d, z0.d
    mov     z0.d, z25.d
    mov     z1.d, z26.d

    movprfx z25, z5
    bcax    z25.d, z25.d, z7.d, z6.d
    movprfx z26, z6
    bcax    z26.d, z26.d, z8.d, z7.d
    bcax    z7.d,  z7.d,  z9.d, z8.d
    bcax    z8.d,  z8.d,  z5.d, z9.d
    bcax    z9.d,  z9.d,  z6.d, z5.d
    mov     z5.d, z25.d
    mov     z6.d, z26.d

    movprfx z25, z10
    bcax    z25.d, z25.d, z12.d, z11.d
    movprfx z26, z11
    bcax    z26.d, z26.d, z13.d, z12.d
    bcax    z12.d, z12.d, z14.d, z13.d
    bcax    z13.d, z13.d, z10.d, z14.d
    bcax    z14.d, z14.d, z11.d, z10.d
    mov     z10.d, z25.d
    mov     z11.d, z26.d

    movprfx z25, z15
    bcax    z25.d, z25.d, z17.d, z16.d
    movprfx z26, z16
    bcax    z26.d, z26.d, z18.d, z17.d
    bcax    z17.d, z17.d, z19.d, z18.d
    bcax    z18.d, z18.d, z15.d, z19.d
    bcax    z19.d, z19.d, z16.d, z15.d
    mov     z15.d, z25.d
    mov     z16.d, z26.d

    movprfx z25, z20
    bcax    z25.d, z25.d, z22.d, z21.d
    movprfx z26, z21
    bcax    z26.d, z26.d, z23.d, z22.d
    bcax    z22.d, z22.d, z24.d, z23.d
    bcax    z23.d, z23.d, z20.d, z24.d
    bcax    z24.d, z24.d, z21.d, z20.d
    mov     z20.d, z25.d
    mov     z21.d, z26.d

    // -----------------------------------------------------------------
    // Iota Step
    // -----------------------------------------------------------------
    ld1rd   {z25.d}, p0/z, [x1]
    add     x1, x1, #8
    eor     z0.d, z0.d, z25.d
.endm

.align 4
.global _f1600x2
_f1600x2:
    // Stack and Register Save (Standard ABI + D8-D15 save)
    stp d8,  d9,  [sp,#-16]!
    stp d10, d11, [sp,#-16]!
    stp d12, d13, [sp,#-16]!
    stp d14, d15, [sp,#-16]!

    // Setup predicate for 128-bit operations (2 x 64-bit lanes)
    ptrue p0.d, vl2

    mov x2, x0
    mov x3, #24

    // Load State
    // Replaced [x0, #imm] with explicit pointer updates to avoid assembler range errors.
    
    // Row 1
    ld1d z0.d, p0/z, [x0]
    add x0, x0, #16
    ld1d z1.d, p0/z, [x0]
    add x0, x0, #16
    ld1d z2.d, p0/z, [x0]
    add x0, x0, #16
    ld1d z3.d, p0/z, [x0]
    add x0, x0, #16

    // Row 2
    ld1d z4.d, p0/z, [x0]
    add x0, x0, #16
    ld1d z5.d, p0/z, [x0]
    add x0, x0, #16
    ld1d z6.d, p0/z, [x0]
    add x0, x0, #16
    ld1d z7.d, p0/z, [x0]
    add x0, x0, #16

    // Row 3
    ld1d z8.d, p0/z, [x0]
    add x0, x0, #16
    ld1d z9.d, p0/z, [x0]
    add x0, x0, #16
    ld1d z10.d, p0/z, [x0]
    add x0, x0, #16
    ld1d z11.d, p0/z, [x0]
    add x0, x0, #16

    // Row 4
    ld1d z12.d, p0/z, [x0]
    add x0, x0, #16
    ld1d z13.d, p0/z, [x0]
    add x0, x0, #16
    ld1d z14.d, p0/z, [x0]
    add x0, x0, #16
    ld1d z15.d, p0/z, [x0]
    add x0, x0, #16

    // Row 5
    ld1d z16.d, p0/z, [x0]
    add x0, x0, #16
    ld1d z17.d, p0/z, [x0]
    add x0, x0, #16
    ld1d z18.d, p0/z, [x0]
    add x0, x0, #16
    ld1d z19.d, p0/z, [x0]
    add x0, x0, #16

    // Row 6
    ld1d z20.d, p0/z, [x0]
    add x0, x0, #16
    ld1d z21.d, p0/z, [x0]
    add x0, x0, #16
    ld1d z22.d, p0/z, [x0]
    add x0, x0, #16
    ld1d z23.d, p0/z, [x0]
    add x0, x0, #16

    // Last lane
    ld1d z24.d, p0/z, [x0]
    // x0 is no longer needed until restore, stored in x2

loop:
    round

    subs x3, x3, #1
    cbnz x3, loop

    // Store State
    mov x0, x2

    // Row 1
    st1d z0.d, p0, [x0]
    add x0, x0, #16
    st1d z1.d, p0, [x0]
    add x0, x0, #16
    st1d z2.d, p0, [x0]
    add x0, x0, #16
    st1d z3.d, p0, [x0]
    add x0, x0, #16

    // Row 2
    st1d z4.d, p0, [x0]
    add x0, x0, #16
    st1d z5.d, p0, [x0]
    add x0, x0, #16
    st1d z6.d, p0, [x0]
    add x0, x0, #16
    st1d z7.d, p0, [x0]
    add x0, x0, #16

    // Row 3
    st1d z8.d, p0, [x0]
    add x0, x0, #16
    st1d z9.d, p0, [x0]
    add x0, x0, #16
    st1d z10.d, p0, [x0]
    add x0, x0, #16
    st1d z11.d, p0, [x0]
    add x0, x0, #16

    // Row 4
    st1d z12.d, p0, [x0]
    add x0, x0, #16
    st1d z13.d, p0, [x0]
    add x0, x0, #16
    st1d z14.d, p0, [x0]
    add x0, x0, #16
    st1d z15.d, p0, [x0]
    add x0, x0, #16

    // Row 5
    st1d z16.d, p0, [x0]
    add x0, x0, #16
    st1d z17.d, p0, [x0]
    add x0, x0, #16
    st1d z18.d, p0, [x0]
    add x0, x0, #16
    st1d z19.d, p0, [x0]
    add x0, x0, #16

    // Row 6
    st1d z20.d, p0, [x0]
    add x0, x0, #16
    st1d z21.d, p0, [x0]
    add x0, x0, #16
    st1d z22.d, p0, [x0]
    add x0, x0, #16
    st1d z23.d, p0, [x0]
    add x0, x0, #16

    // Last lane
    st1d z24.d, p0, [x0]

    // Restore registers
    ldp d14, d15, [sp], #16
    ldp d12, d13, [sp], #16
    ldp d10, d11, [sp], #16
    ldp d8,  d9,  [sp], #16

    ret lr
