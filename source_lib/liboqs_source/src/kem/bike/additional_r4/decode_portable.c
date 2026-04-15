/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#include "decode.h"
#include "decode_internal.h"
#include "utilities.h"

#include <arm_sve.h>

#define R_QWORDS_HALF_LOG2 UPTOPOW2(R_QWORDS / 2)

#if defined(OQS_ENABLE_SVE2)

_INLINE_ void
rotr_big(OUT syndrome_t *out, IN const syndrome_t *in, IN size_t qw_num)
{
    bike_static_assert(sizeof(*out) > 8 * (R_QWORDS + (2 * R_QWORDS_HALF_LOG2)),
                       rotr_big_err);

    // 严谨拷贝，防止数据被破坏
    if (out != in) {
        *out = *in;
    }

    // 去除 __restrict__，确保编译器不会因为内存重叠而生成产生 UB 的乱序指令
    uint64_t *ptr = (uint64_t *)__builtin_assume_aligned(out->qw, 8);

    const uint64_t vl = svcntd();
    const uint64_t vl2 = vl * 2;
    const svbool_t ptrue = svptrue_b64(); // 永远真谓词，让主循环全速裸奔

    for(uint32_t idx = R_QWORDS_HALF_LOG2; idx >= 1; idx >>= 1) {
        const uint64_t mask_val = ((uint32_t)secure_l32_mask(qw_num, idx) + 1U) - 1ULL;
        qw_num = qw_num - (idx & u64_barrier(mask_val));

        // 【性能核弹】：将标量数值掩码直接升维成“恒定时间谓词（Predicate）”
        // svcmpne 是完全 Constant-time 的，它瞬间激活底层的 p0 谓词寄存器！
        svuint64_t v_mask_val = svdup_n_u64(u64_barrier(mask_val));
        svbool_t p_swap = svcmpne_n_u64(ptrue, v_mask_val, 0);

        const size_t limit = R_QWORDS + idx;
        size_t i = 0;

        /* ---- Main Loop 2x 饱和展开 ---- */
        for (; i + vl2 <= limit; i += vl2) {
            svuint64_t v_out0     = svld1_u64(ptrue, &ptr[i]);
            svuint64_t v_out_idx0 = svld1_u64(ptrue, &ptr[i + idx]);
            svuint64_t v_out1     = svld1_u64(ptrue, &ptr[i + vl]);
            svuint64_t v_out_idx1 = svld1_u64(ptrue, &ptr[i + vl + idx]);

            // 【极致优雅】：硬件级谓词选择指令 (Select)
            // 等价于 Cortex-M4 的 SEL，但在 256/512-bit 宽度上全速轰炸！
            svuint64_t v_res0 = svsel_u64(p_swap, v_out_idx0, v_out0);
            svuint64_t v_res1 = svsel_u64(p_swap, v_out_idx1, v_out1);

            svst1_u64(ptrue, &ptr[i], v_res0);
            svst1_u64(ptrue, &ptr[i + vl], v_res1);
        }

        /* ---- 1x 单步补齐 ---- */
        for (; i + vl <= limit; i += vl) {
            svuint64_t v_out     = svld1_u64(ptrue, &ptr[i]);
            svuint64_t v_out_idx = svld1_u64(ptrue, &ptr[i + idx]);
            svuint64_t v_res     = svsel_u64(p_swap, v_out_idx, v_out);
            svst1_u64(ptrue, &ptr[i], v_res);
        }

        /* ---- Tail 安全尾部处理 ---- */
        if (i < limit) {
            svbool_t pg = svwhilelt_b64((uint64_t)i, (uint64_t)limit);
            svuint64_t v_out     = svld1_u64(pg, &ptr[i]);
            svuint64_t v_out_idx = svld1_u64(pg, &ptr[i + idx]);
            svuint64_t v_res     = svsel_u64(p_swap, v_out_idx, v_out);
            svst1_u64(pg, &ptr[i], v_res);
        }
    }
}

_INLINE_ void
rotr_small(OUT syndrome_t *out, IN const syndrome_t *in, IN const size_t bits)
{
    bike_static_assert(sizeof(*out) > (8 * R_QWORDS), rotr_small_qw_err);

    const uint64_t bit_mask_val = (uint64_t)-(bits != 0);
    const uint64_t hi_shift_val = (64 - bits) & u64_barrier(bit_mask_val);

    const svuint64_t v_bit_shift = svdup_n_u64(bits);
    const svuint64_t v_hi_shift  = svdup_n_u64(hi_shift_val);
    const svuint64_t v_mask      = svdup_n_u64(u64_barrier(bit_mask_val));

    // 去除 __restrict__，完美支持 in == out 的原地计算，杜绝 UB！
    const uint64_t *src = (const uint64_t *)__builtin_assume_aligned(in->qw, 8);
    uint64_t *dst       = (uint64_t *)__builtin_assume_aligned(out->qw, 8);

    const uint64_t vl = svcntd();
    const uint64_t vl2 = vl * 2;
    const svbool_t ptrue = svptrue_b64();
    size_t i = 0;
    const size_t limit = R_QWORDS;

    /* ---- Main Loop 2x 饱和展开 ---- */
    for (; i + vl2 <= limit; i += vl2) {
        svuint64_t v0_0 = svld1_u64(ptrue, &src[i]);
        svuint64_t v1_0 = svld1_u64(ptrue, &src[i + 1]);
        svuint64_t v0_1 = svld1_u64(ptrue, &src[i + vl]);
        svuint64_t v1_1 = svld1_u64(ptrue, &src[i + vl + 1]);

        svuint64_t lo0 = svlsr_u64_x(ptrue, v0_0, v_bit_shift);
        svuint64_t hi0 = svlsl_u64_x(ptrue, v1_0, v_hi_shift);
        hi0 = svand_u64_x(ptrue, hi0, v_mask);

        svuint64_t lo1 = svlsr_u64_x(ptrue, v0_1, v_bit_shift);
        svuint64_t hi1 = svlsl_u64_x(ptrue, v1_1, v_hi_shift);
        hi1 = svand_u64_x(ptrue, hi1, v_mask);

        svuint64_t res0 = svorr_u64_x(ptrue, lo0, hi0);
        svuint64_t res1 = svorr_u64_x(ptrue, lo1, hi1);

        svst1_u64(ptrue, &dst[i], res0);
        svst1_u64(ptrue, &dst[i + vl], res1);
    }

    /* ---- 1x 单步补齐 ---- */
    for (; i + vl <= limit; i += vl) {
        svuint64_t v0 = svld1_u64(ptrue, &src[i]);
        svuint64_t v1 = svld1_u64(ptrue, &src[i + 1]);

        svuint64_t lo = svlsr_u64_x(ptrue, v0, v_bit_shift);
        svuint64_t hi = svlsl_u64_x(ptrue, v1, v_hi_shift);
        hi = svand_u64_x(ptrue, hi, v_mask);

        svuint64_t res = svorr_u64_x(ptrue, lo, hi);
        svst1_u64(ptrue, &dst[i], res);
    }

    /* ---- Tail 安全尾部处理 ---- */
    if (i < limit) {
        svbool_t pg = svwhilelt_b64((uint64_t)i, (uint64_t)limit);
        svuint64_t v0 = svld1_u64(pg, &src[i]);
        svuint64_t v1 = svld1_u64(pg, &src[i + 1]);

        svuint64_t lo = svlsr_u64_x(pg, v0, v_bit_shift);
        svuint64_t hi = svlsl_u64_x(pg, v1, v_hi_shift);
        hi = svand_u64_x(pg, hi, v_mask);

        svuint64_t res = svorr_u64_x(pg, lo, hi);
        svst1_u64(pg, &dst[i], res);
    }
}
#else
_INLINE_ void
rotr_big(OUT syndrome_t *out, IN const syndrome_t *in, IN size_t qw_num)
{
  // For preventing overflows (comparison in bytes)
  bike_static_assert(sizeof(*out) > 8 * (R_QWORDS + (2 * R_QWORDS_HALF_LOG2)),
                     rotr_big_err);

  *out = *in;

  for(uint32_t idx = R_QWORDS_HALF_LOG2; idx >= 1; idx >>= 1) {
    // Convert 32 bit mask to 64 bit mask
    const uint64_t mask = ((uint32_t)secure_l32_mask(qw_num, idx) + 1U) - 1ULL;
    qw_num              = qw_num - (idx & u64_barrier(mask));

    // Rotate R_QWORDS quadwords and another idx quadwords,
    // as needed by the next iteration.
    for(size_t i = 0; i < (R_QWORDS + idx); i++) {
      out->qw[i] = (out->qw[i] & u64_barrier(~mask)) |
                   (out->qw[i + idx] & u64_barrier(mask));
    }
  }
}

_INLINE_ void
rotr_small(OUT syndrome_t *out, IN const syndrome_t *in, IN const size_t bits)
{
  bike_static_assert(sizeof(*out) > (8 * R_QWORDS), rotr_small_qw_err);

  // Convert |bits| to 0/1 by using !!bits; then create a mask of 0 or
  // 0xffffffffff Use high_shift to avoid undefined behaviour when doing x << 64;
  const uint64_t mask       = (0 - (!!bits));
  const uint64_t high_shift = (64 - bits) & u64_barrier(mask);

  for(size_t i = 0; i < R_QWORDS; i++) {
    const uint64_t low_part  = in->qw[i] >> bits;
    const uint64_t high_part = (in->qw[i + 1] << high_shift) & u64_barrier(mask);
    out->qw[i]               = low_part | high_part;
  }
}
#endif

void rotate_right_port(OUT syndrome_t *out,
                       IN const syndrome_t *in,
                       IN const uint32_t    bitscount)
{
    // 使用严格等价于标量的恒定时间桶形移位器
    rotr_big(out, in, (bitscount / 64));
    rotr_small(out, out, (bitscount % 64));
}




// #if defined(OQS_ENABLE_SVE2)
// // SVE2实现
// #include <arm_sve.h>
// void rotate_right_port(OUT syndrome_t *out,
//                    IN  const syndrome_t *in,
//                    IN  const uint32_t bitscount)
// {
//     bike_static_assert(sizeof(*out) > (8 * R_QWORDS),
//                        rotate_right_err);

//     const size_t qw_shift  = bitscount >> 6;
//     const size_t bit_shift = bitscount & 63;

//     const uint64_t bit_mask = (uint64_t)-(bit_shift != 0);
//     const uint64_t hi_shift = (64 - bit_shift) & u64_barrier(bit_mask);

//     const svuint64_t v_bit_shift = svdup_n_u64(bit_shift);
//     const svuint64_t v_hi_shift  = svdup_n_u64(hi_shift);
//     const svuint64_t v_bit_mask  = svdup_n_u64(bit_mask);

//     const uint64_t * __restrict__ src =
//         (const uint64_t *)__builtin_assume_aligned(in->qw, 8);
//     uint64_t * __restrict__ dst =
//         (uint64_t *)__builtin_assume_aligned(out->qw, 8);

//     const uint64_t rq = (uint64_t)R_QWORDS;
//     const uint64_t vl = svcntd();

//     uint64_t i = 0;

//     /* ---- main vector loop ---- */
//     for (; i + vl <= rq; i += vl) {

//         svuint64_t v0 = svld1(svptrue_b64(), &src[i + qw_shift]);
//         svuint64_t v1 = svld1(svptrue_b64(), &src[i + qw_shift + 1]);

//         svuint64_t lo = svlsr_u64_x(svptrue_b64(), v0, v_bit_shift);
//         svuint64_t hi = svlsl_u64_x(svptrue_b64(), v1, v_hi_shift);
//         hi = svand_x(svptrue_b64(), hi, v_bit_mask);

//         svuint64_t res = svorr_x(svptrue_b64(), lo, hi);
//         svst1(svptrue_b64(), &dst[i], res);
//     }

//     /* ---- tail ---- */
//     if (i < rq) {
//         svbool_t pg = svwhilelt_b64(i, rq);

//         svuint64_t v0 = svld1(pg, &src[i + qw_shift]);
//         svuint64_t v1 = svld1(pg, &src[i + qw_shift + 1]);

//         svuint64_t lo = svlsr_u64_x(pg, v0, v_bit_shift);
//         svuint64_t hi = svlsl_u64_x(pg, v1, v_hi_shift);
//         hi = svand_x(pg, hi, v_bit_mask);

//         svuint64_t res = svorr_x(pg, lo, hi);
//         svst1(pg, &dst[i], res);
//     }
// }
// // 纯C实现
// // void rotate_right_port(OUT syndrome_t *out,
// //                        IN const syndrome_t *in,
// //                        IN const uint32_t    bitscount)
// // {
// //     bike_static_assert(sizeof(*out) > (8 * R_QWORDS),
// //                        rotate_right_err);

// //     const size_t qw_shift  = bitscount >> 6;      // /64
// //     const size_t bit_shift = bitscount & 63;      // %64

// //     /* constant-time mask: bit_shift != 0 ? all-ones : 0 */
// //     const uint64_t bit_mask = (uint64_t)-(bit_shift != 0);
// //     const uint64_t hi_shift = (64 - bit_shift) & u64_barrier(bit_mask);

// //     /*
// //      * in->qw is already duplicated (3 * R_QWORDS),
// //      * so in[i + qw_shift + 1] is always valid.
// //      */
// //     for (size_t i = 0; i < R_QWORDS; i++) {

// //         const uint64_t lo = in->qw[i + qw_shift] >> bit_shift;
// //         const uint64_t hi =
// //             (in->qw[i + qw_shift + 1] << hi_shift) & u64_barrier(bit_mask);

// //         out->qw[i] = lo | hi;
// //     }
// // }
// #else
// void rotate_right_port(OUT syndrome_t *out,
//                        IN const syndrome_t *in,
//                        IN const uint32_t    bitscount)
// {
//   // Rotate (64-bit) quad-words
//   rotr_big(out, in, (bitscount / 64));
//   // Rotate bits (less than 64)
//   rotr_small(out, out, (bitscount % 64));
// }
// #endif

// Duplicates the first R_BITS of the syndrome three times
// |------------------------------------------|
// |  Third copy | Second copy | first R_BITS |
// |------------------------------------------|
// This is required by the rotate functions.
void dup_port(IN OUT syndrome_t *s)
{
  s->qw[R_QWORDS - 1] =
    (s->qw[0] << LAST_R_QWORD_LEAD) | (s->qw[R_QWORDS - 1] & LAST_R_QWORD_MASK);

  for(size_t i = 0; i < (2 * R_QWORDS) - 1; i++) {
    s->qw[R_QWORDS + i] =
      (s->qw[i] >> LAST_R_QWORD_TRAIL) | (s->qw[i + 1] << LAST_R_QWORD_LEAD);
  }
}

// Use half-adder as described in [1].
void bit_sliced_adder_port(OUT upc_t *upc,
                           IN OUT syndrome_t *rotated_syndrome,
                           IN const size_t    num_of_slices)
{
  // From cache-memory perspective this loop should be the outside loop
  for(size_t j = 0; j < num_of_slices; j++) {
    for(size_t i = 0; i < R_QWORDS; i++) {
      const uint64_t carry = (upc->slice[j].u.qw[i] & rotated_syndrome->qw[i]);
      upc->slice[j].u.qw[i] ^= rotated_syndrome->qw[i];
      rotated_syndrome->qw[i] = carry;
    }
  }
}


void bit_slice_full_subtract_port(OUT upc_t *upc, IN uint8_t val)
{
  // Borrow
  uint64_t br[R_QWORDS] = {0};

  for(size_t j = 0; j < SLICES; j++) {

    const uint64_t lsb_mask = 0 - (val & 0x1);
    val >>= 1;

    // Perform a - b with c as the input/output carry
    // br = 0 0 0 0 1 1 1 1
    // a  = 0 0 1 1 0 0 1 1
    // b  = 0 1 0 1 0 1 0 1
    // -------------------
    // o  = 0 1 1 0 0 1 1 1
    // c  = 0 1 0 0 1 1 0 1
    //
    // o  = a^b^c
    //            _     __    _ _   _ _     _
    // br = abc + abc + abc + abc = abc + ((a+b))c

    for(size_t i = 0; i < R_QWORDS; i++) {
      const uint64_t a      = upc->slice[j].u.qw[i];
      const uint64_t b      = lsb_mask;
      const uint64_t tmp    = ((~a) & b & (~br[i])) | ((((~a) | b) & br[i]));
      upc->slice[j].u.qw[i] = a ^ b ^ br[i];
      br[i]                 = tmp;
    }
  }
}
