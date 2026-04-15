/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#include "gf2x_internal.h"
#include "utilities.h"

#define LSB3(x) ((x)&7)

// 64x64 bit multiplication
// The algorithm is based on the windowing method, for example as in:
// Brent, R. P., Gaudry, P., Thomé, E., & Zimmermann, P. (2008, May), "Faster
// multiplication in GF (2)[x]". In: International Algorithmic Number Theory
// Symposium (pp. 153-166). Springer, Berlin, Heidelberg. In this implementation,
// the last three bits are multiplied using a schoolbook multiplication.
#if defined(OQS_ENABLE_SVE2)
#include <arm_sve.h>
void gf2x_mul_base_port(OUT uint64_t *c,
                        IN const uint64_t *a,
                        IN const uint64_t *b)
{
  svbool_t pg = svwhilelt_b64(0, 2);
  // svuint64_t表示SVE 向量寄存器，即va = [va[0], va[1],  ...]，取决于硬件
  // svld1_u64(pg, a)表示：从内存地址 a 开始，按 64 位为单位，加载“谓词为真”的 lane 数量的数据，放进向量寄存器
  svuint64_t va = svld1_u64(pg, a); 
  svuint64_t vb = svld1_u64(pg, b);

  svuint64_t res0 = svpmullb_pair_u64(va, vb);
  svuint64_t res2 = svpmullt_pair_u64(va, vb);

  // 3. 计算中间项 (a0^a1) * (b0^b1)
  // svrev_u64 表示反转向量寄存器内的元素顺序
  // svsel_u64(pg, va, svdup_u64(0)) 表示： 对 pg 为真的 lane，选择 va 的值；对 pg 为假的 lane，选择 0，这样做是为了防止在 va 或 vb 长度小于 2 时，反转操作访问到无效数据
  svuint64_t va_rev = svrev_u64(svsel_u64(pg, va, svdup_u64(0)));
  svuint64_t vb_rev = svrev_u64(svsel_u64(pg, vb, svdup_u64(0)));
  // sveor_u64_z表示对 pg 为真的 lane： 执行异或操作，pg 为假的 lane 则结果为 0
  svuint64_t a_xor = sveor_u64_z(pg, va, va_rev);
  svuint64_t b_xor = sveor_u64_z(pg, vb, vb_rev);
  // 执行 (a0^a1) * (b0^b1)
  svuint64_t res1 = svpmullb_pair_u64(a_xor, b_xor);

  // --- Karatsuba 合并逻辑 (在 GF(2) 下) ---
  // 中间交叉项 = res1 ^ res0 ^ res2
  svuint64_t mid = sveor_u64_z(pg, res1, sveor_u64_z(pg, res0, res2));

  // 将结果写回 c[0..3] (256 bits)
  // c0 = res0_low
  // c1 = res0_high ^ mid_low
  // c2 = res2_low ^ mid_high
  // c3 = res2_high
  uint64_t r0[2], r1[2], r2[2];
  svst1_u64(pg, r0, res0);
  svst1_u64(pg, r1, mid);
  svst1_u64(pg, r2, res2);

  c[0] = r0[0];
  c[1] = r0[1] ^ r1[0];
  c[2] = r2[0] ^ r1[1];
  c[3] = r2[1];
}
#else
void gf2x_mul_base_port(OUT uint64_t *c,
                        IN const uint64_t *a,
                        IN const uint64_t *b)
{
  uint64_t       h = 0, l = 0, g1, g2, u[8];
  const uint64_t w  = 64;
  const uint64_t s  = 3;
  const uint64_t a0 = a[0];
  const uint64_t b0 = b[0];

  // Multiplying 64 bits by 7 can results in an overflow of 3 bits.
  // Therefore, these bits are masked out, and are treated in step 3.
  const uint64_t b0m = b0 & MASK(61);

  // Step 1: Calculate a multiplication table with 8 entries.
  u[0] = 0;
  u[1] = b0m;
  u[2] = u[1] << 1;
  u[3] = u[2] ^ b0m;
  u[4] = u[2] << 1;
  u[5] = u[4] ^ b0m;
  u[6] = u[3] << 1;
  u[7] = u[6] ^ b0m;

  // Step 2: Multiply two elements in parallel in positions i, i+s
  for (size_t i = 0; i < 8; ++i) {
      // use a mask for secret-independent memory access
      l ^= u[i] & secure_cmpeq64_mask(LSB3(a0), i);
      l ^= (u[i] << 3) & secure_cmpeq64_mask(LSB3(a0 >> 3), i);
      h ^= (u[i] >> 61) & secure_cmpeq64_mask(LSB3(a0 >> 3), i);
  }

  for(size_t i = (2 * s); i < w; i += (2 * s)) {
    const size_t i2 = (i + s);

    g1 = 0;
    g2 = 0;
    for (size_t j = 0; j < 8; ++j) {
        // use a mask for secret-independent memory access
        g1 ^= u[j] & secure_cmpeq64_mask(LSB3(a0 >> i), j);
        g2 ^= u[j] & secure_cmpeq64_mask(LSB3(a0 >> i2), j);
    }

    l ^= (g1 << i) ^ (g2 << i2);
    h ^= (g1 >> (w - i)) ^ (g2 >> (w - i2));
  }

  // Step 3: Multiply the last three bits.
  for(size_t i = 61; i < 64; i++) {
    uint64_t mask = (-((b0 >> i) & 1));
    l ^= ((a0 << i) & mask);
    h ^= ((a0 >> (w - i)) & mask);
  }

  c[0] = l;
  c[1] = h;
}
#endif

// c = a^2
void gf2x_sqr_port(OUT dbl_pad_r_t *c, IN const pad_r_t *a)
{
  const uint64_t *a64 = (const uint64_t *)a;
  uint64_t *      c64 = (uint64_t *)c;

#if defined(OQS_ENABLE_SVE2)
for(size_t i = 0; i < R_QWORDS; i += 2)
        gf2x_mul_base_port(&c64[4 * (i / 2)], &a64[i], &a64[i]);
#else
  for(size_t i = 0; i < R_QWORDS; i++) {
    gf2x_mul_base_port(&c64[2 * i], &a64[i], &a64[i]);
  }
#endif
}
