/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#pragma once

#include "types.h"

#if defined(OQS_ENABLE_SVE2)
#include <arm_sve.h>
_INLINE_ void
gf2x_mod_add(OUT pad_r_t *c, IN const pad_r_t *a, IN const pad_r_t *b)
{
    const uint64_t *a_ptr = (const uint64_t *)a;
    const uint64_t *b_ptr = (const uint64_t *)b;
    uint64_t * c_ptr = (uint64_t *)c;

    size_t i = 0;
    size_t n = R_PADDED_QWORDS;

    // 使用 SVE 循环处理数据
    // svwhilelt_b64 会生成一个谓词掩码，确保处理不会越界
    svbool_t pg = svwhilelt_b64(i, n);

    while (svptest_any(svptrue_b64(), pg)) {
        // 加载数据
        svuint64_t va = svld1_u64(pg, &a_ptr[i]);
        svuint64_t vb = svld1_u64(pg, &b_ptr[i]);

        // 执行按位异或 (GF(2) 下的加法)
        svuint64_t vc = sveor_u64_z(pg, va, vb);

        // 存储结果
        svst1_u64(pg, &c_ptr[i], vc);

        // 递增索引（增加当前向量长度处理的元素个数）
        i += svcntd();
        pg = svwhilelt_b64(i, n);
    }
}
#else
// c = a+b mod (x^r - 1)
_INLINE_ void
gf2x_mod_add(OUT pad_r_t *c, IN const pad_r_t *a, IN const pad_r_t *b)
{
  const uint64_t *a_qwords = (const uint64_t *)a;
  const uint64_t *b_qwords = (const uint64_t *)b;
  uint64_t *      c_qwords = (uint64_t *)c;

  for(size_t i = 0; i < R_PADDED_QWORDS; i++) {
    c_qwords[i] = a_qwords[i] ^ b_qwords[i];
  }
}
#endif




// c = a*b mod (x^r - 1)
void gf2x_mod_mul(OUT pad_r_t *c, IN const pad_r_t *a, IN const pad_r_t *b);

// c = a^-1 mod (x^r - 1)
void gf2x_mod_inv(OUT pad_r_t *c, IN const pad_r_t *a);
