/**
 *
 * Reference ISO-C11 Implementation of CROSS.
 *
 * @version 2.2 (July 2025)
 *
 * Authors listed in alphabetical order:
 *
 * @author: Alessandro Barenghi <alessandro.barenghi@polimi.it>
 * @author: Marco Gianvecchio <marco.gianvecchio@mail.polimi.it>
 * @author: Patrick Karl <patrick.karl@tum.de>
 * @author: Gerardo Pelosi <gerardo.pelosi@polimi.it>
 * @author: Jonas Schupp <jonas.schupp@tum.de>
 *
 *
 * This code is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 **/

#pragma once

#include <stdlib.h>
#include <string.h>

#include "csprng_hash.h"
#include "parameters.h"
#include "restr_arith.h"

#define NUM_BITS_P (BITS_TO_REPRESENT(P))

/* Reduction modulo P=509 as shown in:
 * Hacker's Delight, Second Edition, Chapter 10, Figure 10-4
 * Works for integers in the range [0,4294967295] i.e. all uint32_t */
#define FPRED_SINGLE(x) (((x) - (((uint64_t)(x) * 2160140723) >> 40) * P))
#define FPRED_DOUBLE(x) (FPRED_SINGLE(x))
#define FPRED_OPPOSITE(x) (FPRED_SINGLE(P - (x)))
/* no redundant zero notation in F_509 */
#define FP_DOUBLE_ZERO_NORM(x) (x)

/* for i in [0,1,2,4,8,16,32,64] RESTR_G_GEN**i mod 509 yields
 * [1, 16, 256, 384, 355, 302, 93, 505]
 * the following is a precomputed-squares S&M, to be optimized into muxed
 * register stored tables */

#define RESTR_G_GEN_1  ((FP_ELEM)RESTR_G_GEN)
#define RESTR_G_GEN_2  ((FP_ELEM) 256)
#define RESTR_G_GEN_4  ((FP_ELEM) 384)
#define RESTR_G_GEN_8  ((FP_ELEM) 355)
#define RESTR_G_GEN_16 ((FP_ELEM) 302)
#define RESTR_G_GEN_32 ((FP_ELEM) 93)
#define RESTR_G_GEN_64 ((FP_ELEM) 505)

#define FP_ELEM_CMOV(BIT,TRUE_V,FALSE_V)  ( (((FP_ELEM)0 - (BIT)) & (TRUE_V)) | (~((FP_ELEM)0 - (BIT)) & (FALSE_V)) )

/* log reduction, constant time unrolled S&M w/precomputed squares.
 * To be further optimized with muxed register-fitting tables */
static inline
FP_ELEM RESTR_TO_VAL(FP_ELEM x) {
	uint32_t res1, res2, res3, res4;
	res1 = ( FP_ELEM_CMOV(((x >> 0) & 1), RESTR_G_GEN_1, 1)) *
	       ( FP_ELEM_CMOV(((x >> 1) & 1), RESTR_G_GEN_2, 1)) ;
	res2 = ( FP_ELEM_CMOV(((x >> 2) & 1), RESTR_G_GEN_4, 1)) *
	       ( FP_ELEM_CMOV(((x >> 3) & 1), RESTR_G_GEN_8, 1)) ;
	res3 = ( FP_ELEM_CMOV(((x >> 4) & 1), RESTR_G_GEN_16, 1)) *
	       ( FP_ELEM_CMOV(((x >> 5) & 1), RESTR_G_GEN_32, 1)) ;
	res4 =   FP_ELEM_CMOV(((x >> 6) & 1), RESTR_G_GEN_64, 1);

	/* Two intermediate reductions necessary:
	 *     RESTR_G_GEN_1*RESTR_G_GEN_2*RESTR_G_GEN_4*RESTR_G_GEN_8    < 2^32
	 *     RESTR_G_GEN_16*RESTR_G_GEN_32*RESTR_G_GEN_64               < 2^32 */
	return FPRED_SINGLE( FPRED_SINGLE(res1 * res2) * FPRED_SINGLE(res3 * res4) );
}



/* in-place normalization of redundant zero representation for syndromes*/
static inline
void fp_dz_norm_synd(FP_ELEM v[N - K]) {
	for (int i = 0; i < N - K; i++) {
		v[i] = FP_DOUBLE_ZERO_NORM(v[i]);
	}
}

static inline
void fp_dz_norm(FP_ELEM v[N]) {
	for (int i = 0; i < N; i++) {
		v[i] = FP_DOUBLE_ZERO_NORM(v[i]);
	}
}
/* Computes the product e*H of an n-element restricted vector by a (n-k)*n
 * FP H is in systematic form. Only the non systematic portion of H =[V I],
 * V, is provided, transposed, hence linearized by columns so that syndrome
 * computation is vectorizable. */
#if defined(OQS_ENABLE_SVE2)

#include <arm_sve.h>

#define EPI8_PER_REG 16
#define EPI16_PER_REG 8
#define EPI32_PER_REG 4

static FP_ELEM TABLE_RESTR_TO_VAL[2*Z] = {
    1, 16, 256, 24, 384, 36, 67, 54, 355, 81, 278, 376, 417, 55, 371, 337,
    302, 251, 453, 122, 425, 183, 383, 20, 320, 30, 480, 45, 211, 322, 62, 483,
    93, 470, 394, 196, 82, 294, 123, 441, 439, 407, 404, 356, 97, 25, 400, 292,
    91, 438, 391, 148, 332, 222, 498, 333, 238, 245, 357, 113, 281, 424, 167, 127,
    505, 445, 503, 413, 500, 365, 241, 293, 107, 185, 415, 23, 368, 289, 43, 179,
    319, 14, 224, 21, 336, 286, 504, 429, 247, 389, 116, 329, 174, 239, 261, 104,
    137, 156, 460, 234, 181, 351, 17, 272, 280, 408, 420, 103, 121, 409, 436, 359,
    145, 284, 472, 426, 199, 130, 44, 195, 66, 38, 99, 57, 403, 340, 350,
    1, 16, 256, 24, 384, 36, 67, 54, 355, 81, 278, 376, 417, 55, 371, 337,
    302, 251, 453, 122, 425, 183, 383, 20, 320, 30, 480, 45, 211, 322, 62, 483,
    93, 470, 394, 196, 82, 294, 123, 441, 439, 407, 404, 356, 97, 25, 400, 292,
    91, 438, 391, 148, 332, 222, 498, 333, 238, 245, 357, 113, 281, 424, 167, 127,
    505, 445, 503, 413, 500, 365, 241, 293, 107, 185, 415, 23, 368, 289, 43, 179,
    319, 14, 224, 21, 336, 286, 504, 429, 247, 389, 116, 329, 174, 239, 261, 104,
    137, 156, 460, 234, 181, 351, 17, 272, 280, 408, 420, 103, 121, 409, 436, 359,
    145, 284, 472, 426, 199, 130, 44, 195, 66, 38, 99, 57, 403, 340, 350,
};

/* 辅助函数：针对 Lazy Reduction 后的累加值进行归约并存储 */
static inline void sv_barrett_store(svbool_t pg, FP_ELEM *res_ptr, svuint32_t acc) {
    /* 第一次梅森归约 (处理 32 位累加的大数值) */
    svuint32_t low = svand_n_u32_x(pg, acc, 0x1FF);
    svuint32_t high = svlsr_n_u32_x(pg, acc, 9);
    acc = svmla_n_u32_x(pg, low, high, 3);
    
    /* 第二次梅森归约 (确保值落在 Barrett 安全输入范围内) */
    low = svand_n_u32_x(pg, acc, 0x1FF);
    high = svlsr_n_u32_x(pg, acc, 9);
    acc = svmla_n_u32_x(pg, low, high, 3);

    /* Barrett 归约 (Mod 509) */
    svuint32_t q = svmul_n_u32_x(pg, acc, 16481);
    q = svlsr_n_u32_x(pg, q, 23);
    svuint32_t res_32 = svmls_n_u32_x(pg, acc, q, 509);

    /* 存储 16 位结果 */
    svst1h_u32(pg, (uint16_t*)res_ptr, res_32);
}

/**
 * 1. restr_vec_by_fp_matrix (Single-way SVE)
 */
static void restr_vec_by_fp_matrix(FP_ELEM res[N-K],
                                   FZ_ELEM e[N],
                                   const FP_ELEM V_tr[K][N-K]) 
{
    uint32_t restr_e[N];
    for (int i = 0; i < N; i++) {
        restr_e[i] = TABLE_RESTR_TO_VAL[e[i]];
    }

    const int num_cols = N - K;
    const int vl = svcntw();
    
    // 每一个循环步长仅为一个向量长度 (Single-way)
    for (int j = 0; j < num_cols; j += vl) {
        svbool_t pg = svwhilelt_b32(j, num_cols);

        // 初始化累加器: 加载 e 的后半部分 (查表后的值)
        svuint32_t acc = svld1_u32(pg, &restr_e[K + j]);

        // 内层循环遍历 K 行
        for (int i = 0; i < K; i++) {
            svuint32_t s = svdup_u32(restr_e[i]);
            // 使用 svld1uh_u32 将 16位 提升至 32位 进行 MLA
            svuint32_t v = svld1uh_u32(pg, &V_tr[i][j]);
            acc = svmla_u32_x(pg, acc, v, s);
        }

        // 最后进行归约并存储
        sv_barrett_store(pg, &res[j], acc);
    }
}

/**
 * 2. fp_vec_by_fp_matrix (Single-way SVE)
 */
static void fp_vec_by_fp_matrix(FP_ELEM res[N-K],
                                const FP_ELEM u[N],
                                const FP_ELEM V_tr[K][N-K]) 
{
    const int num_cols = N - K;
    const int vl = svcntw();

    for (int j = 0; j < num_cols; j += vl) {
        svbool_t pg = svwhilelt_b32(j, num_cols);

        // 初始化累加器: 使用 svld1uh_u32 加载 u 的后半部分
        svuint32_t acc = svld1uh_u32(pg, &u[K + j]);

        for (int i = 0; i < K; i++) {
            svuint32_t s = svdup_u32((uint32_t)u[i]);
            svuint32_t v = svld1uh_u32(pg, &V_tr[i][j]);
            acc = svmla_u32_x(pg, acc, v, s);
        }

        sv_barrett_store(pg, &res[j], acc);
    }
}
#else
static
void restr_vec_by_fp_matrix(FP_ELEM res[N - K],
                            FZ_ELEM e[N],
                            FP_ELEM V_tr[K][N - K]) {
	for (int i = K ; i < N; i++) {
		res[i - K] = RESTR_TO_VAL(e[i]);
	}
	for (int i = 0; i < K; i++) {
		for (int j = 0; j < N - K; j++) {
			res[j] = FPRED_DOUBLE( (FP_DOUBLEPREC) res[j] +
			                       (FP_DOUBLEPREC) RESTR_TO_VAL(e[i]) *
			                       (FP_DOUBLEPREC) V_tr[i][j]);
		}
	}
}

static
void fp_vec_by_fp_matrix(FP_ELEM res[N - K],
                         FP_ELEM e[N],
                         FP_ELEM V_tr[K][N - K]) {
	memcpy(res, e + K, (N - K)*sizeof(FP_ELEM));
	for (int i = 0; i < K; i++) {
		for (int j = 0; j < N - K; j++) {
			res[j] = FPRED_DOUBLE( (FP_DOUBLEPREC) res[j] +
			                       (FP_DOUBLEPREC) e[i] *
			                       (FP_DOUBLEPREC) V_tr[i][j]);
		}
	}
}
#endif

static inline
void fp_vec_by_fp_vec_pointwise(FP_ELEM res[N],
                                const FP_ELEM in1[N],
                                const FP_ELEM in2[N]) {
	for (int i = 0; i < N; i++) {
		res[i] = FPRED_DOUBLE( (FP_DOUBLEPREC) in1[i] *
		                       (FP_DOUBLEPREC) in2[i] );
	}
}

static inline
void restr_by_fp_vec_pointwise(FP_ELEM res[N],
                               const FZ_ELEM in1[N],
                               const FP_ELEM in2[N]) {
	for (int i = 0; i < N; i++) {
		res[i] = FPRED_DOUBLE( (FP_DOUBLEPREC) RESTR_TO_VAL(in1[i]) *
		                       (FP_DOUBLEPREC) in2[i]);
	}
}

/* e*chall_1 + u_prime*/
static inline
void fp_vec_by_restr_vec_scaled(FP_ELEM res[N],
                                const FZ_ELEM e[N],
                                const FP_ELEM chall_1,
                                const FP_ELEM u_prime[N]) {
	for (int i = 0; i < N; i++) {
		res[i] = FPRED_DOUBLE( (FP_DOUBLEPREC) u_prime[i] +
		                       (FP_DOUBLEPREC) RESTR_TO_VAL(e[i]) * (FP_DOUBLEPREC) chall_1) ;
	}
}


static inline
void fp_synd_minus_fp_vec_scaled(FP_ELEM res[N - K],
                                 const FP_ELEM synd[N - K],
                                 const FP_ELEM chall_1,
                                 const FP_ELEM s[N - K]) {
	for (int j = 0; j < N - K; j++) {
		FP_ELEM tmp = FPRED_DOUBLE( (FP_DOUBLEPREC) s[j] * (FP_DOUBLEPREC) chall_1);
		tmp = FP_DOUBLE_ZERO_NORM(tmp);
		res[j] = FPRED_SINGLE( (FP_DOUBLEPREC) synd[j] + FPRED_OPPOSITE(tmp) );
	}
}

static inline
void convert_restr_vec_to_fp(FP_ELEM res[N],
                             const FZ_ELEM in[N]) {
	for (int j = 0; j < N; j++) {
		res[j] = RESTR_TO_VAL(in[j]);
	}
}
