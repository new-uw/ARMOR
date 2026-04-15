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

#include "parameters.h"

#define FZRED_SINGLE(x)   (((x) & 0x7f) + ((x) >> 7))
#define FZRED_DOUBLE(x) FZRED_SINGLE(FZRED_SINGLE(x))
#define FZRED_OPPOSITE(x) ((x) ^ 0x7f)
#define FZ_DOUBLE_ZERO_NORM(x) (((x) + (((x) + 1) >> 7)) & 0x7f)


static inline
void fz_dz_norm_n(FZ_ELEM v[N]) {
	for (int i = 0; i < N; i++) {
		v[i] = FZ_DOUBLE_ZERO_NORM(v[i]);
	}
}

/* Elements of the restricted subgroups are represented as the exponents of
 * the generator */
static inline
void fz_vec_sub_n(FZ_ELEM res[N],
                  const FZ_ELEM a[N],
                  const FZ_ELEM b[N]) {
	for (int i = 0; i < N; i++) {
		res[i] = FZRED_SINGLE( a[i] + FZRED_OPPOSITE(b[i]) );
	}
}

static inline
int is_fz_vec_in_restr_group_n(const FZ_ELEM in[N]) {
	int is_in_ok = 1;
	for (int i = 0; i < N; i++) {
		is_in_ok = is_in_ok && (in[i] < Z);
	}
	return is_in_ok;
}

/* computes the information word * M_G product to obtain an element of G
 * only non systematic portion of M_G = [W I] is used, transposed to improve
 * cache friendliness */
#if defined(OQS_ENABLE_SVE2)
#include <arm_sve.h>
#include <string.h>

/**
 * 局部归约：对应 FZRED_SINGLE
 * 将 acc 压缩到 uint16 范围内，防止后续累加溢出 (127*127*4 = 64516 < 65535)
 */
static inline svuint16_t sv_fzred_single(svbool_t pg, svuint16_t x) {
    svuint16_t low = svand_n_u16_x(pg, x, 0x7f);
    svuint16_t high = svlsr_n_u16_x(pg, x, 7);
    return svadd_u16_x(pg, low, high);
}
/**
 * 完整归约：对应 FZRED_DOUBLE
 * 确保最终结果在 [0, 127] 范围内
 */
static inline svuint16_t sv_fzred_double(svbool_t pg, svuint16_t x) {
    x = sv_fzred_single(pg, x);
    return sv_fzred_single(pg, x);
}

static void fz_inf_w_by_fz_matrix(FZ_ELEM res[N],
                                  const FZ_ELEM e[M],
                                  const FZ_ELEM W_mat[M][N - M]) {
    const int num_cols = N - M;
    const int vl = svcnth(); // 获取当前硬件 uint16 的向量元素个数
    int j = 0;
    // 线性扫描每一列块
    for (j = 0; j < num_cols; j += vl) {
        // 生成谓词 pg，自动处理末尾非对齐部分
        svbool_t pg = svwhilelt_b16(j, num_cols);
        // 1. 初始化累加器为 0
        svuint16_t acc = svdup_u16(0);
        // 2. 核心计算循环：遍历 M 行
        for (int i = 0; i < M; i++) {
            // 广播当前行的标量 e[i]
            svuint16_t scalar_e = svdup_u16((uint16_t)e[i]);
            // 加载 W_mat[i][j] 段 (8位无符号加载并自动提升至 16位)
            svuint16_t v_w = svld1ub_u16(pg, &W_mat[i][j]);
            // 向量化乘加 (acc = acc + v_w * scalar_e)
            acc = svmla_u16_x(pg, acc, v_w, scalar_e);
            // 学习 NEON 策略：每 4 次累加进行一次局部归约
            // 理由：127 * 127 = 16129; 16129 * 4 = 64516，未超过 uint16_t 的 65535
            if ((i & 0x3) == 0x3) {
                acc = sv_fzred_single(pg, acc);
            }
        }
        // 3. 循环结束后进行最终的两次约减，确保结果完全符合规范
        acc = sv_fzred_double(pg, acc);
        // 4. 将计算结果 (16位) 存储回内存 (8位存储，自动截断)
        svst1b_u16(pg, &res[j], acc);
    }
    // 处理 e 部分的拷贝 (res[N-M...N-1] = e[0...M-1])
    memcpy(res + (N - M), e, M * sizeof(FZ_ELEM));
}
#else
static
void fz_inf_w_by_fz_matrix(FZ_ELEM res[N],
                           const FZ_ELEM e[M],
                           FZ_ELEM W_mat[M][N - M]) {

	memset(res, 0, (N - M)*sizeof(FZ_ELEM));
	memcpy(res + (N - M), e, M * sizeof(FZ_ELEM));
	for (int i = 0; i < M; i++) {
		for (int j = 0; j < N - M; j++) {
			res[j] = FZRED_DOUBLE( (FZ_DOUBLEPREC) res[j] +
			                       (FZ_DOUBLEPREC) e[i] *
			                       (FZ_DOUBLEPREC) W_mat[i][j]);
		}
	}
}
#endif

static inline
void fz_vec_sub_m(FZ_ELEM res[M],
                  const FZ_ELEM a[M],
                  const FZ_ELEM b[M]) {
	for (int i = 0; i < M; i++) {
		res[i] = FZRED_SINGLE( a[i] + FZRED_OPPOSITE(b[i]) );
	}
}

static inline
int is_fz_vec_in_restr_group_m(const FZ_ELEM in[M]) {
	int is_in_ok = 1;
	for (int i = 0; i < M; i++) {
		is_in_ok = is_in_ok && (in[i] < Z);
	}
	return is_in_ok;
}
static inline
void fz_dz_norm_m(FZ_ELEM v[M]) {
	for (int i = 0; i < M; i++) {
		v[i] = FZ_DOUBLE_ZERO_NORM(v[i]);
	}
}
