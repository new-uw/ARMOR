#pragma once

#include "fips202.h"

#define SHAKE_STATE_STRUCT shake128incctx
// %%%%%%%%%%%%%%%%%% Self-contained SHAKE Wrappers %%%%%%%%%%%%%%%%%%%%%%%%%%%%

static inline
void xof_shake_init(SHAKE_STATE_STRUCT *state, int val) {
	shake128_inc_init(state);
	/* avoid -Werror=unused-parameter */
	(void)val;
}

static inline
void xof_shake_update(SHAKE_STATE_STRUCT *state,
                      const unsigned char *input,
                      unsigned int inputByteLen) {
	shake128_inc_absorb(state,
	                    (const uint8_t *)input,
	                    inputByteLen);
}

static inline
void xof_shake_final(SHAKE_STATE_STRUCT *state) {
	shake128_inc_finalize(state);
}

static inline
void xof_shake_extract(SHAKE_STATE_STRUCT *state,
                       unsigned char *output,
                       unsigned int outputByteLen) {
	shake128_inc_squeeze(output, outputByteLen, state);
}

/* PQClean-edit: SHAKE release context */
static inline
void xof_shake_release(SHAKE_STATE_STRUCT *state) {
	shake128_inc_ctx_release(state);
}

#if defined(OQS_ENABLE_SVE2)
#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#include <arm_sve.h>

typedef struct {
    uint64_t s[50];  // Interleaved: s[2*i] = instance0 lane i, s[2*i+1] = instance1 lane i
    uint64_t offset;
} keccakx2_state;

#define RATE SHAKE128_RATE  // 168
#define MAX_LANES (RATE / 8)  // 21

#define DS (0x1F)
#define WORD_BYTES 8

#define SHAKE_X2_STATE_STRUCT keccakx2_state

static const uint64_t KeccakF_RoundConstants[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

extern void _f1600x2(uint64_t *state, const uint64_t *rc);

static inline void KeccakF1600_StatePermutex2(uint64_t state[50]) {
    _f1600x2(state, KeccakF_RoundConstants);
}

#define SnP_laneLengthInBytes 8

static inline void KeccakP1600times2_AddBytes(keccakx2_state *state, unsigned int instanceIndex,
                                              const unsigned char *data, unsigned int offset, unsigned int length) {
    unsigned int sizeLeft = length;
    unsigned int lanePosition = offset / SnP_laneLengthInBytes;
    unsigned int offsetInLane = offset % SnP_laneLengthInBytes;
    const unsigned char *curData = data;
    uint64_t *statesAsLanes = state->s;

    if ((sizeLeft > 0) && (offsetInLane != 0)) {
        unsigned int bytesInLane = SnP_laneLengthInBytes - offsetInLane;
        uint64_t lane = 0;
        if (bytesInLane > sizeLeft) bytesInLane = sizeLeft;
        memcpy((unsigned char*)&lane + offsetInLane, curData, bytesInLane);
        statesAsLanes[(lanePosition << 1) + instanceIndex] ^= lane;
        sizeLeft -= bytesInLane;
        lanePosition++;
        curData += bytesInLane;
    }

    while (sizeLeft >= SnP_laneLengthInBytes) {
        uint64_t lane = *((const uint64_t*)curData);
        statesAsLanes[(lanePosition << 1) + instanceIndex] ^= lane;
        sizeLeft -= SnP_laneLengthInBytes;
        lanePosition++;
        curData += SnP_laneLengthInBytes;
    }

    if (sizeLeft > 0) {
        uint64_t lane = 0;
        memcpy(&lane, curData, sizeLeft);
        statesAsLanes[(lanePosition << 1) + instanceIndex] ^= lane;
    }
}

static inline void KeccakP1600times2_AddLanesAll(keccakx2_state *state,
                                                 const unsigned char *data0,
                                                 const unsigned char *data1,
                                                 unsigned int laneCount) {
    uint64_t *stateAsLanes = state->s;
    const uint64_t *lanes0 = (const uint64_t *)data0;
    const uint64_t *lanes1 = (const uint64_t *)data1;

    if (laneCount == MAX_LANES) {
        svbool_t pg = svptrue_b64();

        #define PAIRED(i) \
            do { \
                svuint64_t in0 = svld1_u64(pg, lanes0 + (i)); \
                svuint64_t in1 = svld1_u64(pg, lanes1 + (i)); \
                svuint64_t st0 = svld1_u64(pg, stateAsLanes + 2*(i)); \
                svuint64_t st1 = svld1_u64(pg, stateAsLanes + 2*(i+1)); \
                st0 = sveor_u64_x(pg, st0, in0); \
                st1 = sveor_u64_x(pg, st1, in1); \
                svst1_u64(pg, stateAsLanes + 2*(i), st0); \
                svst1_u64(pg, stateAsLanes + 2*(i+1), st1); \
            } while (0)

        PAIRED(0); PAIRED(2); PAIRED(4); PAIRED(6); PAIRED(8);
        PAIRED(10); PAIRED(12); PAIRED(14); PAIRED(16); PAIRED(18);

        stateAsLanes[40] ^= lanes0[20];
        stateAsLanes[41] ^= lanes1[20];

        #undef PAIRED
    } else {
        for (unsigned int i = 0; i < laneCount; ++i) {
            stateAsLanes[2 * i] ^= lanes0[i];
            stateAsLanes[2 * i + 1] ^= lanes1[i];
        }
    }
}

static inline void KeccakP1600times2_ExtractLanesAll(const keccakx2_state *state,
                                                     unsigned char *data0,
                                                     unsigned char *data1,
                                                     unsigned int laneCount) {
    const uint64_t *stateAsLanes = state->s;
    uint64_t *lanes0 = (uint64_t *)data0;
    uint64_t *lanes1 = (uint64_t *)data1;

    if (laneCount == MAX_LANES) {
        svbool_t pg = svptrue_b64();

        #define PAIRED(i) \
            do { \
                svuint64_t vec0 = svld1_u64(pg, stateAsLanes + 2*(i)); \
                svuint64_t vec1 = svld1_u64(pg, stateAsLanes + 2*(i+1)); \
                svst1_u64(pg, lanes0 + (i), vec0); \
                svst1_u64(pg, lanes1 + (i), vec1); \
            } while (0)

        PAIRED(0); PAIRED(2); PAIRED(4); PAIRED(6); PAIRED(8);
        PAIRED(10); PAIRED(12); PAIRED(14); PAIRED(16); PAIRED(18);

        lanes0[20] = stateAsLanes[40];
        lanes1[20] = stateAsLanes[41];

        #undef PAIRED
    } else {
        for (unsigned int i = 0; i < laneCount; ++i) {
            lanes0[i] = stateAsLanes[2 * i];
            lanes1[i] = stateAsLanes[2 * i + 1];
        }
    }
}

static inline void KeccakP1600times2_ExtractBytes(keccakx2_state *state, unsigned int instanceIndex,
                                                  unsigned char *data, unsigned int offset, unsigned int length) {
    unsigned int sizeLeft = length;
    unsigned int lanePosition = offset / SnP_laneLengthInBytes;
    unsigned int offsetInLane = offset % SnP_laneLengthInBytes;
    unsigned char *curData = data;
    const uint64_t *statesAsLanes = state->s;

    if ((sizeLeft > 0) && (offsetInLane != 0)) {
        unsigned int bytesInLane = SnP_laneLengthInBytes - offsetInLane;
        if (bytesInLane > sizeLeft) bytesInLane = sizeLeft;
        memcpy(curData, ((unsigned char *)&statesAsLanes[(lanePosition << 1) + instanceIndex]) + offsetInLane, bytesInLane);
        sizeLeft -= bytesInLane;
        lanePosition++;
        curData += bytesInLane;
    }

    while (sizeLeft >= SnP_laneLengthInBytes) {
        *(uint64_t*)curData = statesAsLanes[(lanePosition << 1) + instanceIndex];
        sizeLeft -= SnP_laneLengthInBytes;
        lanePosition++;
        curData += SnP_laneLengthInBytes;
    }

    if (sizeLeft > 0) {
        memcpy(curData, &statesAsLanes[(lanePosition << 1) + instanceIndex], sizeLeft);
    }
}

static inline void keccakx2_inc_init(keccakx2_state *state) {
    memset(state->s, 0, sizeof(state->s));
    state->offset = 0;
}

static inline void keccakx2_inc_absorb(keccakx2_state *state, const uint8_t *in0, const uint8_t *in1, size_t in_len) {
    size_t remaining = in_len;
    const uint8_t *cur0 = in0;
    const uint8_t *cur1 = in1;

    if (state->offset == 0 && in_len % WORD_BYTES == 0) {
        size_t lanes = in_len / WORD_BYTES;
        while (lanes > 0) {
            size_t this_lanes = (lanes >= MAX_LANES) ? MAX_LANES : lanes;
            KeccakP1600times2_AddLanesAll(state, cur0, cur1, this_lanes);
            cur0 += this_lanes * WORD_BYTES;
            cur1 += this_lanes * WORD_BYTES;
            if (this_lanes == MAX_LANES) {
                KeccakF1600_StatePermutex2(state->s);
            } else {
                state->offset = this_lanes * WORD_BYTES;
            }
            lanes -= this_lanes;
        }
    } else {
        while (remaining + state->offset >= RATE) {
            size_t chunk = RATE - state->offset;
            KeccakP1600times2_AddBytes(state, 0, cur0, state->offset, chunk);
            KeccakP1600times2_AddBytes(state, 1, cur1, state->offset, chunk);
            cur0 += chunk;
            cur1 += chunk;
            remaining -= chunk;
            KeccakF1600_StatePermutex2(state->s);
            state->offset = 0;
        }
        if (remaining > 0) {
            KeccakP1600times2_AddBytes(state, 0, cur0, state->offset, remaining);
            KeccakP1600times2_AddBytes(state, 1, cur1, state->offset, remaining);
            state->offset += remaining;
        }
    }
}

static inline void keccakx2_inc_finalize(keccakx2_state *state) {
    uint8_t pad = DS;
    if (state->offset == RATE - 1) {
        pad |= 0x80;
        KeccakP1600times2_AddBytes(state, 0, &pad, state->offset, 1);
        KeccakP1600times2_AddBytes(state, 1, &pad, state->offset, 1);
    } else {
        KeccakP1600times2_AddBytes(state, 0, &pad, state->offset, 1);
        KeccakP1600times2_AddBytes(state, 1, &pad, state->offset, 1);
        pad = 0x80;
        KeccakP1600times2_AddBytes(state, 0, &pad, RATE - 1, 1);
        KeccakP1600times2_AddBytes(state, 1, &pad, RATE - 1, 1);
    }
    state->offset = 0;
}

static inline void keccakx2_inc_squeeze(keccakx2_state *state, unsigned char *out0, unsigned char *out1, unsigned int out_len) {
    size_t remaining = out_len;
    unsigned char *cur0 = out0;
    unsigned char *cur1 = out1;

    if (state->offset == 0 && out_len % WORD_BYTES == 0) {
        size_t lanes = out_len / WORD_BYTES;
        while (lanes > 0) {
            KeccakF1600_StatePermutex2(state->s);
            size_t this_lanes = (lanes >= MAX_LANES) ? MAX_LANES : lanes;
            KeccakP1600times2_ExtractLanesAll(state, cur0, cur1, this_lanes);
            cur0 += this_lanes * WORD_BYTES;
            cur1 += this_lanes * WORD_BYTES;
            lanes -= this_lanes;
            state->offset = (lanes > 0) ? RATE - this_lanes * WORD_BYTES : 0;
        }
    } else {
        size_t avail = state->offset;
        size_t chunk = (remaining < avail) ? remaining : avail;

        KeccakP1600times2_ExtractBytes(state, 0, cur0, RATE - state->offset, chunk);
        KeccakP1600times2_ExtractBytes(state, 1, cur1, RATE - state->offset, chunk);
        cur0 += chunk;
        cur1 += chunk;
        remaining -= chunk;
        state->offset -= chunk;

        while (remaining > 0) {
            KeccakF1600_StatePermutex2(state->s);
            chunk = (remaining < RATE) ? remaining : RATE;
            KeccakP1600times2_ExtractBytes(state, 0, cur0, 0, chunk);
            KeccakP1600times2_ExtractBytes(state, 1, cur1, 0, chunk);
            cur0 += chunk;
            cur1 += chunk;
            remaining -= chunk;
            state->offset = RATE - chunk;
        }
    }
}

static inline void xof_shake_x2_init(SHAKE_X2_STATE_STRUCT *states) {
    keccakx2_inc_init(states);
}

static inline void xof_shake_x2_update(SHAKE_X2_STATE_STRUCT *states,
                                      const unsigned char *in0,
                                      const unsigned char *in1,
                                      uint32_t singleInputByteLen) {
    keccakx2_inc_absorb(states, in0, in1, singleInputByteLen);
}

static inline void xof_shake_x2_final(SHAKE_X2_STATE_STRUCT *states) {
    keccakx2_inc_finalize(states);
}

static inline void xof_shake_x2_extract(SHAKE_X2_STATE_STRUCT *states,
                                        unsigned char *out0,
                                        unsigned char *out1,
                                        uint32_t singleOutputByteLen) {
    keccakx2_inc_squeeze(states, out0, out1, singleOutputByteLen);
}

// #include <arm_neon.h>

// typedef uint64x2_t v128;
// typedef struct {
//     v128 s[25];
//     uint64_t offset;
// } keccakx2_state;

// #define RATE SHAKE128_RATE

// #define DS (0x1F)
// #define WORD (64)
// #define WORD_BYTES (WORD / 8)
// #define MAX_LANES (RATE / (WORD / 8))

// #define SHAKE_X2_STATE_STRUCT keccakx2_state

// #define NROUNDS 24

// /* Keccak round constants */
// static const uint64_t KeccakF_RoundConstants[NROUNDS] = {
//     (uint64_t)0x0000000000000001ULL,(uint64_t)0x0000000000008082ULL,(uint64_t)0x800000000000808aULL,(uint64_t)0x8000000080008000ULL,
//     (uint64_t)0x000000000000808bULL,(uint64_t)0x0000000080000001ULL,(uint64_t)0x8000000080008081ULL,(uint64_t)0x8000000000008009ULL,
//     (uint64_t)0x000000000000008aULL,(uint64_t)0x0000000000000088ULL,(uint64_t)0x0000000080008009ULL,(uint64_t)0x000000008000000aULL,
//     (uint64_t)0x000000008000808bULL,(uint64_t)0x800000000000008bULL,(uint64_t)0x8000000000008089ULL,(uint64_t)0x8000000000008003ULL,
//     (uint64_t)0x8000000000008002ULL,(uint64_t)0x8000000000000080ULL,(uint64_t)0x000000000000800aULL,(uint64_t)0x800000008000000aULL,
//     (uint64_t)0x8000000080008081ULL,(uint64_t)0x8000000000008080ULL,(uint64_t)0x0000000080000001ULL,(uint64_t)0x8000000080008008ULL
// };

// extern void _f1600x2(v128 *, const uint64_t *);
// static inline
// void KeccakF1600_StatePermutex2(v128 state[25]) {
//     _f1600x2(state, KeccakF_RoundConstants);
// }

// #define SnP_laneLengthInBytes 8
// #define laneIndex(instanceIndex, lanePosition) ((lanePosition<<1) + instanceIndex)

// #define LOAD2_64(low, high) vcombine_u64(vcreate_u64(low), vcreate_u64(high))
// #define LOAD6464(a, b) vcombine_u64(vcreate_u64(b), vcreate_u64(a)) // high: a, low: b
// #define XOReq128(a, b) ((a) = veorq_u64((a), (b)))

// #define LOAD128(a)          vld1q_u64(a)
// #define STORE128(a, b)      vst1q_u64((uint64_t *)(a), b)
// #define STORE64L(a, b)      vst1_u64(a, vget_low_u64(b))
// #define STORE64H(a, b)      vst1_u64(a, vget_high_u64(b))

// #define UNPACKL(a, b)  vzip1q_u64((a), (b))  // { a[0], b[0] }
// #define UNPACKH(a, b)  vzip2q_u64((a), (b))  // { a[1], b[1] }

// static inline
// void KeccakP1600times2_AddBytes(keccakx2_state *state, unsigned int instanceIndex, const unsigned char *data, unsigned int offset, unsigned int length) {
//     unsigned int sizeLeft = length;
//     unsigned int lanePosition = offset/SnP_laneLengthInBytes;
//     unsigned int offsetInLane = offset%SnP_laneLengthInBytes;
//     const unsigned char *curData = data;
//     uint64_t *statesAsLanes = (uint64_t *)state->s;

//     if ((sizeLeft > 0) && (offsetInLane != 0)) {
//         unsigned int bytesInLane = SnP_laneLengthInBytes - offsetInLane;
//         uint64_t lane = 0;
//         if (bytesInLane > sizeLeft)
//             bytesInLane = sizeLeft;
//         memcpy((unsigned char*)&lane + offsetInLane, curData, bytesInLane);
//         statesAsLanes[laneIndex(instanceIndex, lanePosition)] ^= lane;
//         sizeLeft -= bytesInLane;
//         lanePosition++;
//         curData += bytesInLane;
//     }

//     while(sizeLeft >= SnP_laneLengthInBytes) {
//         uint64_t lane = *((const uint64_t*)curData);
//         statesAsLanes[laneIndex(instanceIndex, lanePosition)] ^= lane;
//         sizeLeft -= SnP_laneLengthInBytes;
//         lanePosition++;
//         curData += SnP_laneLengthInBytes;
//     }

//     if (sizeLeft > 0) {
//         uint64_t lane = 0;
//         memcpy(&lane, curData, sizeLeft);
//         statesAsLanes[laneIndex(instanceIndex, lanePosition)] ^= lane;
//     }
// }

// static inline
// void KeccakP1600times2_AddLanesAll(keccakx2_state *state, const unsigned char *data, unsigned int laneCount, unsigned int laneOffset)
// {
//     v128 *stateAsLanes = state->s;
//     unsigned int i;
//     const uint64_t *curData0 = (const uint64_t *)data;
//     const uint64_t *curData1 = (const uint64_t *)(data+laneOffset*SnP_laneLengthInBytes);
//     #define XOR_In( argIndex )  XOReq128( stateAsLanes[argIndex], LOAD6464(curData1[argIndex], curData0[argIndex]))
//     if ( laneCount >= 17 )  {
//         XOR_In( 0 );
//         XOR_In( 1 );
//         XOR_In( 2 );
//         XOR_In( 3 );
//         XOR_In( 4 );
//         XOR_In( 5 );
//         XOR_In( 6 );
//         XOR_In( 7 );
//         XOR_In( 8 );
//         XOR_In( 9 );
//         XOR_In( 10 );
//         XOR_In( 11 );
//         XOR_In( 12 );
//         XOR_In( 13 );
//         XOR_In( 14 );
//         XOR_In( 15 );
//         XOR_In( 16 );
//         if ( laneCount >= 21 )  {
//             XOR_In( 17 );
//             XOR_In( 18 );
//             XOR_In( 19 );
//             XOR_In( 20 );
//             for(i=21; i<laneCount; i++)
//                 XOR_In( i );
//         }
//         else {
//             for(i=17; i<laneCount; i++)
//                 XOR_In( i );
//         }
//     }
//     else {
//         for(i=0; i<laneCount; i++)
//             XOR_In( i );
//     }
//     #undef  XOR_In
// }

// static inline
// void KeccakP1600times2_ExtractLanesAll(const keccakx2_state *states, unsigned char *data, unsigned int laneCount, unsigned int laneOffset) {
//     const uint64_t *stateAsLanes = (const uint64_t *)states->s;
//     v128 lanes;
//     unsigned int i;
//     uint64_t *curData0 = (uint64_t *)data;
//     uint64_t *curData1 = (uint64_t *)(data+laneOffset*SnP_laneLengthInBytes);
//     #define Extr( argIndex )    lanes = LOAD128(&stateAsLanes[argIndex<<1]),          \
//                                 STORE64L(&curData0[argIndex], lanes ),              \
//                                 STORE64H(&curData1[argIndex], lanes )
//     #define Extr2( argIndex )   lanes0 = LOAD128(&stateAsLanes[argIndex<<1]),         \
//                                 lanes1 = LOAD128(&stateAsLanes[(argIndex+1)<<1]),     \
//                                 lanes =  UNPACKL( lanes0, lanes1 ),                 \
//                                 lanes0 = UNPACKH( lanes0, lanes1 ),                 \
//                                 STORE128(&curData0[argIndex], lanes ),    \
//                                 STORE128(&curData1[argIndex], lanes0)
//     if ( laneCount >= 16 )  {
//         v128 lanes0, lanes1;
//         Extr2( 0 );
//         Extr2( 2 );
//         Extr2( 4 );
//         Extr2( 6 );
//         Extr2( 8 );
//         Extr2( 10 );
//         Extr2( 12 );
//         Extr2( 14 );
//         if ( laneCount >= 20 )  {
//             Extr2( 16 );
//             Extr2( 18 );
//             for(i=20; i<laneCount; i++)
//                 Extr( i );
//         }
//         else {
//             for(i=16; i<laneCount; i++)
//                 Extr( i );
//         }
//     }
//     #undef  Extr2
//     else {
//         for(i=0; i<laneCount; i++)
//             Extr( i );
//     }
//     #undef  Extr
// }

// static inline
// void KeccakP1600times2_ExtractBytes(keccakx2_state *states, unsigned int instanceIndex, unsigned char *data, unsigned int offset, unsigned int length)
// {
//     unsigned int sizeLeft = length;
//     unsigned int lanePosition = offset/SnP_laneLengthInBytes;
//     unsigned int offsetInLane = offset%SnP_laneLengthInBytes;
//     unsigned char *curData = data;
//     const uint64_t *statesAsLanes = (const uint64_t *)states->s;

//     if ((sizeLeft > 0) && (offsetInLane != 0)) {
//         unsigned int bytesInLane = SnP_laneLengthInBytes - offsetInLane;
//         if (bytesInLane > sizeLeft)
//             bytesInLane = sizeLeft;
//         memcpy( curData, ((unsigned char *)&statesAsLanes[laneIndex(instanceIndex, lanePosition)]) + offsetInLane, bytesInLane);
//         sizeLeft -= bytesInLane;
//         lanePosition++;
//         curData += bytesInLane;
//     }

//     while(sizeLeft >= SnP_laneLengthInBytes) {
//         *(uint64_t*)curData = statesAsLanes[laneIndex(instanceIndex, lanePosition)];
//         sizeLeft -= SnP_laneLengthInBytes;
//         lanePosition++;
//         curData += SnP_laneLengthInBytes;
//     }

//     if (sizeLeft > 0) {
//         memcpy( curData, &statesAsLanes[laneIndex(instanceIndex, lanePosition)], sizeLeft);
//     }
// }

// static inline
// void keccakx2_inc_init(keccakx2_state *state)
// {
//     memset(state, 0, sizeof(keccakx2_state));
//     state->offset = 0;
// }

// static inline
// void keccakx2_inc_absorb(keccakx2_state *state,
//                          const uint8_t *in0,
//                          const uint8_t *in1,
//                          size_t in_len)
// {
//     unsigned int total_len = 2 * in_len;
//     unsigned char *ins = (unsigned char *)malloc(total_len * sizeof(unsigned char));
//     assert(ins != NULL);
//     uint8_t* original_ins = ins;
//     memcpy(ins, in0, in_len);
//     memcpy(ins + in_len, in1, in_len);

//     if (state->offset == 0 && in_len % WORD_BYTES == 0) {
//         int lanes = in_len * 8 / WORD;
//         int lane_offset = lanes;
//         while (lanes > 0) {
//             if (lanes >= MAX_LANES) {
//                 KeccakP1600times2_AddLanesAll(state, ins, MAX_LANES, lane_offset);
//                 KeccakF1600_StatePermutex2(state->s);
//                 lanes -= MAX_LANES;
//                 ins += MAX_LANES * WORD_BYTES;
//                 state->offset = 0;
//             } else {
//                 KeccakP1600times2_AddLanesAll(state, ins, lanes, lane_offset);
//                 state->offset = lanes * WORD_BYTES;
//                 lanes = 0;
//             }
//         }
//     } else {
//         while (in_len + state->offset >= RATE) {
//             for (int instance = 0; instance < 2; instance++) {
//                 KeccakP1600times2_AddBytes(state,
//                                            instance,
//                                            ins + instance * (total_len/2),
//                                            state->offset,
//                                            RATE - state->offset);
//             }
//             in_len -= (RATE - state->offset);
//             ins += (RATE - state->offset);
//             KeccakF1600_StatePermutex2(state->s);
//             state->offset = 0;
//         }

//         for (int instance = 0; instance < 2; instance++) {
//             KeccakP1600times2_AddBytes(state,
//                                        instance,
//                                        ins + instance * (total_len/2),
//                                        state->offset,
//                                        in_len);
//         }
//         state->offset += in_len;
//     }
//     free(original_ins);
// }

// static inline
// void keccakx2_inc_finalize(keccakx2_state *state)
// {
//     uint8_t ds = DS;
//     if(state->offset == RATE - 1) {
//         ds |= 128;
//         for(int instance=0; instance<2; instance++) {
//             KeccakP1600times2_AddBytes(state, instance, &ds, state->offset, 1);
//         }
//     } else {
//         for(int instance=0; instance<2; instance++) {
//             KeccakP1600times2_AddBytes(state, instance, &ds, state->offset, 1);
//         }
//         ds = 128;
//         for(int instance=0; instance<2; instance++) {
//             KeccakP1600times2_AddBytes(state, instance, &ds, RATE - 1, 1);
//         }
//     }
//     state->offset = 0;
// }

// static inline
// void keccakx2_inc_squeeze(keccakx2_state *state, unsigned char *out0, unsigned char *out1, unsigned int out_len)
// {
//     unsigned int total_len = 2 * out_len;
//     unsigned char *outs = (unsigned char *)malloc(total_len * sizeof(unsigned char));
//     uint8_t* original_outs = outs;
//     int original_out_len = out_len;

//     if (state->offset == 0 && out_len % WORD_BYTES == 0) {
//         int lanes = out_len * 8 / WORD;
//         int lane_offset = lanes;
//         while (lanes > 0) {
//             KeccakF1600_StatePermutex2(state->s);
//             if (lanes >= MAX_LANES) {
//                 KeccakP1600times2_ExtractLanesAll(state, outs, MAX_LANES, lane_offset);
//                 lanes -= MAX_LANES;
//                 outs += MAX_LANES * WORD_BYTES;
//                 state->offset = 0;
//             } else {
//                 KeccakP1600times2_ExtractLanesAll(state, outs, lanes, lane_offset);
//                 state->offset = RATE - (lanes * WORD_BYTES);
//                 lanes = 0;
//             }
//         }
//     } else {
//         unsigned int len = (out_len < state->offset) ? out_len : state->offset;

//         for (int instance = 0; instance < 2; instance++) {
//             KeccakP1600times2_ExtractBytes(state, instance,
//                 outs + instance * (total_len / 2), RATE - state->offset, len);
//         }
//         outs += len;
//         out_len -= len;
//         state->offset -= len;

//         while (out_len > 0) {
//             KeccakF1600_StatePermutex2(state->s);
//             len = (out_len < RATE) ? out_len : RATE;
//             for (int instance = 0; instance < 2; instance++) {
//                 KeccakP1600times2_ExtractBytes(state, instance,
//                 outs + instance * (total_len / 2), 0, len);
//             }
//             outs += len;
//             out_len -= len;
//             state->offset = RATE - len;
//         }
//     }
//     memcpy(out0, original_outs, (total_len/2));
//     memcpy(out1, original_outs+original_out_len, (total_len/2));
//     free(original_outs);
// }


// static inline void xof_shake_x2_init(SHAKE_X2_STATE_STRUCT *states) {
//    keccakx2_inc_init(states);
// }
// static inline void xof_shake_x2_update(SHAKE_X2_STATE_STRUCT *states,
//                       const unsigned char *in0,
//                       const unsigned char *in1,
//                       uint32_t singleInputByteLen) {
//    keccakx2_inc_absorb(states, in0, in1, singleInputByteLen);
// }
// static inline void xof_shake_x2_final(SHAKE_X2_STATE_STRUCT *states) {
//    keccakx2_inc_finalize(states);
// }
// static inline void xof_shake_x2_extract(SHAKE_X2_STATE_STRUCT *states,
//                        unsigned char *out0,
//                        unsigned char *out1,
//                        uint32_t singleOutputByteLen){
//    keccakx2_inc_squeeze(states, out0, out1, singleOutputByteLen);
// }

typedef struct {
   SHAKE_STATE_STRUCT state1;
   SHAKE_X2_STATE_STRUCT state2;
} par_shake_ctx;

#endif

