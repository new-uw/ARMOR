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

#include <stdint.h>
#include <string.h>

#include "csprng_hash.h"
#include "merkle_tree.h"
#include "parameters.h"


#define PARENT(i) ( ((i)%2) ? (((i)-1)/2) : (((i)-2)/2) )
#define SIBLING(i) ( ((i)%2) ? (i)+1 : (i)-1 )

#define CHALLENGE_PROOF_VALUE 0
#define NOT_COMPUTED 0
#define COMPUTED 1

/*****************************************************************************/
static
void place_cmt_on_leaves(unsigned char merkle_tree[NUM_NODES_MERKLE_TREE *
                                               HASH_DIGEST_LENGTH],
                         unsigned char commitments[T][HASH_DIGEST_LENGTH]) {
	const uint16_t cons_leaves[TREE_SUBROOTS] = TREE_CONSECUTIVE_LEAVES;
	const uint16_t leaves_start_indices[TREE_SUBROOTS] = TREE_LEAVES_START_INDICES;

	unsigned int cnt = 0;
	for (size_t i = 0; i < TREE_SUBROOTS; i++) {
		for (size_t j = 0; j < cons_leaves[i]; j++) {
			memcpy(merkle_tree + (leaves_start_indices[i] + j)*HASH_DIGEST_LENGTH,
			       commitments + cnt,
			       HASH_DIGEST_LENGTH);
			cnt++;
		}
	}
}

/*****************************************************************************/
static
void label_leaves(unsigned char flag_tree[NUM_NODES_MERKLE_TREE],
                  const unsigned char challenge[T]) {
	const uint16_t cons_leaves[TREE_SUBROOTS] = TREE_CONSECUTIVE_LEAVES;
	const uint16_t leaves_start_indices[TREE_SUBROOTS] = TREE_LEAVES_START_INDICES;

	unsigned int cnt = 0;
	for (size_t i = 0; i < TREE_SUBROOTS; i++) {
		for (size_t j = 0; j < cons_leaves[i]; j++) {
			if (challenge[cnt] == CHALLENGE_PROOF_VALUE) {
				flag_tree[leaves_start_indices[i] + j] = COMPUTED;
			}
			cnt++;
		}
	}
}

/*****************************************************************************/
#if defined(OQS_ENABLE_SVE2)
void tree_root(uint8_t root[HASH_DIGEST_LENGTH],
               unsigned char tree[NUM_NODES_MERKLE_TREE * HASH_DIGEST_LENGTH],
               unsigned char leaves[T][HASH_DIGEST_LENGTH]) {
    /* off contains the offsets required to move between two layers in order
     * to compensate for the truncation.
     * npl contains the number of nodes per level.
     * leaves_start_indices contains the index of the leftmost leaf of each full binary subtree
     */
    const uint16_t off[LOG2(T) + 1] = TREE_OFFSETS;
    const uint16_t npl[LOG2(T) + 1] = TREE_NODES_PER_LEVEL;
    const uint16_t leaves_start_indices[TREE_SUBROOTS] = TREE_LEAVES_START_INDICES;

    /* Place the commitments on the (unbalanced-) Merkle tree using helper arrays for indexing */
    place_cmt_on_leaves(tree, leaves);

    /* Start hashing the nodes from right to left, starting always with
     * the left-child node */
    unsigned int start_node = leaves_start_indices[0];

    for (int level = LOG2(T); level > 0; level--) {
        int i = npl[level] - 2;

        /* 2-way Parallel loop: Process 2 parents (4 children) per iteration */
        /* Loop condition i >= 2 ensures we have at least 2 pairs (indices i and i-2) to process */
        for (; i >= 2; i -= 4) {
            // --- Pair 1 (Rightmost) ---
            uint16_t current_node_1 = start_node + i;
            uint16_t parent_node_1 = PARENT(current_node_1) + (off[level - 1] >> 1);

            // --- Pair 2 (Left of Pair 1) ---
            uint16_t current_node_2 = start_node + (i - 2);
            uint16_t parent_node_2 = PARENT(current_node_2) + (off[level - 1] >> 1);

            // Fetch children pointers and prepare parent pointers
            // Note: tree + current_node * LEN points to the left child,
            // and since children are contiguous, reading 2*LEN bytes covers both left and right children.
            
            hash_par(2, 
                     tree + parent_node_1 * HASH_DIGEST_LENGTH, // digest_1 (Output)
                     tree + parent_node_2 * HASH_DIGEST_LENGTH, // digest_2 (Output)
                     tree + current_node_1 * HASH_DIGEST_LENGTH, // m_1 (Input children pair 1)
                     tree + current_node_2 * HASH_DIGEST_LENGTH, // m_2 (Input children pair 2)
                     2 * HASH_DIGEST_LENGTH,                     // mlen (2 nodes per hash)
                     HASH_DOMAIN_SEP_CONST,                      // dsc1
                     HASH_DOMAIN_SEP_CONST);                     // dsc2
        }

        /* Handle the remaining single pair if it exists (i.e., if i == 0) */
        if (i == 0) {
            uint16_t current_node = start_node + i;
            uint16_t parent_node = PARENT(current_node) + (off[level - 1] >> 1);

            // Fallback to standard hash for the last item
            hash(tree + parent_node * HASH_DIGEST_LENGTH, 
                 tree + current_node * HASH_DIGEST_LENGTH, 
                 2 * HASH_DIGEST_LENGTH, 
                 HASH_DOMAIN_SEP_CONST);
        }

        start_node -= npl[level - 1];
    }

    /* Root is at first position of the tree */
    memcpy(root, tree, HASH_DIGEST_LENGTH);
}
#else
void tree_root(uint8_t root[HASH_DIGEST_LENGTH],
               unsigned char tree[NUM_NODES_MERKLE_TREE * HASH_DIGEST_LENGTH],
               unsigned char leaves[T][HASH_DIGEST_LENGTH]) {
	/* off contains the offsets required to move between two layers in order
	 * to compensate for the truncation.
	 * npl contains the number of nodes per level.
	 * leaves_start_indices contains the index of the leftmost leaf of each full binary subtree
	 */
	const uint16_t off[LOG2(T) + 1] = TREE_OFFSETS;
	const uint16_t npl[LOG2(T) + 1] = TREE_NODES_PER_LEVEL;
	const uint16_t leaves_start_indices[TREE_SUBROOTS] = TREE_LEAVES_START_INDICES;

	/* Place the commitments on the (unbalanced-) Merkle tree using helper arrays for indexing */
	place_cmt_on_leaves(tree, leaves);

	/* Start hashing the nodes from right to left, starting always with
	 * the left-child node */
	unsigned int start_node = leaves_start_indices[0];
	for (int level = LOG2(T); level > 0; level--) {
		for (int i = npl[level] - 2; i >= 0; i -= 2) {
			uint16_t current_node = start_node + i;
			uint16_t parent_node = PARENT(current_node) + (off[level - 1] >> 1);

			// Fetch both children
			hash(tree + parent_node * HASH_DIGEST_LENGTH, tree + current_node * HASH_DIGEST_LENGTH, 2 * HASH_DIGEST_LENGTH, HASH_DOMAIN_SEP_CONST);
		}
		start_node -= npl[level - 1];
	}

	/* Root is at first position of the tree */
	memcpy(root, tree, HASH_DIGEST_LENGTH);
}
#endif
/*****************************************************************************/
uint16_t tree_proof(uint8_t mtp[HASH_DIGEST_LENGTH * TREE_NODES_TO_STORE],
                    const uint8_t tree[NUM_NODES_MERKLE_TREE * HASH_DIGEST_LENGTH],
                    const uint8_t leaves_to_reveal[T]) {
	/* Label the flag tree to identify computed/valid nodes */
	unsigned char flag_tree[NUM_NODES_MERKLE_TREE] = {NOT_COMPUTED};
	label_leaves(flag_tree, leaves_to_reveal);

	const uint16_t off[LOG2(T) + 1] = TREE_OFFSETS;
	const uint16_t npl[LOG2(T) + 1] = TREE_NODES_PER_LEVEL;
	const uint16_t leaves_start_indices[TREE_SUBROOTS] = TREE_LEAVES_START_INDICES;

	int published = 0;
	unsigned int start_node = leaves_start_indices[0];
	for (int level = LOG2(T); level > 0; level--) {
		for (int i = npl[level] - 2; i >= 0; i -= 2) {
			uint16_t current_node = start_node + i;
			uint16_t parent_node = PARENT(current_node) + (off[level - 1] >> 1);

			flag_tree[parent_node] = (flag_tree[current_node] == COMPUTED) || (flag_tree[SIBLING(current_node)] == COMPUTED);

			/* Add left sibling only if right one was computed but left wasn't */
			if ( (flag_tree[current_node] == NOT_COMPUTED) && (flag_tree[SIBLING(current_node)] == COMPUTED) ) {
				memcpy(mtp + published * HASH_DIGEST_LENGTH, tree + current_node * HASH_DIGEST_LENGTH, HASH_DIGEST_LENGTH);
				published++;
			}

			/* Add right sibling only if left was computed but right wasn't */
			if ( (flag_tree[current_node] == COMPUTED) && (flag_tree[SIBLING(current_node)] == NOT_COMPUTED) ) {
				memcpy(mtp + published * HASH_DIGEST_LENGTH, tree + SIBLING(current_node)*HASH_DIGEST_LENGTH, HASH_DIGEST_LENGTH);
				published++;
			}
		}
		start_node -= npl[level - 1];
	}
	return published;
}

/*****************************************************************************/
#if defined(OQS_ENABLE_SVE2)
uint8_t recompute_root(uint8_t root[HASH_DIGEST_LENGTH],
                       uint8_t recomputed_leaves[T][HASH_DIGEST_LENGTH],
                       const uint8_t mtp[HASH_DIGEST_LENGTH * TREE_NODES_TO_STORE],
                       const uint8_t leaves_to_reveal[T]) {
    uint8_t tree[NUM_NODES_MERKLE_TREE * HASH_DIGEST_LENGTH];
    uint8_t flag_tree[NUM_NODES_MERKLE_TREE] = {NOT_COMPUTED};

    place_cmt_on_leaves(tree, recomputed_leaves);
    label_leaves(flag_tree, leaves_to_reveal);

    const uint16_t off[LOG2(T) + 1] = TREE_OFFSETS;
    const uint16_t npl[LOG2(T) + 1] = TREE_NODES_PER_LEVEL;
    const uint16_t leaves_start_indices[TREE_SUBROOTS] = TREE_LEAVES_START_INDICES;

    unsigned int published = 0;
    unsigned int start_node = leaves_start_indices[0];

    for (int level = LOG2(T); level > 0; level--) {
        int i = npl[level] - 2;

        for (; i >= 2; i -= 4) {
            uint16_t node1 = start_node + i;
            uint16_t node2 = start_node + (i - 2);
            
            // 判断这两组节点是否都需要计算
            int need1 = (flag_tree[node1] == COMPUTED || flag_tree[SIBLING(node1)] == COMPUTED);
            int need2 = (flag_tree[node2] == COMPUTED || flag_tree[SIBLING(node2)] == COMPUTED);

            if (need1 && need2) {
                // 两组都可以并行计算
                uint8_t hash_in1[2 * HASH_DIGEST_LENGTH];
                uint8_t hash_in2[2 * HASH_DIGEST_LENGTH];
                uint16_t parent1 = PARENT(node1) + (off[level - 1] >> 1);
                uint16_t parent2 = PARENT(node2) + (off[level - 1] >> 1);

                // 准备第一组输入 (注意次序：node1 始终是左子节点索引，因为循环是从右向左且 i 为偶数)
                // 原始逻辑中 current_node 实际上就是左子节点
                for (int j = 0; j < 2; j++) {
                    uint16_t target = (j == 0) ? node1 : SIBLING(node1);
                    if (flag_tree[target] == COMPUTED) {
                        memcpy(hash_in1 + j * HASH_DIGEST_LENGTH, tree + target * HASH_DIGEST_LENGTH, HASH_DIGEST_LENGTH);
                    } else {
                        memcpy(hash_in1 + j * HASH_DIGEST_LENGTH, mtp + published * HASH_DIGEST_LENGTH, HASH_DIGEST_LENGTH);
                        published++;
                    }
                }

                // 准备第二组输入
                for (int j = 0; j < 2; j++) {
                    uint16_t target = (j == 0) ? node2 : SIBLING(node2);
                    if (flag_tree[target] == COMPUTED) {
                        memcpy(hash_in2 + j * HASH_DIGEST_LENGTH, tree + target * HASH_DIGEST_LENGTH, HASH_DIGEST_LENGTH);
                    } else {
                        memcpy(hash_in2 + j * HASH_DIGEST_LENGTH, mtp + published * HASH_DIGEST_LENGTH, HASH_DIGEST_LENGTH);
                        published++;
                    }
                }

                hash_par(2, tree + parent1 * HASH_DIGEST_LENGTH, tree + parent2 * HASH_DIGEST_LENGTH,
                         hash_in1, hash_in2, 2 * HASH_DIGEST_LENGTH, HASH_DOMAIN_SEP_CONST, HASH_DOMAIN_SEP_CONST);
                
                flag_tree[parent1] = COMPUTED;
                flag_tree[parent2] = COMPUTED;
            } else {
                // 如果其中有一组不需要计算，则退回到逐个处理逻辑，以保证 published 指针增加的顺序正确
                // 这里处理 i，处理完后 i 会在循环末尾减 2 (通过调整步长或手动处理)
                // 为了简单起见，我们让 i 只退回 2，交给下单次循环处理
                goto handle_single; 
            }
            continue;

        handle_single:
            {
                uint16_t current_node = start_node + i;
                if (flag_tree[current_node] == COMPUTED || flag_tree[SIBLING(current_node)] == COMPUTED) {
                    uint8_t hash_input[2 * HASH_DIGEST_LENGTH];
                    uint16_t parent_node = PARENT(current_node) + (off[level - 1] >> 1);

                    if (flag_tree[current_node] == COMPUTED) {
                        memcpy(hash_input, tree + current_node * HASH_DIGEST_LENGTH, HASH_DIGEST_LENGTH);
                    } else {
                        memcpy(hash_input, mtp + published * HASH_DIGEST_LENGTH, HASH_DIGEST_LENGTH);
                        published++;
                    }

                    if (flag_tree[SIBLING(current_node)] == COMPUTED) {
                        memcpy(hash_input + HASH_DIGEST_LENGTH, tree + SIBLING(current_node)*HASH_DIGEST_LENGTH, HASH_DIGEST_LENGTH);
                    } else {
                        memcpy(hash_input + HASH_DIGEST_LENGTH, mtp + published * HASH_DIGEST_LENGTH, HASH_DIGEST_LENGTH);
                        published++;
                    }

                    hash(tree + parent_node * HASH_DIGEST_LENGTH, hash_input, 2 * HASH_DIGEST_LENGTH, HASH_DOMAIN_SEP_CONST);
                    flag_tree[parent_node] = COMPUTED;
                }
                i += 2; // 抵消外层循环的 i -= 4，使得实际效果为 i -= 2
            }
        }

        // 处理最后剩下的一个节点（如果 i == 0）
        for (; i >= 0; i -= 2) {
            uint16_t current_node = start_node + i;
            if (flag_tree[current_node] == COMPUTED || flag_tree[SIBLING(current_node)] == COMPUTED) {
                uint8_t hash_input[2 * HASH_DIGEST_LENGTH];
                uint16_t parent_node = PARENT(current_node) + (off[level - 1] >> 1);

                if (flag_tree[current_node] == COMPUTED) {
                    memcpy(hash_input, tree + current_node * HASH_DIGEST_LENGTH, HASH_DIGEST_LENGTH);
                } else {
                    memcpy(hash_input, mtp + published * HASH_DIGEST_LENGTH, HASH_DIGEST_LENGTH);
                    published++;
                }

                if (flag_tree[SIBLING(current_node)] == COMPUTED) {
                    memcpy(hash_input + HASH_DIGEST_LENGTH, tree + SIBLING(current_node)*HASH_DIGEST_LENGTH, HASH_DIGEST_LENGTH);
                } else {
                    memcpy(hash_input + HASH_DIGEST_LENGTH, mtp + published * HASH_DIGEST_LENGTH, HASH_DIGEST_LENGTH);
                    published++;
                }

                hash(tree + parent_node * HASH_DIGEST_LENGTH, hash_input, 2 * HASH_DIGEST_LENGTH, HASH_DOMAIN_SEP_CONST);
                flag_tree[parent_node] = COMPUTED;
            }
        }
        start_node -= npl[level - 1];
    }

    memcpy(root, tree, HASH_DIGEST_LENGTH);

    uint8_t error = 0;
    for (int i = published * HASH_DIGEST_LENGTH; i < TREE_NODES_TO_STORE * HASH_DIGEST_LENGTH; i++) {
        error |= mtp[i];
    }
    return (error == 0);
}
#else
uint8_t recompute_root(uint8_t root[HASH_DIGEST_LENGTH],
                       uint8_t recomputed_leaves[T][HASH_DIGEST_LENGTH],
                       const uint8_t mtp[HASH_DIGEST_LENGTH * TREE_NODES_TO_STORE],
                       const uint8_t leaves_to_reveal[T]) {
	uint8_t tree[NUM_NODES_MERKLE_TREE * HASH_DIGEST_LENGTH];
	uint8_t flag_tree[NUM_NODES_MERKLE_TREE] = {NOT_COMPUTED};
	uint8_t hash_input[2 * HASH_DIGEST_LENGTH];

	place_cmt_on_leaves(tree, recomputed_leaves);
	label_leaves(flag_tree, leaves_to_reveal);

	const uint16_t off[LOG2(T) + 1] = TREE_OFFSETS;
	const uint16_t npl[LOG2(T) + 1] = TREE_NODES_PER_LEVEL;
	const uint16_t leaves_start_indices[TREE_SUBROOTS] = TREE_LEAVES_START_INDICES;

	unsigned int published = 0;
	unsigned int start_node = leaves_start_indices[0];
	for (int level = LOG2(T); level > 0; level--) {
		for (int i = npl[level] - 2; i >= 0; i -= 2) {
			uint16_t current_node = start_node + i;
			uint16_t parent_node = PARENT(current_node) + (off[level - 1] >> 1);

			/* Both siblings are unused */
			if (flag_tree[current_node] == NOT_COMPUTED && flag_tree[SIBLING(current_node)] == NOT_COMPUTED) {
				continue;
			}

			/* Process left sibling from the tree if valid, otherwise take it from the merkle proof */
			if (flag_tree[current_node] == COMPUTED) {
				memcpy(hash_input, tree + current_node * HASH_DIGEST_LENGTH, HASH_DIGEST_LENGTH);
			} else {
				memcpy(hash_input, mtp + published * HASH_DIGEST_LENGTH, HASH_DIGEST_LENGTH);
				published++;
			}

			/* Process right sibling from the tree if valid, otherwise take it from the merkle proof */
			if (flag_tree[SIBLING(current_node)] == COMPUTED) {
				memcpy(hash_input + HASH_DIGEST_LENGTH, tree + SIBLING(current_node)*HASH_DIGEST_LENGTH, HASH_DIGEST_LENGTH);
			} else {
				memcpy(hash_input + HASH_DIGEST_LENGTH, mtp + published * HASH_DIGEST_LENGTH, HASH_DIGEST_LENGTH);
				published++;
			}

			/* Hash it and store the digest at the parent node */
			hash(tree + parent_node * HASH_DIGEST_LENGTH, hash_input, sizeof(hash_input), HASH_DOMAIN_SEP_CONST);
			flag_tree[parent_node] = COMPUTED;
		}
		start_node -= npl[level - 1];
	}

	/* Root is at first position of the tree */
	memcpy(root, tree, HASH_DIGEST_LENGTH);

	// Check for correct zero padding in the remaining parth of the Merkle proof to
	// prevent trivial forgery
	uint8_t error = 0;
	for (int i = published * HASH_DIGEST_LENGTH; i < TREE_NODES_TO_STORE * HASH_DIGEST_LENGTH; i++) {
		error |= mtp[i];
	}
	return (error == 0);
}
#endif