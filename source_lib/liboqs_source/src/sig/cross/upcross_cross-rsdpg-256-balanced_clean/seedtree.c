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
#include <string.h> // memcpy(...), memset(...)
#include "arm_sve.h"
#include "seedtree.h"

#define LEFT_CHILD(i) (2*(i)+1)
#define RIGHT_CHILD(i) (2*(i)+2)
#define PARENT(i) ( ((i)%2) ? (((i)-1)/2) : (((i)-2)/2) )
#define SIBLING(i) ( ((i)%2) ? (i)+1 : (i)-1 )

/* Seed tree implementation. The binary seed tree is linearized into an array
 * from root to leaves, and from left to right.
 */

#define TO_PUBLISH 1
#define NOT_TO_PUBLISH 0

/*****************************************************************************/
/**
 * const unsigned char *indices: input parameter denoting an array
 * with a number of binary cells equal to "leaves" representing
 * the labels of the nodes identified as leaves of the tree[...]
 * passed as second parameter.
 * A label = 1 means that the byteseed of the node having the same index
 * has to be released; = 0, otherwise.
 *
 * unsigned char *tree: input/output parameter denoting an array
 * with a number of binary cells equal to "2*leaves-1";
 * the first "leaves" cells (i.e., the ones with positions from 0 to leaves-1)
 * are the ones that will be modified by the current subroutine,
 * the last "leaves" cells will be a copy of the input array passed as first
 * parameter.
 *
 * uint64_t leaves: input parameter;
 *
 */

static
void label_leaves(unsigned char flag_tree[NUM_NODES_SEED_TREE],
                  const unsigned char indices_to_publish[T]) {
	const uint16_t cons_leaves[TREE_SUBROOTS] = TREE_CONSECUTIVE_LEAVES;
	const uint16_t leaves_start_indices[TREE_SUBROOTS] = TREE_LEAVES_START_INDICES;

	unsigned int cnt = 0;
	for (size_t i = 0; i < TREE_SUBROOTS; i++) {
		for (size_t j = 0; j < cons_leaves[i]; j++) {
			flag_tree[leaves_start_indices[i] + j] = indices_to_publish[cnt];
			cnt++;
		}
	}
}
#if defined(OQS_ENABLE_SVE2)
static void compute_seeds_to_publish(
    unsigned char flags_tree[NUM_NODES_SEED_TREE],
    const unsigned char indices_to_publish[T]) 
{
    // 1. 严格按照原逻辑初始化叶子
    label_leaves(flags_tree, indices_to_publish);

    const uint16_t off[LOG2(T) + 1] = TREE_OFFSETS;
    const uint16_t npl[LOG2(T) + 1] = TREE_NODES_PER_LEVEL;
    const uint16_t leaves_start_indices[TREE_SUBROOTS] = TREE_LEAVES_START_INDICES;

    unsigned int start_node = leaves_start_indices[0];

    for (int level = LOG2(T); level > 0; level--) {
        uint16_t parent_adj = off[level - 1] >> 1;
        
        // 这里的循环步长和索引必须与原代码完全一致
        // 原代码是 i = npl[level] - 2; i >= 0; i -= 2
        // 我们改为正向循环以便 CPU 预取，并进行 4 倍展开
        int i = 0;
        int num_nodes = (int)npl[level];

        // 标量展开优化：减少分支开销，保持计算逻辑严谨
        for (; i <= num_nodes - 8; i += 8) {
            for (int k = 0; k < 8; k += 2) {
                uint16_t cur = start_node + i + k;
                // 严格保留原公式
                uint16_t sib = SIBLING(cur);
                uint16_t par = PARENT(cur) + parent_adj;
                
                // 使用位运算逻辑消除 if 分支
                flags_tree[par] = (flags_tree[cur] == TO_PUBLISH) && 
                                  (flags_tree[sib] == TO_PUBLISH);
            }
        }

        // 处理剩余节点（尾部处理）
        for (; i <= num_nodes - 2; i += 2) {
            uint16_t cur = start_node + i;
            uint16_t par = PARENT(cur) + parent_adj;
            flags_tree[par] = (flags_tree[cur] == TO_PUBLISH) && 
                              (flags_tree[SIBLING(cur)] == TO_PUBLISH);
        }

        // 跨层跳转逻辑必须保持原样
        start_node -= npl[level - 1];
    }
}
#else
static void compute_seeds_to_publish(
    /* linearized binary tree of boolean nodes containing
     * flags for each node 1-filled nodes are to be released */
    unsigned char flags_tree_to_publish[NUM_NODES_SEED_TREE],
    /* Boolean Array indicating which of the T seeds must be
     * released convention as per the above defines */
    const unsigned char indices_to_publish[T]) {
	/* the indices to publish may be less than the full leaves, copy them
	 * into the linearized tree leaves */
	label_leaves(flags_tree_to_publish, indices_to_publish);

	const uint16_t off[LOG2(T) + 1] = TREE_OFFSETS;
	const uint16_t npl[LOG2(T) + 1] = TREE_NODES_PER_LEVEL;
	const uint16_t leaves_start_indices[TREE_SUBROOTS] = TREE_LEAVES_START_INDICES;

	/* compute the value for the internal nodes of the tree starting from the
	 * the leaves, right to left */
	unsigned int start_node = leaves_start_indices[0];
	for (int level = LOG2(T); level > 0; level--) {
		for (int i = npl[level] - 2; i >= 0; i -= 2) {
			uint16_t current_node = start_node + i;
			uint16_t parent_node = PARENT(current_node) + (off[level - 1] >> 1);

			flags_tree_to_publish[parent_node] = (flags_tree_to_publish[current_node] == TO_PUBLISH)
			                                     && (flags_tree_to_publish[SIBLING(current_node)] == TO_PUBLISH);
		}
		start_node -= npl[level - 1];
	}
} /* end compute_seeds_to_publish */
#endif
/**
 * unsigned char *seed_tree:
 * it is intended as an output parameter;
 * storing the linearized seed tree
 *
 * The root seed is taken as a parameter.
 * The seed of its TWO children are computed expanding (i.e., shake128...) the
 * entropy in "salt" + "seedBytes of the parent" +
 *            "int, encoded over 16 bits - uint16_t,  associated to each node
 *             from roots to leaves layer-by-layer from left to right,
 *             counting from 0 (the integer bound with the root node)"
 */
#if defined(OQS_ENABLE_SVE2)
void gen_seed_tree(unsigned char seed_tree[NUM_NODES_SEED_TREE * SEED_LENGTH_BYTES],
                   const unsigned char root_seed[SEED_LENGTH_BYTES],
                   const unsigned char salt[SALT_LENGTH_BYTES]) {
    unsigned char csprng_input1[CSPRNG_INPUT_LENGTH];
    unsigned char csprng_input2[CSPRNG_INPUT_LENGTH];
    
    /* Pre-fill the salt part for both input buffers */
    memcpy(csprng_input1 + SEED_LENGTH_BYTES, salt, SALT_LENGTH_BYTES);
    memcpy(csprng_input2 + SEED_LENGTH_BYTES, salt, SALT_LENGTH_BYTES);

    /* Set the root seed in the tree */
    memcpy(seed_tree, root_seed, SEED_LENGTH_BYTES);

    const uint16_t off[LOG2(T) + 1] = TREE_OFFSETS;
    const uint16_t npl[LOG2(T) + 1] = TREE_NODES_PER_LEVEL;
    const uint16_t lpl[LOG2(T) + 1] = TREE_LEAVES_PER_LEVEL;

    int start_node = 0;
    for (int level = 0; level < LOG2(T); level++) {
        int nodes_to_expand = npl[level] - lpl[level];
        int node_in_level = 0;

        /* 2-way Parallel expansion: Process 2 fathers per iteration */
        for (; node_in_level <= nodes_to_expand - 2; node_in_level += 2) {
            uint16_t father1 = start_node + node_in_level;
            uint16_t father2 = start_node + node_in_level + 1;
            
            uint16_t left_child1 = LEFT_CHILD(father1) - off[level];
            uint16_t left_child2 = LEFT_CHILD(father2) - off[level];

            /* Prepare inputs for both fathers */
            memcpy(csprng_input1, seed_tree + father1 * SEED_LENGTH_BYTES, SEED_LENGTH_BYTES);
            memcpy(csprng_input2, seed_tree + father2 * SEED_LENGTH_BYTES, SEED_LENGTH_BYTES);

            uint16_t dsc1 = CSPRNG_DOMAIN_SEP_CONST + father1;
            uint16_t dsc2 = CSPRNG_DOMAIN_SEP_CONST + father2;

            /* Use the parallel XOF functions */
            PAR_CSPRNG_STATE_T states;
            par_xof_input(2, &states, csprng_input1, csprng_input2, CSPRNG_INPUT_LENGTH, dsc1, dsc2);
            
            /* Each expansion generates 2 children (2 * SEED_LENGTH_BYTES) */
            par_xof_output(2, &states, 
                           seed_tree + left_child1 * SEED_LENGTH_BYTES, 
                           seed_tree + left_child2 * SEED_LENGTH_BYTES, 
                           2 * SEED_LENGTH_BYTES);
        }

        /* Handle the remaining father node if nodes_to_expand is odd */
        if (node_in_level < nodes_to_expand) {
            uint16_t father_node = start_node + node_in_level;
            uint16_t left_child_node = LEFT_CHILD(father_node) - off[level];
            
            memcpy(csprng_input1, seed_tree + father_node * SEED_LENGTH_BYTES, SEED_LENGTH_BYTES);
            uint16_t domain_sep = CSPRNG_DOMAIN_SEP_CONST + father_node;

            CSPRNG_STATE_T tree_csprng_state;
            csprng_initialize(&tree_csprng_state, csprng_input1, CSPRNG_INPUT_LENGTH, domain_sep);
            csprng_randombytes(seed_tree + left_child_node * SEED_LENGTH_BYTES,
                               2 * SEED_LENGTH_BYTES,
                               &tree_csprng_state);
            csprng_release(&tree_csprng_state);
        }
        
        start_node += npl[level];
    }
}
#else
void gen_seed_tree(unsigned char seed_tree[NUM_NODES_SEED_TREE * SEED_LENGTH_BYTES],
                   const unsigned char root_seed[SEED_LENGTH_BYTES],
                   const unsigned char salt[SALT_LENGTH_BYTES]) {
	/* input buffer to the CSPRNG, contains the seed to be expanded, a salt,
	 * and the integer index of the node being expanded for domain separation */
	unsigned char csprng_input[CSPRNG_INPUT_LENGTH];
	CSPRNG_STATE_T tree_csprng_state;
	memcpy(csprng_input + SEED_LENGTH_BYTES, salt, SALT_LENGTH_BYTES);

	/* Set the root seed in the tree from the received parameter */
	memcpy(seed_tree, root_seed, SEED_LENGTH_BYTES);

	/* off contains the offsets required to move between two layers in order
	 * to compensate for the truncation.
	 * npl contains the number of nodes per level.
	 * lpl contains the number of leaves per level
	 * */
	const uint16_t off[LOG2(T) + 1] = TREE_OFFSETS;
	const uint16_t npl[LOG2(T) + 1] = TREE_NODES_PER_LEVEL;
	const uint16_t lpl[LOG2(T) + 1] = TREE_LEAVES_PER_LEVEL;

	/* Generate the log_2(t) layers from the root, each iteration generates a tree
	 * level; iterate on nodes of the parent level; the leaf nodes on each level
	 * don't need to be expanded, thus only iterate to npl[level]-lpl[level] */
	int start_node = 0;
	for (int level = 0; level < LOG2(T); level++) {
		for (int node_in_level = 0; node_in_level < npl[level] - lpl[level]; node_in_level++ ) {
			uint16_t father_node = start_node + node_in_level;
			uint16_t left_child_node = LEFT_CHILD(father_node) - off[level];

			/* prepare the CSPRNG input to expand the father node */
			memcpy(csprng_input,
			       seed_tree + father_node * SEED_LENGTH_BYTES,
			       SEED_LENGTH_BYTES);

			/* Domain separation using father node index */
			uint16_t domain_sep = CSPRNG_DOMAIN_SEP_CONST + father_node;

			/* Generate the children (stored contiguously).
			 * By construction, the tree has always two children */
			csprng_initialize(&tree_csprng_state, csprng_input, CSPRNG_INPUT_LENGTH, domain_sep);
			csprng_randombytes(seed_tree + left_child_node * SEED_LENGTH_BYTES,
			                   2 * SEED_LENGTH_BYTES,
			                   &tree_csprng_state);
			/* PQClean-edit: CSPRNG release context */
			csprng_release(&tree_csprng_state);
		}
		start_node += npl[level];
	}
} /* end generate_seed_tree */
#endif

/*****************************************************************************/
void seed_leaves(unsigned char rounds_seeds[T * SEED_LENGTH_BYTES],
                 unsigned char seed_tree[NUM_NODES_SEED_TREE * SEED_LENGTH_BYTES]) {
	const uint16_t cons_leaves[TREE_SUBROOTS] = TREE_CONSECUTIVE_LEAVES;
	const uint16_t leaves_start_indices[TREE_SUBROOTS] = TREE_LEAVES_START_INDICES;

	unsigned int cnt = 0;
	for (size_t i = 0; i < TREE_SUBROOTS; i++) {
		for (size_t j = 0; j < cons_leaves[i]; j++) {
			memcpy(rounds_seeds + cnt * SEED_LENGTH_BYTES,
			       seed_tree + (leaves_start_indices[i] + j)*SEED_LENGTH_BYTES,
			       SEED_LENGTH_BYTES);
			cnt++;
		}
	}
}


/*****************************************************************************/
int seed_path(unsigned char *seed_storage,
              // OUTPUT: sequence of seeds to be released
              const unsigned char
              seed_tree[NUM_NODES_SEED_TREE * SEED_LENGTH_BYTES],
              // INPUT: linearized seedtree array with 2T-1 nodes each of size SEED_LENGTH_BYTES
              const unsigned char indices_to_publish[T]
              // INPUT: binary array denoting which node has to be released (cell == TO_PUBLISH) or not
             ) {
	/* complete linearized binary tree containing boolean values determining
	 * if a node is to be released or not according to convention above.
	 * */
	unsigned char flags_tree_to_publish[NUM_NODES_SEED_TREE] = {NOT_TO_PUBLISH};
	compute_seeds_to_publish(flags_tree_to_publish, indices_to_publish);

	const uint16_t off[LOG2(T) + 1] = TREE_OFFSETS;
	const uint16_t npl[LOG2(T) + 1] = TREE_NODES_PER_LEVEL;

	/* no sense in trying to publish the root node, start examining from level 1 */
	int start_node = 1;
	int num_seeds_published = 0;
	for (int level = 1; level <= LOG2(T); level++) {
		for (int node_in_level = 0; node_in_level < npl[level]; node_in_level++ ) {
			uint16_t current_node = start_node + node_in_level;
			uint16_t father_node = PARENT(current_node) + (off[level - 1] >> 1);

			/* if seed is to published and its ancestor/parent node is not,
			 * add it to the seed storage */
			if ( (flags_tree_to_publish[current_node] == TO_PUBLISH) &&
			        (flags_tree_to_publish[father_node] == NOT_TO_PUBLISH) ) {
				memcpy(seed_storage + num_seeds_published * SEED_LENGTH_BYTES,
				       seed_tree + current_node * SEED_LENGTH_BYTES,
				       SEED_LENGTH_BYTES);
				num_seeds_published++;
			}
		}
		start_node += npl[level];
	}
	return num_seeds_published;
} /* end publish_seeds */

/*****************************************************************************/
#if defined(OQS_ENABLE_SVE2)
uint8_t rebuild_tree(unsigned char seed_tree[NUM_NODES_SEED_TREE * SEED_LENGTH_BYTES],
                     const unsigned char indices_to_publish[T],
                     const unsigned char *stored_seeds,
                     const unsigned char salt[SALT_LENGTH_BYTES]) {
    unsigned char flags_tree_to_publish[NUM_NODES_SEED_TREE] = {0};
    compute_seeds_to_publish(flags_tree_to_publish, indices_to_publish);

    unsigned char cs_in1[CSPRNG_INPUT_LENGTH];
    unsigned char cs_in2[CSPRNG_INPUT_LENGTH];
    memcpy(cs_in1 + SEED_LENGTH_BYTES, salt, SALT_LENGTH_BYTES);
    memcpy(cs_in2 + SEED_LENGTH_BYTES, salt, SALT_LENGTH_BYTES);

    const uint16_t off[LOG2(T) + 1] = TREE_OFFSETS;
    const uint16_t npl[LOG2(T) + 1] = TREE_NODES_PER_LEVEL;
    const uint16_t lpl[LOG2(T) + 1] = TREE_LEAVES_PER_LEVEL;

    int nodes_used = 0;
    int start_node = 1;

    for (int level = 1; level <= LOG2(T); level++) {
        int node_in_level = 0;
        int expand_limit = npl[level] - lpl[level];

        /* Attempt to process 2 nodes at a time */
        for (; node_in_level <= npl[level] - 2; node_in_level += 2) {
            uint16_t curr1 = start_node + node_in_level;
            uint16_t curr2 = start_node + node_in_level + 1;

            // Step 1: Handle seed loading (must be sequential to maintain nodes_used order)
            uint16_t nodes[2] = {curr1, curr2};
            for (int j = 0; j < 2; j++) {
                uint16_t father = PARENT(nodes[j]) + (off[level - 1] >> 1);
                if (flags_tree_to_publish[nodes[j]] == TO_PUBLISH && flags_tree_to_publish[father] == NOT_TO_PUBLISH) {
                    memcpy(seed_tree + nodes[j] * SEED_LENGTH_BYTES,
                           stored_seeds + nodes_used * SEED_LENGTH_BYTES,
                           SEED_LENGTH_BYTES);
                    nodes_used++;
                }
            }

            // Step 2: Parallel Expansion check
            int can_expand1 = (flags_tree_to_publish[curr1] == TO_PUBLISH) && (node_in_level < expand_limit);
            int can_expand2 = (flags_tree_to_publish[curr2] == TO_PUBLISH) && ((node_in_level + 1) < expand_limit);

            if (can_expand1 && can_expand2) {
                uint16_t left1 = LEFT_CHILD(curr1) - off[level];
                uint16_t left2 = LEFT_CHILD(curr2) - off[level];
                
                memcpy(cs_in1, seed_tree + curr1 * SEED_LENGTH_BYTES, SEED_LENGTH_BYTES);
                memcpy(cs_in2, seed_tree + curr2 * SEED_LENGTH_BYTES, SEED_LENGTH_BYTES);

                PAR_CSPRNG_STATE_T states;
                par_xof_input(2, &states, cs_in1, cs_in2, CSPRNG_INPUT_LENGTH, 
                              CSPRNG_DOMAIN_SEP_CONST + curr1, CSPRNG_DOMAIN_SEP_CONST + curr2);
                par_xof_output(2, &states, 
                               seed_tree + left1 * SEED_LENGTH_BYTES, 
                               seed_tree + left2 * SEED_LENGTH_BYTES, 
                               2 * SEED_LENGTH_BYTES);
            } else {
                // Fallback: If both don't need expansion, handle them individually
                uint16_t current_nodes[2] = {curr1, curr2};
                for(int j=0; j<2; j++) {
                    int local_idx = node_in_level + j;
                    if ( ( flags_tree_to_publish[current_nodes[j]] == TO_PUBLISH ) && (local_idx < expand_limit ) ) {
                        memcpy(cs_in1, seed_tree + current_nodes[j] * SEED_LENGTH_BYTES, SEED_LENGTH_BYTES);
                        CSPRNG_STATE_T state;
                        csprng_initialize(&state, cs_in1, CSPRNG_INPUT_LENGTH, CSPRNG_DOMAIN_SEP_CONST + current_nodes[j]);
                        csprng_randombytes(seed_tree + (LEFT_CHILD(current_nodes[j]) - off[level]) * SEED_LENGTH_BYTES,
                                           2 * SEED_LENGTH_BYTES, &state);
                        csprng_release(&state);
                    }
                }
            }
        }

        /* Handle the last node if level has odd number of nodes */
        if (node_in_level < npl[level]) {
            uint16_t curr = start_node + node_in_level;
            uint16_t father = PARENT(curr) + (off[level - 1] >> 1);
            if (flags_tree_to_publish[curr] == TO_PUBLISH && flags_tree_to_publish[father] == NOT_TO_PUBLISH) {
                memcpy(seed_tree + curr * SEED_LENGTH_BYTES,
                       stored_seeds + nodes_used * SEED_LENGTH_BYTES,
                       SEED_LENGTH_BYTES);
                nodes_used++;
            }
            if ((flags_tree_to_publish[curr] == TO_PUBLISH) && (node_in_level < expand_limit)) {
                memcpy(cs_in1, seed_tree + curr * SEED_LENGTH_BYTES, SEED_LENGTH_BYTES);
                CSPRNG_STATE_T state;
                csprng_initialize(&state, cs_in1, CSPRNG_INPUT_LENGTH, CSPRNG_DOMAIN_SEP_CONST + curr);
                csprng_randombytes(seed_tree + (LEFT_CHILD(curr) - off[level]) * SEED_LENGTH_BYTES,
                                   2 * SEED_LENGTH_BYTES, &state);
                csprng_release(&state);
            }
        }
        start_node += npl[level];
    }

    uint8_t error = 0;
    for (int i = nodes_used * SEED_LENGTH_BYTES; i < TREE_NODES_TO_STORE * SEED_LENGTH_BYTES; i++) {
        error |= stored_seeds[i];
    }
    return (error == 0);
}
#else
uint8_t rebuild_tree(unsigned char
                     seed_tree[NUM_NODES_SEED_TREE * SEED_LENGTH_BYTES],
                     const unsigned char indices_to_publish[T],
                     const unsigned char *stored_seeds,
                     const unsigned char salt[SALT_LENGTH_BYTES]) {
	/* complete linearized binary tree containing boolean values determining
	 * if a node is to be released or not according to aboves convention
	 */
	unsigned char flags_tree_to_publish[NUM_NODES_SEED_TREE] = {0};
	compute_seeds_to_publish(flags_tree_to_publish, indices_to_publish);

	unsigned char csprng_input[CSPRNG_INPUT_LENGTH];
	CSPRNG_STATE_T tree_csprng_state;

	const uint16_t off[LOG2(T) + 1] = TREE_OFFSETS;
	const uint16_t npl[LOG2(T) + 1] = TREE_NODES_PER_LEVEL;
	const uint16_t lpl[LOG2(T) + 1] = TREE_LEAVES_PER_LEVEL;

	memcpy(csprng_input + SEED_LENGTH_BYTES, salt, SALT_LENGTH_BYTES);

	/* regenerating the seed tree never starts from the root, as it is never
	 * disclosed */
	int nodes_used = 0;
	int start_node = 1;
	for (int level = 1; level <= LOG2(T); level++) {
		for (int node_in_level = 0; node_in_level < npl[level]; node_in_level++ ) {
			uint16_t current_node = start_node + node_in_level;
			uint16_t father_node = PARENT(current_node) + (off[level - 1] >> 1);
			uint16_t left_child = LEFT_CHILD(current_node) - off[level];

			/* if the current node is a seed which was published (thus its father
			 * was not), memcpy it in place */
			if ( flags_tree_to_publish[current_node] == TO_PUBLISH ) {
				if ( flags_tree_to_publish[father_node] == NOT_TO_PUBLISH ) {
					memcpy(seed_tree + current_node * SEED_LENGTH_BYTES,
					       stored_seeds + nodes_used * SEED_LENGTH_BYTES,
					       SEED_LENGTH_BYTES );
					nodes_used++;
				}
			}
			/* If the current node is published and not a leaf, CSPRNG-expand its children.
			 * Since there is no reason of expanding leaves, only iterate to nodes per level (npl)
			 * minus leaves per level (lpl) in each level */
			if ( ( flags_tree_to_publish[current_node] == TO_PUBLISH ) && (node_in_level < npl[level] - lpl[level] ) ) {
				/* prepare the CSPRNG input to expand the children of node current_node */
				memcpy(csprng_input,
				       seed_tree + current_node * SEED_LENGTH_BYTES,
				       SEED_LENGTH_BYTES);

				/* Domain separation using father node index */
				uint16_t domain_sep = CSPRNG_DOMAIN_SEP_CONST + current_node;

				/* expand the children (stored contiguously), by construction always two children */
				csprng_initialize(&tree_csprng_state, csprng_input, CSPRNG_INPUT_LENGTH, domain_sep);
				csprng_randombytes(seed_tree + left_child * SEED_LENGTH_BYTES,
				                   2 * SEED_LENGTH_BYTES,
				                   &tree_csprng_state);
				/* PQClean-edit: CSPRNG release context */
				csprng_release(&tree_csprng_state);
			}
		}
		start_node += npl[level];
	}

	// Check for correct zero padding in the remaining parth of the seed path to
	// prevent trivial forgery
	uint8_t error = 0;
	for (int i = nodes_used * SEED_LENGTH_BYTES; i < TREE_NODES_TO_STORE * SEED_LENGTH_BYTES; i++) {
		error |= stored_seeds[i];
	}
	return (error == 0);
} /* end regenerate_leaves */
#endif
