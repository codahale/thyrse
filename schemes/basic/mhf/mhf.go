// Package mhf implements the [DEGSample] data-dependent memory-hard function from Blocki & Holman (2025), "Towards
// Practical Data-Dependent Memory-Hard Functions with Optimal Sustained Space Trade-offs."
//
// The MHF is defined by a directed acyclic graph on 5N nodes:
//   - 3N "static" nodes from indegree-reduced EGSample (DRSample ∪ Grates)
//   - 2N "dynamic" challenge-chain nodes with random back-pointers
//
// [DEGSample]: https://arxiv.org/pdf/2508.06795
package mhf

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/bits"

	"github.com/codahale/thyrse"
)

// Hash calculates a memory-hard hash of the given password and salt using the DEGSample construction with the given
// cost and salt parameters. It appends n bytes of output to dst and returns the resulting slice.
//
// The total memory usage required is 5*2**(cost+10) to perform 7*2**(cost+10) operations.
//
// For online operations (i.e., password validation), the cost parameter should be selected so that the total operation
// takes ~100ms; for offline operations (i.e., password-based encryption), the cost parameter should be selected to
// fully use all available memory.
func Hash(domain string, cost uint8, salt, password, dst []byte, n int) []byte {
	// Calculate parameters and allocate memory.
	N := 1 << cost
	totalNodes, staticNodes, gratesCols := 5*N, 3*N, numGratesCols(N)
	blocks := make([][blockSize]byte, totalNodes)

	// Initialize the root protocol and mix in all public parameters.
	root := thyrse.New(domain)
	root.Mix("cost", []byte{cost})
	root.Mix("salt", salt)

	// Fork into data-independent and data-dependent branches.
	branches := root.Fork("data", []byte("independent"), []byte("dependent"))
	id, dd := branches[0], branches[1]

	// Mix the password into the data-dependent branch.
	dd.Mix("password", password)

	// ------------------------------------------------------------------
	// Phase 1: Static part (3N nodes of indegree-reduced EGSample)
	// ------------------------------------------------------------------
	// Source node: a hash of all the parameters.
	dd.Derive("source", blocks[0][:0], blockSize)

	for v := 1; v < staticNodes; v++ {
		p1, p2 := staticParents(id.Clone(), gratesCols, v)
		h := dd.Clone()
		h.Mix("node", binary.AppendUvarint(nil, uint64(v)))
		if p1 >= 0 {
			h.Mix("required", blocks[p1][:])
		}
		if p2 >= 0 {
			h.Mix("optional", blocks[p2][:])
		}
		h.Derive("static", blocks[v][:0], blockSize)
	}

	// ------------------------------------------------------------------
	// Phase 2: Dynamic challenge chain (2N nodes)
	// ------------------------------------------------------------------
	// Each node has:
	//   - A chain edge to the immediately preceding node
	//   - A dynamic back-edge into the static part, derived from
	//     the previous node's label
	//
	// Two Derive calls per node:
	//   1. preLabel = Derive("pre-label") after mixing block[prev] → derive back-pointer
	//   2. block[v] = Derive("dynamic") after additionally mixing block[target]
	//
	// The back-pointer targets the "last sub-node" of a random original
	// node: target = 3 * (preLabel mod N) + 2.

	for v := staticNodes; v < totalNodes; v++ {
		prev := v - 1

		h := dd.Clone()
		h.Mix("prev", blocks[prev][:])

		// Step 1: Compute static pre-label to discover dynamic edge.
		var buf [8]byte
		preLabel := h.Derive("pre-label", buf[:0], 8)

		// Step 2: Derive the back-pointer into the static part.
		r := int(binary.LittleEndian.Uint64(preLabel) % uint64(N))
		target := 3*r + 2 // last sub-node of original node r

		// Step 3: Compute final dynamic label.
		h.Mix("back-pointer", blocks[target][:])
		h.Derive("dynamic", blocks[v][:0], blockSize)
	}

	dd.Mix("final", blocks[totalNodes-1][:])
	return dd.Derive("output", dst, n)
}

// staticParents returns the parent indices (p1, p2) for a node in the indegree-reduced static graph. p2 = -1 means only
// one parent. If both p1 = p2 = -1, then the node is a source.
//
// # Indegree-reduced EGSample parent computation
//
// The union DRS ∪ Grates on N nodes has max indegree 3:
//
//	parent 0: chain       (v-1)           for v ≥ 1
//	parent 1: DRS random  drsParent(v)    for v ≥ 2
//	parent 2: Grates grid gratesParent(v) for v ≥ cols
//
// Indegree reduction (Definition 15 of the paper) expands each original
// node v into 3 sub-nodes {3v, 3v+1, 3v+2}:
//
//	sub-node 3v  : one external parent  → last sub-node of parent[0]
//	sub-node 3v+1: internal chain 3v, external parent → last sub-node of parent[1]
//	sub-node 3v+2: internal chain 3v+1, external parent → last sub-node of parent[2]
//
// "Last sub-node" of original node u is 3u+2. If a parent slot is unused (i.e., original node has < 3 parents), the
// sub-node gets only its internal chain edge (indegree 1).
func staticParents(id *thyrse.Protocol, gratesCols, v int) (int, int) {
	origNode := v / 3
	subIndex := v % 3

	// Collect the original node's parents in order: [chain, drs, grates].
	// Using a fixed-size array to avoid allocation.
	var parents [3]int
	nParents := 0

	if origNode >= 1 {
		parents[nParents] = origNode - 1 // chain edge
		nParents++
	}
	if origNode >= 2 {
		parents[nParents] = drsParent(id, origNode)
		nParents++
	}
	if g := gratesParent(origNode, gratesCols); g >= 0 {
		parents[nParents] = g
		nParents++
	}

	// Map through indegree reduction.
	// "last sub-node of original node u" = 3*u + 2
	lastSub := func(orig int) int { return 3*orig + 2 }

	switch subIndex {
	case 0:
		// First sub-node: one external parent (parent[0]'s last sub-node).
		if nParents >= 1 {
			return lastSub(parents[0]), -1
		}
		return -1, -1 // source node

	case 1:
		// Second sub-node: internal chain from 3v, plus parent[1] external.
		internal := v - 1 // = 3*origNode + 0
		if nParents >= 2 {
			return internal, lastSub(parents[1])
		}
		return internal, -1

	case 2:
		// Third sub-node: internal chain from 3v+1, plus parent[2] external.
		internal := v - 1 // = 3*origNode + 1
		if nParents >= 3 {
			return internal, lastSub(parents[2])
		}
		return internal, -1
	default:
		panic(fmt.Sprintf("invalid subIndex: %v", subIndex))
	}
}

// drsParent returns the parent index of the DRSample node given original node index before indegree reduction (v) and
// the data-independent protocol state.
//
// # DRSample edge computation
//
// DRSample(N) produces a DAG on N nodes with indegree 2:
//
//	edge 1: chain (v-1) → v for all v ≥ 1
//	edge 2: random r(v) → v for all v ≥ 2
//
// The random parent r(v) is drawn so that Pr[r(v)=u] ≥ 1/((v−u)·log v).
//
// We implement this with geometric buckets:
//  1. Pick level j uniformly from {1, …, ⌊log₂(v−1)⌋+1}
//  2. Pick parent uniformly from [v − 2^j,  v − 2^{j−1})
//
// Randomness is derived deterministically from the data-independent protocol state and v.
func drsParent(id *thyrse.Protocol, v int) int {
	if v < 2 {
		return 0
	}

	// Mix in the node index.
	var buf [binary.MaxVarintLen64]byte
	id.Mix("node", binary.AppendUvarint(buf[:0], uint64(v)))

	// Derive the unreduced level and offset.
	level := binary.LittleEndian.Uint64(id.Derive("level", buf[:0], 8))
	offset := binary.LittleEndian.Uint64(id.Derive("offset", buf[:0], 8))

	// Number of geometric levels available.
	// ⌊log₂(v-1)⌋ + 1
	maxLevel := max(bits.Len(uint(v-1)), 1)
	j := int(level%uint64(maxLevel)) + 1 // j ∈ [1, maxLevel]

	hi := 1 << j       // 2^j
	lo := 1 << (j - 1) // 2^{j-1}
	rangeSize := max(hi-lo, 1)

	// Parent index = v − 2^j + offset,  offset ∈ [0, 2^{j-1})
	return max(v-hi+int(offset%uint64(rangeSize)), 0)
}

// gratesParent returns the index of the Grates parent node given the original node index before indegree reduction (v)
// and the number of columns in the Grates graph.
//
// # Grates edge computation
//
// Grates(N, ε) is a deterministic DAG on N nodes arranged as a grid:
//
//	    rows = ⌈N^ε⌉  (the "tall" dimension)
//		   cols = N / rows (the "wide" dimension, ≈ N^{1−ε})
//
// Every node has a chain edge (v-1 → v) which traverses each row left to right. Nodes in rows > 0 additionally have a
// cross-edge from the same column one row up: (v − cols) → v.
//
// This gives (γN, γ'N^{1−ε})-depth-robustness with indegree 2. A production implementation could use the full recursive
// Schnitger construction for tighter constants; this single-level grid is the base case and is sufficient to
// demonstrate the algorithm.
func gratesParent(v int, cols int) int {
	if v >= cols {
		return v - cols // same column, previous row
	}
	return -1 // row 0: no cross-edge
}

// numGratesCols returns the number of columns in the Grates grid ≈ N^{1-ε}.
func numGratesCols(n int) int {
	cols := int(math.Round(math.Pow(float64(n), 1.0-epsilon)))
	return min(max(1, cols), n)
}

const (
	// blockSize is the label size in bytes.
	blockSize = 1024

	// epsilon controls the Grates depth-robustness exponent.
	// Grates(N, Epsilon) is (γN, γ'N^{1-Epsilon})-depth-robust.
	// Smaller Epsilon → stronger depth guarantee but smaller constant γ'.
	// Typical value: 0.1 to 0.3.
	epsilon = 0.2
)
