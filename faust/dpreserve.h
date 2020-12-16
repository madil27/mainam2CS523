#ifndef DPRESERVE_H
#define DPRESERVE_H
/* Dependence preserving reductions
 *
 * Original work:
 *   Dependence-Preserving Data Compaction for Scalable Forensic Analysis
 *   M. N. Hossain, J. Wang, R. Sekar, S. D. Stoller
 *   USENIX Security '18
 *
 * The original work implements `Full Dependence' (FD) and `Source Dependence'
 * (SD), but does not reach a fully optimal reduction, because they
 * approximate global reachability with local reachability (in the paper, they
 * use REO instead of REO*, while REO* is required for optimal FD). It also
 * proposes `Continuous Dependence' (CD), the weakest reduction, but doesn't
 * seem to actually benchmark it.
 *
 *
 * FD: for all pairs u and v:
 * backwards reachability from v to u is preserved at all times
 *  (if a path u ->* v exists, it isn't removed)
 * forwards reachability from u to v is preserved at all times u gains an
 * ancestor (i.e. an incoming edge), and at t = 0
 *
 * SD: for source nodes u (indegree(u) = 0) and all nodes v =/= u,
 * backwards reachability from v to u is preserved at all times
 *
 * Note that SD allows for some edges to be completely removed; FD will only
 * remove redundant edges (otherwise, backwards reachability is not preserved)
 *     1            1
 *    / \    SD    / \
 *   2   3  ===>  2   3
 *    \ /          \
 *     4            4
 */

struct State; // structures.h

namespace DPreserve {
/** Reduce the graph while preserving FD. */
void fd(State &state);

/** Reduce the graph while preserving SD.
 * Note that in the edge case where there are no source nodes, this will end
 * up removing everything, which meets the definition of SD, but might not be
 * forensically desirable. */
void sd(State &state);
}

#endif
