#include "dpreserve.h"

#include <limits>
#include <stack>
#include <unordered_set>
#include <unordered_map>

#include "Snap.h"

#include "structures.h"

using ESet = std::unordered_set<int>;
using NSet = std::unordered_set<int>;
using TNodeI = TNEANet::TNodeI;

// including filters.h causes problems, so just forward declare this
void filter_event(TInt, filters_t, filter_actions_t, State* state);

namespace {

/* direction-dependent functions (implemented as macros to implicitly use rev)
 * !!! these assume the reverse parameter is named `rev' !!! */
#define od_(r, n)     (r ? n.GetInDeg() : n.GetOutDeg())
#define oei_(r, n, i) (r ? n.GetInEId(i) : n.GetOutEId(i))
#define oni_(r, n, i) (r ? n.GetInNId(i) : n.GetOutNId(i))

#define outdegree(n)   od_(rev, n)
#define indegree(n)    od_(!rev, n)
#define outedgei(n, i) oei_(rev, n, i)
#define inedgei(n, i)  oei_(!rev, n, i)
#define outnodei(n, i) oni_(rev, n, i)
#define innodei(n, i)  oni_(!rev, n, i)

void reachable_dfs(PNEANet g, NSet &visited, const TNodeI &n, bool rev) {
  if (!visited.insert(n.GetId()).second)
    return;
  for (auto i = 0; i != outdegree(n); ++i)
    reachable_dfs(g, visited, g->GetNI(outnodei(n, i)), rev);
}

/** Return the set of nodes that satisfy backwards reachability to n;
 * i.e. can n reach u for all u in S?
 * (Forwards reachability iff rev; i.e. can u for all u in S reach n?) */
NSet reachable(PNEANet g, const TNodeI &n, bool rev) {
  NSet visited;
  reachable_dfs(g, visited, n, rev);
  return visited;
}

/** Identify required edges (req) that must be kept to preserve backwards
 * reachability to all sources. Anything that is not required could thus be
 * removed without breaking backwards reachability.
 *
 * If rev, reverses the direction (i.e. preserves forward reachability to all
 * sinks).
 *
 * If fd, preserves all-pair reachability instead. */
void find_req(PNEANet g, ESet &req, bool rev = false, bool fd = false) {
  NSet sources;

  for (auto i = g->BegNI(); i != g->EndNI(); i++)
    // if FD, must check all pair reachability, not just to sources
    if (fd || indegree(i) == 0) sources.insert(i.GetId());

  for (const auto src : sources) {
    const auto reachset = reachable(g, g->GetNI(src), rev);

    for (const auto nid : reachset) {
      if (nid == src)
        continue;

      const auto n = g->GetNI(nid);
      // find the oldest (lowest timestamp) required edge
      // n.b.: this assumes -1 is an invalid node id
      auto reqts = std::numeric_limits<int>::max();
      auto reqid = -1;
      for (auto i = 0; i != indegree(n); ++i) {
        auto eid = inedgei(n, i);
        auto e = g->GetEI(eid);
        // check if this parent is actually on some src ->* n
        if (reachset.find(innodei(n, i)) != reachset.cend()) {
          auto ts = g->GetIntAttrDatE(e, "T_s");
          if (ts <= reqts) {
            reqts = ts;
            reqid = eid;
          }
        }
      }

      if (reqid == -1)
        fprintf(stderr, "ERR (%s): no required edge found\n", __func__);
      req.insert(reqid);
    }
  }
}

/** Mark all edges not in req as removable edges in the graph. */
void mark(State &state, const ESet &req, filters_t name) {
  auto g = *state.ProvGraph;
  for (auto i = g->BegEI(); i != g->EndEI(); i++) {
    auto eid = i.GetId();
    if (req.find(eid) == req.cend()) {
      const auto id = state.event_id_map[eid];
      filter_event(id, name, DROP, &state);
    }
  }
}

}

namespace DPreserve {

void fd(State &state) {
  ESet req, rreq;
  find_req(*state.ProvGraph, req, false, true);
  find_req(*state.ProvGraph, rreq, true, true);

  // union the forwards and reverse sets
  for (const auto i : rreq)
    req.insert(i);

  mark(state, req, FAUST_FILTER_DPRESERVE_FD);
}

void sd(State &state) {
  ESet req;
  find_req(*state.ProvGraph, req);
  mark(state, req, FAUST_FILTER_DPRESERVE_SD);
}

}
