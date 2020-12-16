#ifndef LOGGC_H
#define LOGGC_H

#include <vector>
#include <map>

#include "structures.h"
#include "Snap.h"


/*
Static class made to attempt to trim specified provenance graph nodes
 */
class LogGC {
 public:
  static int attemptToTrimGraphFromNode(PNEANet &ProvGraph, TInt nodeID, std::map <TInt, std::vector<filters_t>> &filter_lists, std::map <TInt, std::vector<filter_actions_t> > &filter_actions_lists);  
  
 private:
  static bool nodeIsTrimable(PNEANet &ProvGraph, TInt nodeID, std::map <TInt, std::vector<filters_t> > &filter_lists);
  static inline bool isProcess(PNEANet &ProvGraph, TInt nodeID);
  static inline bool nodeIsDead(PNEANet &ProvGraph, TInt nodeID);
  static inline bool affectsState(PNEANet &ProvGraph, TInt nodeID);
  static inline bool nodeIsDeletedByLogGC(PNEANet &ProvGraph, TInt nodeID, std::map <TInt, std::vector<filters_t> > &filter_lists);
  static inline bool isTempFile(PNEANet &ProvGraph, TInt nodeID);
  static inline bool isDeadEndEvent();
  static inline void deleteNode(PNEANet &ProvGraph, TInt nodeID, std::map <TInt, std::vector<filters_t> > &filter_lists, std::map <TInt, std::vector<filter_actions_t> > &filter_actions_lists);
  static inline void filterEdge(PNEANet &ProvGraph, int edgeID, std::map <TInt, std::vector<filters_t> > &filter_lists, std::map <TInt, std::vector<filter_actions_t> > &filter_actions_lists); 
  static inline bool affectsState(PNEANet &ProvGraph, TInt nodeID, std::map <TInt, std::vector<filters_t> > &filter_lists);
  static inline bool edgeRelationModifiesSrc(edge_relation rel);
};

#endif
