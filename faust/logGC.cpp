#include "logGC.h"
#include "structures.h"

#include <iostream>
#include <algorithm>
#include <vector>
#include <set>

/*
Given a provenance graph and a specified attempt to trim node and parents
Returns 0 if success (may have trimmed or may not have trimmed any nodes)
Returns 1 if an error/inconsistency occurred during triming
*/

int LogGC::attemptToTrimGraphFromNode(PNEANet &ProvGraph, TInt nodeID, std::map <TInt, std::vector<filters_t> > &filter_lists, std::map <TInt, std::vector<filter_actions_t> > &filter_actions_lists) {
  //if node id doesn't exist, return
  if(nodeID < 0) {
    return 1; 
  }
  
  //if node is trimable according to rules
  if(nodeIsTrimable(ProvGraph, nodeID, filter_lists)){

    deleteNode(ProvGraph, nodeID, filter_lists, filter_actions_lists);
    
    TNEANet::TNodeI node = ProvGraph->GetNI(nodeID);
    int numParents = node.GetOutDeg();
    std::set<int> checkedParents;
    
    // TODO: make sure this has tail end recursion to not blow stack 
    // printf("node:%d has the following parent nodes:", nodeID);
    for(int i = 0; i < numParents; i++){
      int parentNId = node.GetOutNId(i);
      
      if(checkedParents.find(parentNId) != checkedParents.end()) {
	continue;
      }
      attemptToTrimGraphFromNode(ProvGraph, parentNId, filter_lists, filter_actions_lists);
      checkedParents.insert(parentNId);
    }
  } 
  return 0;
}


/*
returns true if node should be trimmed according to LogGC rules

LogGC rules:
0. If a node is already "deleted" cannot be trimmed again (may not be needed)
1. If a process is dead and doesn't affect current state*, delete it
2. If a file is dead and considered a temp file, delete it
3. Certain files/events we consider irrelevant to info flow (like writes to stdout) are deleted
*doesn't affect current state meaning it has not written to any live files and hasn't deleted any live files (unless files are considered temp, then ok)

*/
bool LogGC::nodeIsTrimable(PNEANet &ProvGraph, TInt nodeID, std::map <TInt, std::vector<filters_t> > &filter_lists) {
  //will this condition ever occur??? as long as we don't attempt to trim already trimmed nodes, this will never occur!
  /*if(nodeIsDeletedByLogGC(ProvGraph, nodeID, filter_lists)) {
    return false;
    }*/
  
  if(isProcess(ProvGraph, nodeID)) {
    return nodeIsDead(ProvGraph, nodeID) && !affectsState(ProvGraph, nodeID, filter_lists);
  } else {
    return nodeIsDead(ProvGraph, nodeID) && isTempFile(ProvGraph, nodeID) || isDeadEndEvent();
  }
}

inline bool LogGC::isProcess(PNEANet &ProvGraph, TInt nodeID) {
  return ProvGraph->GetIntAttrDatN(nodeID, "type") == FAUST_NODE_PROCESS;
}


inline bool LogGC::nodeIsDead(PNEANet &ProvGraph, TInt nodeID) {
  int isAlive = ProvGraph->GetIntAttrDatN(nodeID, "is_alive");
  return isAlive == DEAD;
}

/*
returns if logGC already semantically "deleted" node
if an edge exists and is not filtered by LogGC then alive, else dead
*/
inline bool LogGC::nodeIsDeletedByLogGC(PNEANet &ProvGraph, TInt nodeID, std::map <TInt, std::vector<filters_t> > &filter_lists) {
  TNEANet::TNodeI node = ProvGraph->GetNI(nodeID);
  
  if(node.GetInDeg() > 0) {
    int edgeID = node.GetInEId(0);
    int syscallID = ProvGraph->GetIntAttrDatE(edgeID, "evt_id");
    return (std::find(filter_lists[syscallID].begin(), filter_lists[syscallID].end(), FAUST_FILTER_LOG_GC) != filter_lists[syscallID].end());
  }
  if(node.GetOutDeg() > 0) {
    int edgeID = node.GetOutEId(0);
    int syscallID = ProvGraph->GetIntAttrDatE(edgeID, "evt_id");
    return (std::find(filter_lists[syscallID].begin(), filter_lists[syscallID].end(), FAUST_FILTER_LOG_GC) != filter_lists[syscallID].end());
  }
  
  return false;
}

/*
doesn't have any direct or indirect outgoing edges to any alive processes or alive files
ie, no influence on current state
*/
inline bool LogGC::affectsState(PNEANet &ProvGraph, TInt nodeID, std::map <TInt, std::vector<filters_t> > &filter_lists){
  //check all incoming edges, if any src node is alive and has a modifying edge, then affects state

  TNEANet::TNodeI node = ProvGraph->GetNI(nodeID);
  int inEdgeNum = node.GetInDeg();
  for(int i = 0; i < inEdgeNum; i++) {
    int edgeID = node.GetInEId(i);
   
    //if edge relation is modifying and not already filtered
    
    edge_relation rel = static_cast<edge_relation>((int)ProvGraph->GetIntAttrDatE(edgeID, "rel"));
    if(edgeRelationModifiesSrc(rel)) {
      int syscallID = ProvGraph->GetIntAttrDatE(edgeID, "evt_id");
      //affects state if filter for edge does not exist
      if (std::find(filter_lists[syscallID].begin(), filter_lists[syscallID].end(), FAUST_FILTER_LOG_GC) == filter_lists[syscallID].end()) {
	   return true;
      }
    }
  }
  return false;
}

  inline bool LogGC::edgeRelationModifiesSrc(edge_relation rel) {
    //if event is not part of the below list, it is considered modifying (ie, whitelist of events we can assume causes no info flow from dst to src)
    //note: add new non-modifying syscalls here else LogGC will attempt to preserve them
    switch (rel) {
    case FAUST_EDGE_OPENED_BY:
    case FAUST_EDGE_CLOSED_BY:
    case FAUST_EDGE_USED:
    case FAUST_EDGE_EXITED_BY:
      return false;
    default:
      return true;
    }
  }

/*
Considered a temp file if only a single process has interacted with the file in it's lifetime
 */
inline bool LogGC::isTempFile(PNEANet &ProvGraph, TInt nodeID){
  TNEANet::TNodeI node = ProvGraph->GetNI(nodeID);
  int outEdgeNum = node.GetOutDeg();
  int inEdgeNum = node.GetInDeg();
  
  int neighborNodeId = -1;
  for(int i = 0; i < outEdgeNum; i++){
    int nodeId = node.GetOutNId(i);
    if(neighborNodeId == -1) {
      neighborNodeId = nodeId;
    } else if(nodeId != neighborNodeId) {
      return false;
    }
  }
  for(int i = 0; i < inEdgeNum; i++){
    int nodeId = node.GetInNId(i);
    if(neighborNodeId == -1) {
      neighborNodeId = nodeId;
    } else if(nodeId != neighborNodeId) {
      return false;
    }
  }
  return true; 
}

/*
"A dead end event is one that has effect only on objects directly involved in the event and the effect will not create dependences in subsequent execution of the system. For example, writes tostdout will not influence any system object"
 */
inline bool LogGC::isDeadEndEvent() {
  return false;
}


/*
  Semantically delete node and all edges associated with node
  (really just mark all log events associated with node for filtering and keep track of what nodes should be deleted by this filter)
 Note: as optimization, outgoing edges and incoming edges are deleted. As optimization, only delete nonmodyfing edges, maintains correctness due to recursive nature (modifying edges should have been already filtered by this point).
*/
inline void LogGC::deleteNode(PNEANet &ProvGraph, TInt nodeID, std::map <TInt, std::vector<filters_t> > &filter_lists, std::map <TInt, std::vector<filter_actions_t> > &filter_actions_lists) {
  TNEANet::TNodeI nodeToFilter = ProvGraph->GetNI(nodeID);
  //printf("logGC del nid:%d\n", nodeID);

  //Grab out edges, mark each edge for filtering
  int outEdgeNum = nodeToFilter.GetOutDeg();
  for(int i = 0; i < outEdgeNum; i++) {
    int edgeIDToFilter = nodeToFilter.GetOutEId(i);
    //printf("filtering out edge_id:%d\n", edgeIDToFilter);
    filterEdge(ProvGraph, edgeIDToFilter, filter_lists, filter_actions_lists);
  }

  //grab in edges, mark non-modifying edges for filtering
  int inEdgeNum = nodeToFilter.GetInDeg();
  for(int i = 0; i < inEdgeNum; i++) {
    int edgeIDToFilter = nodeToFilter.GetInEId(i);    
    edge_relation rel = static_cast<edge_relation>((int)ProvGraph->GetIntAttrDatE(edgeIDToFilter, "rel"));
    
    //if nonmodifying and hasn't been filtered then filter
    if(!edgeRelationModifiesSrc(rel)) {
      int syscallID = ProvGraph->GetIntAttrDatE(edgeIDToFilter, "evt_id");
      if(std::find(filter_lists[syscallID].begin(), filter_lists[syscallID].end(), FAUST_FILTER_LOG_GC) == filter_lists[syscallID].end()) {
	//printf("filtering in edge_id:%d\n", edgeIDToFilter);
	filterEdge(ProvGraph, edgeIDToFilter, filter_lists, filter_actions_lists);
      }
    }
  }
}

/*
given edgeId, find corresponding log entry and add to LogGC filter list
*/
inline void LogGC::filterEdge(PNEANet &ProvGraph, int edgeID, std::map <TInt, std::vector<filters_t> > &filter_lists, std::map <TInt, std::vector<filter_actions_t> > &filter_actions_lists) {
  int syscallID = ProvGraph->GetIntAttrDatE(edgeID, "evt_id");
  //note, should only filter an edge once! If called multiple times will create multiple filter tags which is incorrect
  filter_lists[syscallID].push_back(FAUST_FILTER_LOG_GC);
  filter_actions_lists[syscallID].push_back(DROP);
}


