#ifndef STRUCTURES_H
#define STRUCTURES_H

#include <map>
#include <vector>

#include "Snap.h"

enum filters_t {
  FAUST_FILTER_REDUNDANT_IO,
  FAUST_FILTER_LOG_GC,
  FAUST_FILTER_APPROX,
  FAUST_FILTER_INDUCTION,
  FAUST_FILTER_UNSUPPORTED,
  FAUST_FILTER_IBURST,
  FAUST_FILTER_TAG,
  FAUST_FILTER_DPRESERVE_FD,
  FAUST_FILTER_DPRESERVE_SD,
  FAUST_FILTER_NODEMERGE,
};

const int TOTAL_NUM_FILTERS = 9;

enum filter_actions_t {
  ALLOW,
  MANGLE,
  DROP,
};

enum node_type{
  FAUST_NODE_PROCESS,
  FAUST_NODE_INODE,
  FAUST_NODE_SOCKET,
  FAUST_NUM_TYPES
};
enum edge_relation {
  FAUST_EDGE_OPENED_BY, //open syscall
  FAUST_EDGE_CLOSED_BY, //close syscall
  FAUST_EDGE_FORKED_BY, //fork syscall
  FAUST_EDGE_EXITED_BY, //exit syscall (note, shouldn't really have an edge between nodes...) should discuss further
  FAUST_EDGE_UNLINKED_BY, //unlink syscall
  FAUST_EDGE_USED, //read syscall
  FAUST_EDGE_WAS_GENERATED_BY //write syscall
};

//For whether a file/process is alive or dead
enum {
  ALIVE,
  DEAD
};

// file metadata for what an fd actually points to
struct FDFile {
  short type; // typed enum would be better
  // using some variant type here could save a bit of space
  TInt inode;
  // for now, ignore socket address (all sockets are logically equal)
  // std::string saddr;

  bool operator<(const FDFile &f) const {
    if (type != f.type) return type < f.type;
    switch (type) {
    case FAUST_NODE_INODE: return inode < f.inode;
    case FAUST_NODE_SOCKET: return false;
    //case FAUST_NODE_SOCKET: return saddr.compare(f.saddr) < 0;
    default: // this shouldn't happen
#ifdef DEBUGMSG
      printf("%s: encountered unexpected case\n",__func__);
#endif
      return false;
    }
  }
};

/* Key for EdgeMap */
struct EdgePair {
 public:
  
  EdgePair(int src_id, int dst_id, edge_relation relation) {
    this->src_id = src_id;
    this->dst_id = dst_id;
    this->relation = relation;
  }
  
  int src_id;
  int dst_id;
  edge_relation relation;
  
  bool operator<(const EdgePair& e) const
  {
    if (src_id < e.src_id) return true;
    if (src_id > e.src_id) return false;
    if (dst_id < e.dst_id) return true;
    if (dst_id > e.dst_id) return false;
    if (relation < e.relation) return true;
    if (relation > e.relation) return false;
    return false;
  }
} __attribute__((packed));

struct State{
  PNEANet* ProvGraph;
  struct Queue* queue;
  
  int events_added;
  int unsupported_events_removed;
  int entries_added;
  
  std::map <TInt,TInt> process_map; /* Process ID (pid) -> Node Id */
  std::map <TInt,TInt> process_id_map; /* Node ID -> Process ID (pid) */
  std::map <TInt,std::map<TInt,FDFile>> process_fd_fdfile_map; /* Process ID (pid) -> FD -> FDFile */
  std::map <TInt,std::map<FDFile,TInt>> process_fdfile_syscall_map; /* Process ID (pid) -> FDFile -> Syscall Id (in Queue) */
  std::map <FDFile,TInt> fdfile_map; /* FDFile -> Node ID */
  std::map <TInt,FDFile> fdfile_id_map; /* Node ID -> FDFile */
  std::map <EdgePair,TInt> edge_map; /* <Source Node Id, Dest Node Id, edge_relation> -> Live Edge ID */
  std::map <TInt,TInt> event_map;  /* Syscall Id (in Queue) -> Edge Id */
  std::map <TInt,TInt> event_id_map; /* Edge Id -> Syscall Id (in Queue) */
  std::map <TInt, std::vector<filters_t> > filter_lists;
  std::map <TInt, std::vector<filter_actions_t> > filter_actions_lists;
  std::vector <TInt> syscall_ids;
};



#endif //STRUCTURES_H
