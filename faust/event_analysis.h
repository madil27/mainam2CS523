#include <asm/unistd_64.h>

#include <map>
#include <vector>
#include <set>
#include <stdexcept>
#include <string>
#include <iostream>

#include <limits.h>

#include "audit_helpers.h"
#include "filters.h"
#include "hex2bin.h"
#include "virtualfile.h"

#include "structures.h"

#include "logGC.h"

#define BURST_SEC 5 //time period for bursty process
#define BURST_PROC_LIM 20 //min process number to be considered bursty

thread_local State* state;
bool isBursting;

void init_listener_state(State * newState) {
  state = newState;
}

// an saddr is always 32 bytes long
// #define SADDR_LEN 32

// TODO saddr entries look off, increasing SADDR_LEN to parse them
// needs a closer look (probably IPv6)
#define SADDR_LEN 256

/*thread_local std::map <TInt,TInt> process_map;  Process ID (pid) -> Node Id
thread_local std::map <TInt,TInt> process_id_map;  Node ID -> Process ID (pid)
thread_local std::map <TInt,std::map <TInt,TInt> > process_fd_to_inode_map;  Process ID (pid) -> FD -> Inode
thread_local std::map <TInt,std::map <TInt,TInt> > process_inode_to_syscall_map;  Process ID (pid) -> Inode -> Syscall Id (in Queue)
thread_local std::map <TInt,TInt> inode_map;  inode -> Node ID 
thread_local std::map <TInt,TInt> inode_id_map;  Node ID -> inode
thread_local std::map <EdgePair,TInt> edge_map;  <Source Node Id, Dest Node Id> -> Live Edge ID
thread_local std::map <TInt,TInt> event_map;   Syscall Id (in Queue) -> Edge Id
thread_local std::map <TInt,TInt> event_id_map; Edge Id -> Syscall Id (in Queue) */

//#define DEBUGMSG

void dump_event_sequence(struct Queue * event_sequence, const char * func) {

  struct QNode * it = event_sequence->front;
  struct log_entry * curr_entry;

  int rv = 0;
  char * proctitle_hex, * proctitle;
  do {
    if(!it)
      break;

    curr_entry = (log_entry *) it->item;

    /* Because PROCTITLE is especially helpful for debugging,
       we will decode these from HEX to ASCII when we encounter them */
    if(!strcmp(curr_entry->type,"PROCTITLE")){
      proctitle_hex = (char *) malloc(curr_entry->msg_len);

      rv = get_event_field("proctitle", proctitle_hex, curr_entry->msg, curr_entry->msg_len);
      if(rv < 0)
    fprintf(stderr,"ERR (%s): '%s' field was not found in entry for entry %s\n", __func__, "proctitle", curr_entry->msg);
      else {
    rv = hexs2bin(proctitle_hex, (unsigned char **) &proctitle);

    if(rv > 0) {

      for(int i = 0; i < (rv-1); i++)
        if(proctitle[i] == 0)
          proctitle[i] = ' ';
      proctitle[rv]='\0';

      char * front_of_entry = strstr(curr_entry->msg, "proctitle=");
      printf("%s: %*.*s proctitle=\"%s\"\n", func,
        front_of_entry - curr_entry->msg, front_of_entry - curr_entry->msg, curr_entry->msg, proctitle);
      free(proctitle);
    }
      }

      free(proctitle_hex);
    }
    else
      printf("%s: \t%s\n", func, curr_entry->msg);
    it = it->next;
  }
  while(it && it != event_sequence->front);

}

TInt get_node(PNEANet &ProvGraph, int type, const void *key){

  TInt NodeId = -1;

  /* Make sure key is non-null */
  if(!key)
    return NodeId;

  TInt Type = type;
  switch(type) {
  case FAUST_NODE_PROCESS: {
    TInt PId = *((int *)key);
    if ( (state->process_map).find(PId) != (state->process_map).end() )
      NodeId = (state->process_map)[PId];
  }
    break;
  case FAUST_NODE_INODE: {
    FDFile f;
    f.type = FAUST_NODE_INODE;
    f.inode = *((unsigned long *) key);
    if ((state->fdfile_map).find(f) != (state->fdfile_map).end())
      NodeId = (state->fdfile_map)[f];
  }
    break;
  case FAUST_NODE_SOCKET: {
    FDFile f;
    f.type = FAUST_NODE_SOCKET;
    //f.saddr = (char *) key;
    if ((state->fdfile_map).find(f) != (state->fdfile_map).end())
      NodeId = (state->fdfile_map)[f];
  }
    break;
  }

  return NodeId;

}

/* Convert an saddr to some TInt-representable form. TODO IPv6?
 * IPv4: just use 32bit address (omit the port)
 */
TInt saddr_to_TInt(std::string saddr) {
  return std::stoi(saddr.substr(8, 8), NULL, 16);
}

TInt get_or_create_node(PNEANet &ProvGraph, int type, const void *key) {

  TInt NodeId = -1;

  /* Make sure key is non-null */
  if(!key)
    return NodeId;

  TInt TType = type;
  switch(type) {
  case FAUST_NODE_PROCESS: {
    TInt PId = *((int *)key);
    if ( state->process_map.find(PId) != state->process_map.end() )
      NodeId = state->process_map[PId];
    else {
      NodeId = ProvGraph->AddNode(ProvGraph->GetMxNId());
      ProvGraph->AddIntAttrDatN(NodeId,PId,"pid");
      ProvGraph->AddIntAttrDatN(NodeId,TType,"type");
      ProvGraph->AddIntAttrDatN(NodeId, ALIVE,"is_alive");
      // printf("Created node %d with pid %d\n", NodeId, *(TInt *)key);
      state->process_map[*(TInt *)key] = NodeId;
      state->process_id_map[NodeId] = *(TInt *)key;
    }
  }
    break;
  case FAUST_NODE_INODE: {
    FDFile f;
    f.type = FAUST_NODE_INODE;
    f.inode = *((unsigned long *) key);
    if ((state->fdfile_map).find(f) != (state->fdfile_map).end())
      NodeId = (state->fdfile_map)[f];
    else {
      NodeId = ProvGraph->AddNode(ProvGraph->GetMxNId());
      ProvGraph->AddIntAttrDatN(NodeId, f.inode, "inode");
      ProvGraph->AddIntAttrDatN(NodeId, TType, "type");
      ProvGraph->AddIntAttrDatN(NodeId, ALIVE, "is_alive");
      ProvGraph->AddIntAttrDatN(NodeId, 0, "virtual");
      /* printf("Created node %d\n", NodeId); */
      (state->fdfile_map)[f] = NodeId;
      (state->fdfile_id_map)[NodeId] = f;
    }
  }
    break;
  case FAUST_NODE_SOCKET: {
    FDFile f;
    f.type = FAUST_NODE_INODE;
    //f.saddr = (char *) key;
    if ((state->fdfile_map).find(f) != (state->fdfile_map).end())
      NodeId = (state->fdfile_map)[f];
    else {
      NodeId = ProvGraph->AddNode(ProvGraph->GetMxNId());
      //ProvGraph->AddIntAttrDatN(NodeId, saddr_to_TInt(f.saddr), "saddr");
      ProvGraph->AddIntAttrDatN(NodeId, TType, "type");
      (state->fdfile_map)[f] = NodeId;
      (state->fdfile_id_map)[NodeId] = f;
    }
  }
    break;
  }

  return NodeId;

}

TInt get_edge(TInt src_id, TInt dst_id, edge_relation rel) {

  EdgePair e(src_id, dst_id, rel);

  std::map<EdgePair,TInt>::iterator it = state->edge_map.find(e);
  if ( state->edge_map.find(e) == state->edge_map.end() )
    return -1;
  else
    return it->second;
}

TInt create_edge(PNEANet &ProvGraph, TInt SrcId, TInt DstId, edge_relation rel, int event_id, bool live) {

  TInt EdgeId = ProvGraph->AddEdge(SrcId,DstId,ProvGraph->GetMxEId());

  /* Create TInt version of our integer attributes;
     I'm hoping this will help with memory leaks in the SNAP internals */
  TInt TRel = rel;
  TInt TEventId = event_id;

  ProvGraph->AddIntAttrDatE(EdgeId,TRel,"rel");
  ProvGraph->AddIntAttrDatE(EdgeId,TEventId,"evt_id");

  if(live){
    EdgePair e(SrcId, DstId, rel);
    
    state->edge_map[e] = EdgeId;
  }

  state->event_map[TEventId] = EdgeId;
  state->event_id_map[EdgeId] = TEventId;

  /* printf("Created edge %d from node %d to node %d\n", EdgeId, SrcId, DstId); */

  return EdgeId;

}

// returns most recent live edge
TInt get_or_create_edge(PNEANet &ProvGraph, TInt SrcId, TInt DstId, edge_relation rel, int event_id) {

  TInt edge_id = -1;

  if( SrcId == DstId )
    return edge_id;

  /* Check to see if the edge already exists */
  edge_id = get_edge(SrcId,DstId, rel);

  /* Only create new if edge does not already exist */
  if(edge_id < 0)
    edge_id = create_edge(ProvGraph, SrcId, DstId, rel, event_id, 1);

  return edge_id;

}


// this function is called from handle_read, handle_write
// it returns true when there has been an event since old_t_e_id
// that requires the creation of a distinct edge (to preserve info flow)
bool auxiliary_flow(PNEANet &ProvGraph, bool read_event, TInt old_t_e_id, TInt process_nid, TInt inode_nid) {
  bool create_new_edge = false;

  TNEANet::TNodeI inode_node = ProvGraph->GetNI(inode_nid);
  TNEANet::TNodeI process_node = ProvGraph->GetNI(process_nid);

  if(read_event){

    // read event:
    // if there is a write to inode with timestamp > T_e
    // or read from process with timestamp > T_e
    // then create new edge

    // search for write to inode (out-edges from inode)
    for(int i = 0; i < inode_node.GetOutDeg(); i++){
      TInt out_edge_id = inode_node.GetOutEId(i);

      // if write event, check if timestamp more recent
      if(ProvGraph->GetIntAttrDatE(out_edge_id, "rel") == FAUST_EDGE_WAS_GENERATED_BY){
        TInt out_edge_t_e_id = ProvGraph->GetIntAttrDatE(out_edge_id, "T_e");
        if(out_edge_t_e_id > old_t_e_id){
          create_new_edge = true;
        }
      }
    }

    // search for read from process (out-edges from process)
    for(int i = 0; i < process_node.GetOutDeg(); i++){
      TInt out_edge_id = process_node.GetOutEId(i);

      // if read event, check if timestamp more recent
      if(ProvGraph->GetIntAttrDatE(out_edge_id, "rel") == FAUST_EDGE_USED){
        TInt out_edge_t_e_id = ProvGraph->GetIntAttrDatE(out_edge_id, "T_e");
        if(out_edge_t_e_id > old_t_e_id){
          create_new_edge = true;
        }
      }
    }
  }else{ // write event

    // write event:
    // if there is read from process with timestamp > T_e
    // then create new edge

    // search for read from process (out-edges from process)
    for(int i = 0; i < process_node.GetOutDeg(); i++){
      TInt out_edge_id = process_node.GetOutEId(i);

      // if read event, check if timestamp more recent
      if(ProvGraph->GetIntAttrDatE(out_edge_id, "rel") == FAUST_EDGE_USED){
        TInt out_edge_t_e_id = ProvGraph->GetIntAttrDatE(out_edge_id, "T_e");
        if(out_edge_t_e_id > old_t_e_id){
          create_new_edge = true;
        }
      }
    }
  }

  return create_new_edge;
}

TInt handle_execve(PNEANet &ProvGraph, struct Queue * event_sequence, int syscall_id){
  int rv = -1;

  if(!event_sequence
    || !event_sequence->front
    || !event_sequence->front->item)
    return rv;

  log_entry * syscall_entry = (log_entry *)event_sequence->front->item;

  TInt pid = -1;
  char * pid_str = (char *) malloc(PID_STR_LEN);
  rv = get_event_field("pid", pid_str, syscall_entry->msg, syscall_entry->msg_len);
  if(rv < 0)
    fprintf(stderr,"ERR (%s): '%s' field was not found in entry for syscall %d\n", __func__, "pid", syscall_id);
  else
    pid = atoi(pid_str);
  free(pid_str);

  TInt ppid = -1;
  char * ppid_str = (char *) malloc(PID_STR_LEN);
  rv = get_event_field("ppid", ppid_str, syscall_entry->msg, syscall_entry->msg_len);
  if(rv < 0)
    fprintf(stderr,"ERR (%s): '%s' field was not found in entry for syscall %d\n", __func__, "ppid", syscall_id);
  else
    ppid = atoi(ppid_str);
  free(ppid_str);

  if(pid >= 0 && ppid >= 0) {

    TInt parent_nid = get_or_create_node(ProvGraph, FAUST_NODE_PROCESS, (void *) &ppid);
    TInt process_nid = get_or_create_node(ProvGraph, FAUST_NODE_PROCESS, (void *) &pid);
    if (isBursting) {
         ProvGraph->AddIntAttrDatN(parent_nid, 1, "isBursting");
    }
    TInt fork_eid = get_or_create_edge(ProvGraph, process_nid, parent_nid,
                       FAUST_EDGE_FORKED_BY, syscall_id);
    rv = fork_eid;
  }

  return rv;
}

/* TInt handle_open(..)
   DESCRIPTION: Right now, all we're doing here is tracking which FD's the proc has open,
   which is needed for resolving READ and WRITE calls unfortunately...
*/
TInt handle_open(PNEANet &ProvGraph, struct Queue * event_sequence, TInt syscall_id) {

  int rv = -1;

  if(!event_sequence || !event_sequence->front)
    fprintf(stderr, "%s: event sequence uninitialized\n",__func__);

  // dump_event_sequence(event_sequence, __func__);

  /* First log_entry in queue is always the SYSCALL */
  log_entry * syscall_entry = (log_entry *)event_sequence->front->item;
  log_entry * path_entry=NULL,  * curr_entry=NULL;

  struct QNode * it = event_sequence->front;
  do {
    if(!it)
      break;

    curr_entry = (log_entry *) it->item;
    /* There may be multiple PATH entries.
       If so, the first is the parent dir and the second is the actual file,
       so we always want the last entry */
    if( !strcmp(curr_entry->type,"PATH") ) {
      path_entry = curr_entry;
    }
    it = it->next;
  }
  while(it && it != event_sequence->front);

  if(!path_entry) {
#ifdef DEBUGMSG
    printf("%s: could not find path entry\n",__func__);
    dump_event_sequence(event_sequence, __func__);
#endif
    return rv;
  }

  TInt pid = -1;
  char * pid_str = (char *) malloc(PID_STR_LEN);
  rv = get_event_field("pid", pid_str, syscall_entry->msg, syscall_entry->msg_len);
  if(rv < 0){
#ifdef DEBUGMSG
    fprintf(stderr,"ERR (%s): '%s' field was not found in entry for syscall %d\n", __func__, "pid", syscall_id);
#endif
  }
  else
    pid = atoi(pid_str);
  free(pid_str);

  TInt inode = -1;
  char * inode_str = (char *) malloc(INODE_STR_LEN);
  rv = get_event_field("inode", inode_str, path_entry->msg, path_entry->msg_len);
  if(rv < 0) {
#ifdef DEBUGMSG
    fprintf(stderr,"ERR (%s): '%s' field was not found in entry for syscall %d\n", __func__, "inode", syscall_id);
    dump_event_sequence(event_sequence, __func__);
#endif
  }
  else{
    inode = atoi(inode_str);

    // if inode number too high for int range
    // (mostly /proc/*)
    // (files in /usr/lib64/*.so normally don't have inode #)
    
    // negative inode values are ok, just not -1
  }free(inode_str);

  char *pathbuf = (char *) malloc(PATH_STR_LEN);
  rv = get_event_field("name", pathbuf, path_entry->msg, path_entry->msg_len);
  if(rv < 0) {
#ifdef DEBUGMSG
    fprintf(stderr,"ERR (%s): '%s' field was not found in entry for syscall %d\n", __func__, "inode", syscall_id);
    dump_event_sequence(event_sequence, __func__);
#endif
  }
  size_t pathlen = rv;
  // audit quirk: path is surrounded by quotes; must remove them
  char *path = pathbuf + 1;
  pathbuf[pathlen - 1] = '\0';
  pathlen -= 2;


  /* We also need to manage a set of open file descriptors for each process, because REASONS >_< */
  TInt fd = -1;
  char * fd_str = (char *)malloc(FD_STR_LEN); /* that's probably a big enough FD space per process, right? */
  rv = get_event_field("exit", fd_str, syscall_entry->msg, syscall_entry->msg_len);
  if(rv < 0)
    fprintf(stderr,"ERR (%s): '%s' field was not found in entry for syscall %d\n", __func__, "exit", syscall_id);
  else
    fd = strtoul(fd_str, NULL, 16);
  free(fd_str);

  if(pid >=0 && inode != -1 && fd >=0) {
    FDFile f;
    f.type = FAUST_NODE_INODE;
    f.inode = inode;
    (state->process_fd_fdfile_map)[pid][fd] = f;
    (state->process_fdfile_syscall_map)[pid][f] = syscall_id;
    // printf("%s: process_fd_fdfile_map[%d][%d] = %d\n",__func__,pid,fd,inode);;
    rv = 0;
  }

  TInt process_nid = get_or_create_node(ProvGraph, FAUST_NODE_PROCESS, (void *) &pid);
  //get parent process node in prov graph
  
  TInt inode_nid = get_or_create_node(ProvGraph, FAUST_NODE_INODE, (void *) &inode);
  //create edge between them
  
  // mark as virtual
  if (pathlen >= 0 && is_virtual(path)){
    ProvGraph->AddIntAttrDatN(inode_nid, 1, "virtual");
  }
  free(pathbuf);

  TInt open_eid = get_edge(inode_nid, process_nid, FAUST_EDGE_OPENED_BY);
  if(open_eid < 0) {
    open_eid = create_edge(ProvGraph, inode_nid, process_nid, FAUST_EDGE_OPENED_BY, syscall_id, 1);
  }else{
    if(is_active(FAUST_FILTER_REDUNDANT_IO)){
      filter_event(syscall_id, FAUST_FILTER_REDUNDANT_IO, DROP, state);

    if(is_active(FAUST_FILTER_IBURST))
      filter_event(syscall_id, FAUST_FILTER_IBURST, DROP, state);
    }

    if(is_active(FAUST_FILTER_APPROX)){
      filter_event(syscall_id, FAUST_FILTER_APPROX, DROP, state);
    }

    // FD and SD would always remove this, but they also assume the edge
    // actually exists in the graph... just mark it as removed here
    if (is_active(FAUST_FILTER_DPRESERVE_FD)) {
      filter_event(syscall_id, FAUST_FILTER_DPRESERVE_FD, DROP, state);
    }
    if (is_active(FAUST_FILTER_DPRESERVE_SD)) {
      filter_event(syscall_id, FAUST_FILTER_DPRESERVE_SD, DROP, state);
    }
  }

  if (isBursting)
    ProvGraph->AddIntAttrDatN(process_nid, 1, "isBursting");
  /*
  TInt process_nid = get_or_create_node(ProvGraph, FAUST_NODE_PROCESS, (void *) &pid);
  TInt inode_nid = get_or_create_node(ProvGraph, FAUST_NODE_INODE, (void *) &inode);
  */

  //Argument a1 is the open flags
  //This is based on audit-tools/auparse/interpret.c:print_open_flags btw
  /*
  char * flags_str = (char *) malloc(10);
  get_event_field("a1", flags_str, syscall_entry->msg, syscall_entry->msg_len);
  unsigned int flags = strtoul(flags_str, NULL, 16);

  TInt rel_eid;
  if ( ((flags & O_ACCMODE) == 0)
       || flags & O_RDONLY
       || flags & O_RDWR ) {
    rel_eid = get_or_create_edge(ProvGraph, process_nid, inode_nid,
                 FAUST_EDGE_USED, syscall_id);
  }
  if ( flags & O_WRONLY
       || flags & O_CREAT
       || flags & O_APPEND
       || flags & O_RDWR ) {
    rel_eid = get_or_create_edge(ProvGraph, inode_nid, process_nid,
                 FAUST_EDGE_WAS_GENERATED_BY, syscall_id);
  }
  */

  return rv;

}



/* TInt handle_close(..)
   DESCRIPTION: Our only job here is to update the set of open FD's for this process */
TInt handle_close(PNEANet &ProvGraph, struct Queue * event_sequence, TInt syscall_id) {

  int rv;
  log_entry * syscall_entry = (log_entry *)event_sequence->front->item;

  TInt pid = -1;
  char * pid_str = (char *) malloc(PID_STR_LEN);
  rv = get_event_field("pid", pid_str, syscall_entry->msg, syscall_entry->msg_len);
  if(rv < 0)
    fprintf(stderr,"ERR (%s): '%s' field was not found in entry for syscall %d\n", __func__, "pid", syscall_id);
  else
    pid = atoi(pid_str);
  free(pid_str);

  TInt fd = -1;
  char * fd_str = (char *)malloc(FD_STR_LEN);
  rv = get_event_field("a0", fd_str, syscall_entry->msg, syscall_entry->msg_len);
  if(rv < 0)
    fprintf(stderr,"ERR (%s): '%s' field was not found in entry for syscall %d\n", __func__, "exit", syscall_id);
  else
    fd = strtoul(fd_str, NULL, 16);
  free(fd_str);

  TInt inode = -1;
  const void *key = NULL;
  TInt type = FAUST_NUM_TYPES;
  /* If they're using std*, let's just say fd == inode */
  if(fd >= 0 && fd < 3) {
    inode = fd;
    key = &inode;
    type = FAUST_NODE_INODE;
  } else if (fd >= 0) {
    /* If there was event loss, we may not know which inode this FD belongs to */
    switch ((state->process_fd_fdfile_map)[pid][fd].type) { // CSE pls                                                                                                        
    case FAUST_NODE_INODE:
      inode = (state->process_fd_fdfile_map)[pid][fd].inode;
      key = &inode;
      type = FAUST_NODE_INODE;
      break;
    case FAUST_NODE_SOCKET:
      //saddr = process_fd_fdfile_map[pid][fd].saddr;                                                                                                                         
      //key = saddr.c_str();                                                                                                                                                  
      type = FAUST_NODE_SOCKET;
      break;
    }
    //if (!inode && saddr.empty() || !key) {                                                                                                                                  
    /*if (!inode) {
#ifdef DEBUGMSG
      fprintf(stderr, "%s: Could not find file for pid=%d, fd=%d\n",__func__,pid,fd);
#endif
      return -1;
    }*/
  }

  if(pid >= 0 && fd >= 0) {
    
    if(key != NULL) {
      
      if(fd >= 0 && fd < 3 && is_active(FAUST_FILTER_APPROX)){
        filter_event(syscall_id, FAUST_FILTER_APPROX, DROP, state);
      }

      TInt process_nid = get_or_create_node(ProvGraph, FAUST_NODE_PROCESS, (void *) &pid);
      //get parent process node in prov graph
      TInt inode_nid = get_or_create_node(ProvGraph, FAUST_NODE_INODE, key);
      //create edge between them

      TInt close_eid = get_edge(inode_nid, process_nid, FAUST_EDGE_CLOSED_BY);
      
      if (isBursting) {
         ProvGraph->AddIntAttrDatN(process_nid, 1, "isBursting");
      }

      if(close_eid < 0) {
        close_eid = create_edge(ProvGraph, inode_nid, process_nid, FAUST_EDGE_CLOSED_BY, syscall_id, 1);
      }else{
        // should create edge regardless?

        if(is_active(FAUST_FILTER_REDUNDANT_IO)){
          filter_event(syscall_id, FAUST_FILTER_REDUNDANT_IO, DROP, state);
        
          if(is_active(FAUST_FILTER_IBURST))
            filter_event(syscall_id, FAUST_FILTER_IBURST, DROP, state);
        }

        if(is_active(FAUST_FILTER_APPROX)){
          filter_event(syscall_id, FAUST_FILTER_APPROX, DROP, state);
        }

        // FD and SD would always remove this, but they also assume the edge
        // actually exists in the graph... just mark it as removed here
        if (is_active(FAUST_FILTER_DPRESERVE_FD)) {
          filter_event(syscall_id, FAUST_FILTER_DPRESERVE_FD, DROP, state);
        }
        if (is_active(FAUST_FILTER_DPRESERVE_SD)) {
          filter_event(syscall_id, FAUST_FILTER_DPRESERVE_SD, DROP, state);
        }
      }
    }else{ // most events in audit.log.1 end up here

      // close() entries corresponding to missing open()
      // remove entry
      state->entries_added -= delete_log_event(state->queue,syscall_id);
      state->events_added--;
      (state->syscall_ids).pop_back();
      
    }
    (state->process_fd_fdfile_map)[pid].erase(fd);
  }
 exit:
  return rv;

  
  }


TInt handle_read(PNEANet &ProvGraph, struct Queue * event_sequence, TInt syscall_id) {

  int rv;
  log_entry * syscall_entry = (log_entry *)event_sequence->front->item;

  //printf("RD (%d): %s\n", syscall_id, syscall_entry->msg);

  TInt pid = -1;
  char * pid_str = (char *) malloc(PID_STR_LEN);
  rv = get_event_field("pid", pid_str, syscall_entry->msg, syscall_entry->msg_len);
  if(rv < 0) {
    fprintf(stderr,"ERR (%s): '%s' field was not found in entry for syscall %d\n", __func__, "pid", syscall_id);
    dump_event_sequence(event_sequence,__func__);
  }
  else
    pid = atoi(pid_str);
  free(pid_str);

  TInt fd = -1;
  char * fd_str = (char *)malloc(FD_STR_LEN); /* that's probably a big enough FD space per process, right? */
  rv = get_event_field("a0", fd_str, syscall_entry->msg, syscall_entry->msg_len);
  if(rv < 0) {
    fprintf(stderr,"ERR (%s): '%s' field was not found in entry for syscall %d\n", __func__, "a0", syscall_id);
    dump_event_sequence(event_sequence,__func__);
  }
  else
    fd = strtoul(fd_str, NULL, 16);
  free(fd_str);

  // stack allocate both possible values; they're small enough
  std::string saddr;
  TInt inode = -1;
  const void *key = NULL;
  TInt type = FAUST_NUM_TYPES;
  /* If they're using std*, let's just say fd == inode */
  if(fd >= 0 && fd < 3) {
    inode = fd;
    key = &inode;
    type = FAUST_NODE_INODE;
  } else if (fd >= 0) {
    /* If there was event loss, we may not know which inode this FD belongs to */
    switch ((state->process_fd_fdfile_map)[pid][fd].type) { // CSE pls
    case FAUST_NODE_INODE:
      inode = (state->process_fd_fdfile_map)[pid][fd].inode;
      key = &inode;
      type = FAUST_NODE_INODE;
      break;
    case FAUST_NODE_SOCKET:
      //saddr = process_fd_fdfile_map[pid][fd].saddr;
      //key = saddr.c_str();
      type = FAUST_NODE_SOCKET;
      break;
    }
    //if ((inode < 0 && saddr.empty()) || !key) {
    if (inode == -1) {
#ifdef DEBUGMSG
      fprintf(stderr, "%s: Could not find file for pid=%d, fd=%d\n",__func__,pid,fd);
#endif
    
      // most of the entries in audit.log.2
      // read() entries corresponding to missing open()
      // remove entry
      state->entries_added -= delete_log_event(state->queue,syscall_id);
      state->events_added--;
      (state->syscall_ids).pop_back();
      
      return -1;
    }

    //printf("%s: found inode %d for pid %d, file descriptor %d\n", __func__, inode, pid, fd);
  } else{
    return rv;
  }

  edge_relation rel = FAUST_EDGE_USED;
  if(pid >= 0 && key) {
    TInt process_nid = get_or_create_node(ProvGraph, FAUST_NODE_PROCESS, (void *) &pid);
    TInt file_nid = get_or_create_node(ProvGraph, type, key);

    // if virtual, ignore event
    TInt is_virtual = ProvGraph->GetIntAttrDatN(file_nid, "virtual");
    if(is_virtual){
      state->entries_added -= delete_log_event(state->queue,syscall_id);
      state->events_added--;
      (state->syscall_ids).pop_back();
      return -1;
    }

    if(fd >= 0 && fd < 3 && is_active(FAUST_FILTER_APPROX)){
      filter_event(syscall_id, FAUST_FILTER_APPROX, DROP, state);
    
      if (isBursting) {
         ProvGraph->AddIntAttrDatN(process_nid, 1, "isBursting");
      }
    }

    TInt rel_eid = get_edge(process_nid, file_nid, rel);
    if(rel_eid < 0) {
      rel_eid = create_edge(ProvGraph, process_nid, file_nid,
                rel, syscall_id, 1);
      ProvGraph->AddIntAttrDatE(rel_eid,syscall_id,"T_s");
      ProvGraph->AddIntAttrDatE(rel_eid,syscall_id,"T_e");
      ProvGraph->AddIntAttrDatE(rel_eid,1,"Live");
    
    
    }else {
      TInt t_s_id = ProvGraph->GetIntAttrDatE(rel_eid, "T_s");
      TInt old_t_e_id = ProvGraph->GetIntAttrDatE(rel_eid, "T_e");

      bool create_new_edge = auxiliary_flow(ProvGraph, true, old_t_e_id, process_nid, file_nid);

      if(!is_active(FAUST_FILTER_REDUNDANT_IO) || create_new_edge){
        // mark old edge dead
        ProvGraph->AddIntAttrDatE(rel_eid,0,"Live");

        // create new edge
        rel_eid = create_edge(ProvGraph, process_nid, file_nid,
                                   rel, syscall_id, 1);
        ProvGraph->AddIntAttrDatE(rel_eid,syscall_id,"T_s");
        ProvGraph->AddIntAttrDatE(rel_eid,syscall_id,"T_e");
        ProvGraph->AddIntAttrDatE(rel_eid,1,"Live");

        if(is_active(FAUST_FILTER_REDUNDANT_IO) && is_active(FAUST_FILTER_IBURST)) {
          filter_event(old_t_e_id, FAUST_FILTER_IBURST, DROP, state);
          TInt live_t_s = ProvGraph->GetIntAttrDatE(rel_eid, "T_s");
          filter_event(live_t_s, FAUST_FILTER_IBURST, DROP, state);
        }
      }else{ // keep old edge, update T_e (filter all in between T_s, T_e)

        // create new dead edge
        
        TInt dead_edge_eid = create_edge(ProvGraph, process_nid, 
                      file_nid, rel, syscall_id, 0);
        ProvGraph->AddIntAttrDatE(dead_edge_eid,syscall_id,"T_s");
        ProvGraph->AddIntAttrDatE(dead_edge_eid,syscall_id,"T_e");
        ProvGraph->AddIntAttrDatE(dead_edge_eid,0,"Live");

        if(t_s_id  != old_t_e_id){
          filter_event(old_t_e_id, FAUST_FILTER_REDUNDANT_IO, DROP, state);
          
          if (is_active(FAUST_FILTER_IBURST))
            filter_event(old_t_e_id, FAUST_FILTER_IBURST, DROP, state);
        }

        ProvGraph->AddIntAttrDatE(rel_eid,syscall_id,"T_e");
      }
    }
    rv = rel_eid;
  }
  
  return rv;

}

TInt handle_write(PNEANet &ProvGraph, struct Queue * event_sequence, TInt syscall_id) {

  int rv;
  log_entry * syscall_entry = (log_entry *)event_sequence->front->item;

  //printf("WR (%d): %s\n", syscall_id, syscall_entry->msg);

  // dump_event_sequence(event_sequence, __func__);

  TInt pid = -1;
  char * pid_str = (char *) malloc(PID_STR_LEN);
  rv = get_event_field("pid", pid_str, syscall_entry->msg, syscall_entry->msg_len);
  if(rv < 0)
    fprintf(stderr,"ERR (%s): '%s' field was not found in entry for syscall %d\n", __func__, "pid", syscall_id);
  else
    pid = atoi(pid_str);
  free(pid_str);

  TInt fd = -1;
  char * fd_str = (char *)malloc(FD_STR_LEN); /* that's probably a big enough FD space per process, right? */
  rv = get_event_field("a0", fd_str, syscall_entry->msg, syscall_entry->msg_len);
  if(rv < 0)
    fprintf(stderr,"ERR (%s): '%s' field was not found in entry for syscall %d\n", __func__, "a0", syscall_id);
  else
    fd = strtoul(fd_str, NULL, 16);
  free(fd_str);

  // stack allocate both possible values; they're small enough
  std::string saddr;
  TInt inode = -1;
  const void *key = NULL;
  TInt type = FAUST_NUM_TYPES;
  /* If they're using std*, let's just say fd == inode */
  if(fd >= 0 && fd < 3) {
    inode = fd;
    key = &inode;
    type = FAUST_NODE_INODE;
  } else if (fd >= 0) {
    /* If there was event loss, we may not know which inode this FD belongs to */
    switch ((state->process_fd_fdfile_map)[pid][fd].type) { // CSE pls
    case FAUST_NODE_INODE:
      inode = (state->process_fd_fdfile_map)[pid][fd].inode;
      key = &inode;
      type = FAUST_NODE_INODE;
      break;
    case FAUST_NODE_SOCKET:
      //saddr = process_fd_fdfile_map[pid][fd].saddr;
      //key = saddr.c_str();
      type = FAUST_NODE_SOCKET;
      break;
    }
    //if (!inode && saddr.empty() || !key) {
    if (inode == -1) {
#ifdef DEBUGMSG
      fprintf(stderr, "%s: Could not find file for pid=%d, fd=%d\n",__func__,pid,fd);
#endif

      // write() entries corresponding to missing open()
      // remove entry
      state->entries_added -= delete_log_event(state->queue,syscall_id);
      state->events_added--;
      (state->syscall_ids).pop_back();
      
      return -1;
    }

    //printf("%s: found inode %d for pid %d, file descriptor %d\n", __func__, inode, pid, fd);
  } else
    return rv;
  
  if(pid >= 0 && key) {
    TInt process_nid = get_or_create_node(ProvGraph, FAUST_NODE_PROCESS, (void *) &pid);
    TInt file_nid = get_or_create_node(ProvGraph, type, key);

    // if virtual, ignore event
    TInt is_virtual = ProvGraph->GetIntAttrDatN(file_nid, "virtual");
    if(is_virtual){
      state->entries_added -= delete_log_event(state->queue,syscall_id);
      state->events_added--;
      (state->syscall_ids).pop_back();
      return -1;
    }

    if(fd >= 0 && fd < 3 && is_active(FAUST_FILTER_APPROX)){
      filter_event(syscall_id, FAUST_FILTER_APPROX, DROP, state);
    }
    
    if (isBursting) {
       ProvGraph->AddIntAttrDatN(process_nid, 1, "isBursting");
    }
    
    edge_relation generated_edge_rel = FAUST_EDGE_WAS_GENERATED_BY;
    TInt rel_eid = get_edge(file_nid, process_nid, generated_edge_rel);
    if(rel_eid < 0){
      // printf("Creating edge between inode %d (fd %d) and pid %d\n", inode, fd, pid);
      rel_eid = create_edge(ProvGraph, file_nid, process_nid,
                generated_edge_rel, syscall_id, 1);
      ProvGraph->AddIntAttrDatE(rel_eid,syscall_id,"T_s");
      ProvGraph->AddIntAttrDatE(rel_eid,syscall_id,"T_e");
    } else {
      TInt t_s_id = ProvGraph->GetIntAttrDatE(rel_eid, "T_s");
      TInt old_t_e_id = ProvGraph->GetIntAttrDatE(rel_eid, "T_e");

      bool create_new_edge = auxiliary_flow(ProvGraph, false, old_t_e_id, process_nid, file_nid);

      if(!is_active(FAUST_FILTER_REDUNDANT_IO) || create_new_edge){
        // mark old edge dead
        ProvGraph->AddIntAttrDatE(rel_eid,0,"Live");

        // create new edge
        rel_eid = create_edge(ProvGraph, file_nid, process_nid,
                            generated_edge_rel, syscall_id, 1);
        ProvGraph->AddIntAttrDatE(rel_eid,syscall_id,"T_s");
        ProvGraph->AddIntAttrDatE(rel_eid,syscall_id,"T_e");
        ProvGraph->AddIntAttrDatE(rel_eid,1,"Live");
        
        if(is_active(FAUST_FILTER_REDUNDANT_IO) && is_active(FAUST_FILTER_IBURST)) {
          filter_event(old_t_e_id, FAUST_FILTER_IBURST, DROP, state);
          TInt live_t_s = ProvGraph->GetIntAttrDatE(rel_eid, "T_s");
          filter_event(live_t_s, FAUST_FILTER_IBURST, DROP, state);
        }
      }else{ // keep old edge, update T_e (filter all in between T_s, T_e)
        // create new dead edge
        
        TInt dead_edge_eid = create_edge(ProvGraph, file_nid, 
                process_nid, generated_edge_rel, syscall_id, 0);
        ProvGraph->AddIntAttrDatE(dead_edge_eid,syscall_id,"T_s");
        ProvGraph->AddIntAttrDatE(dead_edge_eid,syscall_id,"T_e");
        ProvGraph->AddIntAttrDatE(dead_edge_eid,0,"Live");

        if(is_active(FAUST_FILTER_REDUNDANT_IO)){
          if(t_s_id  != old_t_e_id){
            filter_event(old_t_e_id, FAUST_FILTER_REDUNDANT_IO, DROP, state);
            
            if(is_active(FAUST_FILTER_IBURST))
              filter_event(old_t_e_id, FAUST_FILTER_IBURST, DROP, state);
          }
        }

        ProvGraph->AddIntAttrDatE(rel_eid,syscall_id,"T_e");
      }
    }
    rv = rel_eid;
  }

  return rv;
}

/*
Parses syscall event to get int value of field

returns -1 on failure, no modification to fieldVal
returns 0 on success
*/
int get_event_numField(const char* field, TInt &fieldVal, const log_entry* syscall_entry) {
  TInt rv = -1;
  if(syscall_entry == NULL || field == NULL) {
    return -1;
  }

  int TINT_LEN = 12;
  char * tint_str = (char *) malloc(TINT_LEN);

  if(get_event_field(field, tint_str, syscall_entry->msg, syscall_entry->msg_len)<0){
    rv = -1;
  } else {
    rv = 1;
    fieldVal = atoi(tint_str);
  }

  free(tint_str);
  return rv;
}

//todo, keep track of references to inode
void updateInodeState_unlink(TInt inode_id) {
  return;
}
//todo,actually determine if this is the last reference using inode state
bool isLastReferenceToInode(TInt inode_id){
  return true;
}

void printFieldnameErrorAndDump(struct Queue* event_sequence, const char* field_name, TInt syscall_id){
  fprintf(stderr,"ERR (%s): '%s' field was not found in entry for syscall %d\n", __func__, field_name, syscall_id);
  dump_event_sequence(event_sequence,__func__);
}


/*
Get node in provenance graph, if last reference to inode(TODO!), then delete
 */
TInt handle_unlinkat(PNEANet &ProvGraph, struct Queue * event_sequence, TInt syscall_id) {
  TInt rv = -1;

  if(!event_sequence || !event_sequence->front || !event_sequence->front->item) {
    fprintf(stderr, "%s: event sequence uninitialized\n",__func__);
    return -1;
  }

  /* First log_entry in queue is always the SYSCALL */
  log_entry * syscall_entry = (log_entry *)event_sequence->front->item;
  log_entry * path_entry=NULL,  * curr_entry=NULL;

  //get file path
  for(struct QNode * it = event_sequence->front; it; it=it->next) {
    curr_entry = (log_entry *) it->item;

    /* There may be multiple PATH entries.
       If so, the first is the parent dir and the second is the actual file,
       so we always want the last entry */
    if( !strcmp(curr_entry->type,"PATH") ) {
      path_entry = curr_entry;
    }
  }


  if(!path_entry) {
    printf("no path entry found\n");
#ifdef DEBUGMSG
    printf("%s: could not find path entry\n",__func__);
    dump_event_sequence(event_sequence, __func__);
#endif
    return rv;
  }
  
  //get inode via next syslog
  TInt unlinkedInode_id = -1;
  TInt pid = -1;
  if((rv=get_event_numField("inode", unlinkedInode_id, path_entry)) < 0) { // && ((rv = get_event_numField("", process_id, syscall_entry)) < 0)){
    printFieldnameErrorAndDump(event_sequence, "inode", syscall_id);
  } else if((rv=get_event_numField("pid", pid, syscall_entry)) < 0) {
    printFieldnameErrorAndDump(event_sequence, "pid", syscall_id);
  } else if(unlinkedInode_id >=0){
    //also get pid that unlinked and make an edge between them (from inode to parent process)
    
    
    TInt inode_nid = get_or_create_node(ProvGraph, FAUST_NODE_INODE, (void *) &unlinkedInode_id);
    TInt process_nid = get_or_create_node(ProvGraph, FAUST_NODE_PROCESS, (void *) &pid);
    TInt unlink_eid = create_edge(ProvGraph, inode_nid, process_nid, FAUST_EDGE_UNLINKED_BY, syscall_id, 1);
   
    if (isBursting) {
       ProvGraph->AddIntAttrDatN(process_nid, 1, "isBursting");
    }

    //update inode state
    updateInodeState_unlink(unlinkedInode_id);

    //if last reference to inode then mark dead
    if(isLastReferenceToInode(unlinkedInode_id)) {
      //mark as dead
      ProvGraph->AddIntAttrDatN(inode_nid, DEAD, "is_alive");

      //if LogGC is utilized, invoke filter to check if nodes should be trimmed
      if(is_active(FAUST_FILTER_LOG_GC)){
	LogGC::attemptToTrimGraphFromNode(ProvGraph, inode_nid, state->filter_lists, state->filter_actions_lists);
      }
      //printf("inode %d marked as dead with node id %d\n", unlinkedInode_id, inode_nid);
    }
  }

  return rv;
}

TInt handle_unlink(PNEANet &ProvGraph, struct Queue * event_sequence, TInt syscall_id) {
  return handle_unlinkat(ProvGraph, event_sequence, syscall_id);
}

/*
If process has exited, mark corresponding node in ProvGraph as dead

returns -1 if error in occurs in reading field attribute
if
*/
TInt handle_exit_group(PNEANet &ProvGraph, struct Queue * event_sequence, TInt syscall_id){
  TInt rv = -1, pid = -1, ppid = -1;

  if(!event_sequence || !event_sequence->front || !event_sequence->front->item){
    return -1;
  }
  log_entry * syscall_entry = (log_entry *)event_sequence->front->item;

  /*for(TNEANet::TNodeI n = ProvGraph->BegNI(); n != ProvGraph->EndNI(); n++){
    printf("node-id = %d, in-deg = %d, out-deg %d\n", n.GetId(), n.GetInDeg(), n.GetOutDeg());
    }*/

  
  //get node in provenence graph
  if((rv = get_event_numField("pid", pid, syscall_entry)) < 0) {
    printFieldnameErrorAndDump(event_sequence, "pid", syscall_id);
  } else if ((rv = get_event_numField("ppid", ppid, syscall_entry)) < 0) {
    printFieldnameErrorAndDump(event_sequence, "ppid", syscall_id);
  } else if(pid >=0 && ppid >=0) {

    //get child process node in provenence graph
    TInt process_nid = get_or_create_node(ProvGraph, FAUST_NODE_PROCESS, (void *) &pid);
    //get parent process node in prov graph
    TInt parent_nid = get_or_create_node(ProvGraph, FAUST_NODE_PROCESS, (void *) &ppid);
    //create edge between them
    TInt exit_eid = create_edge(ProvGraph, process_nid, parent_nid, FAUST_EDGE_EXITED_BY, syscall_id, 1);  
    //printf("pid: %d ppid: %d eid: %d\n", process_nid, parent_nid, exit_eid);

    //mark as dead
    ProvGraph->AddIntAttrDatN(process_nid, DEAD, "is_alive");
    //printf("node with provid: %d and pid: \%d marked as dead!\n",process_nid, exited_pid);
    //if LogGC is utilized, invoke filter to check if nodes should be trimmed
    if(is_active(FAUST_FILTER_LOG_GC)){
      LogGC::attemptToTrimGraphFromNode(ProvGraph, process_nid, state->filter_lists, state->filter_actions_lists);
    }
    
  }

  return rv;
}

/*
For now, assume that exit fully exists a program like exit_group
TODO: discuss this, likely incorrect for multithreaded programs
*/
TInt handle_exit(PNEANet &ProvGraph, struct Queue * event_sequence, TInt syscall_id){
  return handle_exit_group(ProvGraph, event_sequence, syscall_id);
}

TInt handle_connect(PNEANet &ProvGraph, struct Queue * event_sequence, TInt syscall_id) {

  int rv = -1;

  if(!event_sequence || !event_sequence->front)
    fprintf(stderr, "%s: event sequence uninitialized\n",__func__);

  log_entry *syscall_entry = (log_entry *)event_sequence->front->item;
  log_entry *sockaddr_entry = NULL, *curr_entry = NULL;

  struct QNode * it = event_sequence->front;
  do {
    if(!it)
      break;

    curr_entry = (log_entry *) it->item;
    // there's only one SOCKADDR entry; could just break here
    if(!strcmp(curr_entry->type, "SOCKADDR")) {
      sockaddr_entry = curr_entry;
    }
    it = it->next;
  }
  while(it && it != event_sequence->front);

  if(!sockaddr_entry) {
#ifdef DEBUGMSG
    printf("%s: could not find sockaddr entry\n",__func__);
    dump_event_sequence(event_sequence, __func__);
#endif
    return rv;
  }

  TInt pid = -1;
  char * pid_str = (char *) malloc(PID_STR_LEN);
  rv = get_event_field("pid", pid_str, syscall_entry->msg, syscall_entry->msg_len);
  if(rv < 0){
#ifdef DEBUGMSG
    fprintf(stderr,"ERR (%s): '%s' field was not found in entry for syscall %d\n", __func__, "pid", syscall_id);
#endif
  }
  else
    pid = atoi(pid_str);
  free(pid_str);

  /* We also need to manage a set of open file descriptors for each process, because REASONS >_< */
  TInt fd = -1;
  char * fd_str = (char *)malloc(FD_STR_LEN); /* that's probably a big enough FD space per process, right? */
  rv = get_event_field("a0", fd_str, syscall_entry->msg, syscall_entry->msg_len);
  if(rv < 0)
    fprintf(stderr,"ERR (%s): '%s' field was not found in entry for syscall %d\n", __func__, "a0", syscall_id);
  else
    fd = strtoul(fd_str, NULL, 16);
  free(fd_str);

  char *saddr = (char *) malloc(SADDR_LEN + 1);
  rv = get_event_field("saddr", saddr, sockaddr_entry->msg, sockaddr_entry->msg_len);
  if(rv < 0){
#ifdef DEBUGMSG
    fprintf(stderr,"ERR (%s): no saddr field for sockaddr entry\n", __func__);
#endif
  }

  if(pid >= 0 && fd >= 0) {
    FDFile f;
    f.type = FAUST_NODE_SOCKET;
    //f.saddr = saddr;
    (state->process_fd_fdfile_map)[pid][fd] = f;
    (state->process_fdfile_syscall_map)[pid][f] = syscall_id;
    rv = 0;
  }
  free(saddr);
  return rv;
}

TInt handle_recvfrom(PNEANet &ProvGraph, struct Queue * event_sequence, TInt syscall_id) {
  /* 1. TCP: this basically looks identical to read
   * 2. UDP: there will be a SOCKADDR entry; this could be the first time the
   *         saddr is seen! (bind saddr =/= recvfrom saddr (!))
   */

  int rv;
  log_entry *syscall_entry = (log_entry *)event_sequence->front->item;

  TInt pid = -1;
  char * pid_str = (char *) malloc(PID_STR_LEN);
  rv = get_event_field("pid", pid_str, syscall_entry->msg, syscall_entry->msg_len);
  if(rv < 0) {
    fprintf(stderr,"ERR (%s): '%s' field was not found in entry for syscall %d\n", __func__, "pid", syscall_id);
    dump_event_sequence(event_sequence,__func__);
  }
  else
    pid = atoi(pid_str);
  free(pid_str);

  TInt fd = -1;
  char * fd_str = (char *)malloc(FD_STR_LEN); /* that's probably a big enough FD space per process, right? */
  rv = get_event_field("a0", fd_str, syscall_entry->msg, syscall_entry->msg_len);
  if(rv < 0) {
    fprintf(stderr,"ERR (%s): '%s' field was not found in entry for syscall %d\n", __func__, "a0", syscall_id);
    dump_event_sequence(event_sequence,__func__);
  }
  else
    fd = strtoul(fd_str, NULL, 16);
  free(fd_str);

  // add socket FDFile if necessary
  log_entry *sockaddr_entry = NULL, *curr_entry = NULL;
  struct QNode * it = event_sequence->front;
  do {
    if(!it)
      break;

    curr_entry = (log_entry *) it->item;
    // there's only one SOCKADDR entry; could just break here
    if(!strcmp(curr_entry->type, "SOCKADDR")) {
      sockaddr_entry = curr_entry;
    }
    it = it->next;
  }
  while(it && it != event_sequence->front);

  // if UDP, add/update entry now
  if (sockaddr_entry) {
    char *saddr = (char *) malloc(SADDR_LEN + 1);
    rv = get_event_field("saddr", saddr, sockaddr_entry->msg, sockaddr_entry->msg_len);
    if(rv < 0){
#ifdef DEBUGMSG
      fprintf(stderr,"ERR (%s): no saddr field for sockaddr entry\n", __func__);
#endif
    }
    FDFile f;
    f.type = FAUST_NODE_SOCKET;
    //f.saddr = saddr;
    (state->process_fd_fdfile_map)[pid][fd] = f;
    (state->process_fdfile_syscall_map)[pid][f] = syscall_id;
  }

  if(pid >= 0) {
    TInt process_nid = get_or_create_node(ProvGraph, FAUST_NODE_PROCESS, (void *) &pid);
    // yes this is a hack
    TInt sock_nid = get_or_create_node(ProvGraph, FAUST_NODE_SOCKET, (void *) 1);
    //TInt sock_nid = get_or_create_node(ProvGraph, FAUST_NODE_SOCKET, process_fd_fdfile_map[pid][fd].saddr.c_str());
    edge_relation rel = FAUST_EDGE_USED;
    
    if (isBursting) {
       ProvGraph->AddIntAttrDatN(process_nid, 1, "isBursting");
    }

    TInt rel_eid = get_edge(process_nid, sock_nid, rel);
    if(rel_eid < 0) {
      rel_eid = create_edge(ProvGraph, process_nid, sock_nid,
                FAUST_EDGE_USED, syscall_id, 1);
      ProvGraph->AddIntAttrDatE(rel_eid,syscall_id,"T_s");
      ProvGraph->AddIntAttrDatE(rel_eid,syscall_id,"T_e");
      ProvGraph->AddIntAttrDatE(rel_eid,1,"Live");
    }
    else {
      TInt t_s_id = ProvGraph->GetIntAttrDatE(rel_eid, "T_s");
      TInt old_t_e_id = ProvGraph->GetIntAttrDatE(rel_eid, "T_e");

      bool create_new_edge = auxiliary_flow(ProvGraph, true, old_t_e_id, process_nid, sock_nid);

      if(!is_active(FAUST_FILTER_REDUNDANT_IO) || create_new_edge){
        // mark old edge dead
        ProvGraph->AddIntAttrDatE(rel_eid,0,"Live");

        // create new edge
        rel_eid = create_edge(ProvGraph, process_nid, sock_nid,
                                   rel, syscall_id, 1);
        ProvGraph->AddIntAttrDatE(rel_eid,syscall_id,"T_s");
        ProvGraph->AddIntAttrDatE(rel_eid,syscall_id,"T_e");
        ProvGraph->AddIntAttrDatE(rel_eid,1,"Live");
        
        if(is_active(FAUST_FILTER_REDUNDANT_IO) && is_active(FAUST_FILTER_IBURST)){
          filter_event(old_t_e_id, FAUST_FILTER_IBURST, DROP, state);
          TInt live_t_s = ProvGraph->GetIntAttrDatE(rel_eid, "T_s");
          filter_event(live_t_s, FAUST_FILTER_IBURST, DROP, state);
        } 
      }else{ // keep old edge, update T_e (filter all in between T_s, T_e)
        
        // create new dead edge
        
        TInt dead_edge_eid = create_edge(ProvGraph, process_nid, 
                sock_nid, rel, syscall_id, 0);
        ProvGraph->AddIntAttrDatE(dead_edge_eid,syscall_id,"T_s");
        ProvGraph->AddIntAttrDatE(dead_edge_eid,syscall_id,"T_e");
        ProvGraph->AddIntAttrDatE(dead_edge_eid,0,"Live");
        
        if(t_s_id  != old_t_e_id){
            filter_event(old_t_e_id, FAUST_FILTER_APPROX, DROP, state);
        }

        ProvGraph->AddIntAttrDatE(rel_eid,syscall_id,"T_e");
      }
    }
    rv = rel_eid;
  }

  return rv;
}

TInt handle_sendto(PNEANet &ProvGraph, struct Queue * event_sequence, TInt syscall_id) {
  /* 1. TCP: this basically looks identical to write
   * 2. UDP: there will be a SOCKADDR entry; this could be the first time the
   *         saddr is seen! (bind saddr =/= sendto saddr (!))
   */

  int rv;
  log_entry * syscall_entry = (log_entry *)event_sequence->front->item;

  //printf("WR (%d): %s\n", syscall_id, syscall_entry->msg);

  // dump_event_sequence(event_sequence, __func__);

  TInt pid = -1;
  char * pid_str = (char *) malloc(PID_STR_LEN);
  rv = get_event_field("pid", pid_str, syscall_entry->msg, syscall_entry->msg_len);
  if(rv < 0)
    fprintf(stderr,"ERR (%s): '%s' field was not found in entry for syscall %d\n", __func__, "pid", syscall_id);
  else
    pid = atoi(pid_str);
  free(pid_str);

  TInt fd = -1;
  char * fd_str = (char *)malloc(FD_STR_LEN); /* that's probably a big enough FD space per process, right? */
  rv = get_event_field("a0", fd_str, syscall_entry->msg, syscall_entry->msg_len);
  if(rv < 0)
    fprintf(stderr,"ERR (%s): '%s' field was not found in entry for syscall %d\n", __func__, "a0", syscall_id);
  else
    fd = strtoul(fd_str, NULL, 16);
  free(fd_str);

  // add socket FDFile if necessary
  log_entry *sockaddr_entry = NULL, *curr_entry = NULL;
  struct QNode * it = event_sequence->front;
  do {
    if(!it)
      break;

    curr_entry = (log_entry *) it->item;
    // there's only one SOCKADDR entry; could just break here
    if(!strcmp(curr_entry->type, "SOCKADDR")) {
      sockaddr_entry = curr_entry;
    }
    it = it->next;
  }
  while(it && it != event_sequence->front);

  // if UDP, add/update entry now
  if (sockaddr_entry) {
    char *saddr = (char *) malloc(SADDR_LEN + 1);
    rv = get_event_field("saddr", saddr, sockaddr_entry->msg, sockaddr_entry->msg_len);
    if(rv < 0){
#ifdef DEBUGMSG
      fprintf(stderr,"ERR (%s): no saddr field for sockaddr entry\n", __func__);
#endif
    }
    FDFile f;
    f.type = FAUST_NODE_SOCKET;
    //f.saddr = saddr;
    (state->process_fd_fdfile_map)[pid][fd] = f;
    (state->process_fdfile_syscall_map)[pid][f] = syscall_id;
  }

  if (pid >= 0) {
    TInt process_nid = get_or_create_node(ProvGraph, FAUST_NODE_PROCESS, (void *) &pid);
    // yes this is a hack
    TInt sock_nid = get_or_create_node(ProvGraph, FAUST_NODE_SOCKET, (void *) 1);
    //TInt sock_nid = get_or_create_node(ProvGraph, FAUST_NODE_SOCKET, process_fd_fdfile_map[pid][fd].saddr.c_str());
    edge_relation rel = FAUST_EDGE_WAS_GENERATED_BY;
    
    if (isBursting) {
       ProvGraph->AddIntAttrDatN(process_nid, 1, "isBursting");
    }
    
    TInt rel_eid = get_edge(sock_nid, process_nid, rel);
    if(rel_eid < 0){
      // printf("Creating edge between inode %d (fd %d) and pid %d\n", inode, fd, pid);
      rel_eid = create_edge(ProvGraph, sock_nid, process_nid,
                rel, syscall_id, 1);
      ProvGraph->AddIntAttrDatE(rel_eid,syscall_id,"T_s");
      ProvGraph->AddIntAttrDatE(rel_eid,syscall_id,"T_e");
    } else {
      TInt t_s_id = ProvGraph->GetIntAttrDatE(rel_eid, "T_s");
      TInt old_t_e_id = ProvGraph->GetIntAttrDatE(rel_eid, "T_e");

      bool create_new_edge = auxiliary_flow(ProvGraph, false, old_t_e_id, process_nid, sock_nid);

      if(!is_active(FAUST_FILTER_REDUNDANT_IO) || create_new_edge){
        // mark old edge dead
        ProvGraph->AddIntAttrDatE(rel_eid,0,"Live");

        // create new edge
        rel_eid = create_edge(ProvGraph, sock_nid, process_nid,
                                   rel, syscall_id, 1);
        ProvGraph->AddIntAttrDatE(rel_eid,syscall_id,"T_s");
        ProvGraph->AddIntAttrDatE(rel_eid,syscall_id,"T_e");
        ProvGraph->AddIntAttrDatE(rel_eid,1,"Live");
        
        if(is_active(FAUST_FILTER_REDUNDANT_IO) && is_active(FAUST_FILTER_IBURST)) {
          filter_event(old_t_e_id, FAUST_FILTER_IBURST, DROP, state);
          TInt live_t_s = ProvGraph->GetIntAttrDatE(rel_eid, "T_s");
          filter_event(live_t_s, FAUST_FILTER_IBURST, DROP, state);
        }
      }else{ // keep old edge, update T_e (filter all in between T_s, T_e)
        
        // create new dead edge
        
        TInt dead_edge_eid = create_edge(ProvGraph, sock_nid, 
                process_nid, rel, syscall_id, 0);
        ProvGraph->AddIntAttrDatE(dead_edge_eid,syscall_id,"T_s");
        ProvGraph->AddIntAttrDatE(dead_edge_eid,syscall_id,"T_e");
        ProvGraph->AddIntAttrDatE(dead_edge_eid,0,"Live");

        // filter_redundant_io(ProvGraph, rel_eid);
        if(t_s_id  != old_t_e_id){
            filter_event(old_t_e_id, FAUST_FILTER_APPROX, DROP, state);
        }

        ProvGraph->AddIntAttrDatE(rel_eid,syscall_id,"T_e");
      }
    }
    rv = rel_eid;
  }

  return rv;
}

TInt handle_unsupportedSyscall(PNEANet &ProvGraph, struct Queue * event_sequence, TInt syscall_id) {
  TInt rv = 0;
  
  if(is_active(FAUST_FILTER_UNSUPPORTED)) {
    
    if(!event_sequence || !event_sequence->front || !event_sequence->front->item){
      return -1;
    }
    
    //get syscall
    //log_entry * syscall_entry = (log_entry *)event_sequence->front->item;
    // printf("filtering unsupported syscall with id %d", syscall_id);
    
    //filter corresponding log entry
    (state->filter_lists)[syscall_id].push_back(FAUST_FILTER_UNSUPPORTED);
    (state->filter_actions_lists)[syscall_id].push_back(DROP);
    state->unsupported_events_removed++;
  }
  return rv;
}

TInt update_graph(PNEANet &ProvGraph, struct Queue * event_sequence, TInt syscall_id, int seq_start) {
  TInt rv = -1;

  if(!event_sequence)
    return rv;
  else if (!event_sequence->front)
    return rv;
  else if (!event_sequence->front->item)
    return rv;

  /* First log_entry in queue is always the SYSCALL, then CWD, then others */
  TInt syscall;
  log_entry * syscall_entry = (log_entry *)event_sequence->front->item;
  char * syscall_str = (char *) malloc(SYSCALL_STR_LEN);
  rv = get_event_field("syscall", syscall_str, syscall_entry->msg, syscall_entry->msg_len);
  if(rv < 0) {
    fprintf(stderr,"ERR (%s): '%s' field was not found in entry for syscall %d\n", __func__, "syscall", syscall_id);
    dump_event_sequence(event_sequence, __func__);
  }
  else
    syscall = strtoul(syscall_str, NULL, 0);
  free(syscall_str);

  char ts_string[50];
  rv = get_timestamp(syscall_entry->msg, ts_string, syscall_entry->msg_len);
  int ts = atoi(ts_string);

  if ((ts - seq_start) >= BURST_SEC) {
    if ((event_sequence != NULL) && (event_sequence->size >= BURST_PROC_LIM))
      //MARK PROCESS AS BURSTY
      isBursting = true;
  } else {
    isBursting = false;
  }
  // [nsm2] Do not print all syscalls
  //printf("SYS(%d): %s\n", syscall_id, syscall_entry->msg);

  // add syscall_id to list of syscall id's
  (state->syscall_ids).push_back(syscall_id);

  switch(syscall) {
    
  case __NR_execve:
    //printf("EXE(%d): %s\n", syscall_id, syscall_entry->msg);
    rv = handle_execve(ProvGraph, event_sequence, syscall_id);
    break;
  case __NR_open:
    //printf("OPN(%d): %s\n", syscall_id, syscall_entry->msg);
    rv = handle_open(ProvGraph, event_sequence, syscall_id);
    break;
  case __NR_close:
    //printf("CLS(%d): %s\n", syscall_id, syscall_entry->msg);
    rv = handle_close(ProvGraph, event_sequence, syscall_id);
    break;
  case __NR_read:
    rv = handle_read(ProvGraph, event_sequence, syscall_id);
    break;
  case __NR_write:
    rv = handle_write(ProvGraph, event_sequence, syscall_id);
    break;
  case __NR_unlink:
    rv = handle_unlink(ProvGraph, event_sequence, syscall_id);
  case __NR_unlinkat:
    rv = handle_unlinkat(ProvGraph, event_sequence, syscall_id);
    break;
  case __NR_exit:
    rv = handle_exit(ProvGraph, event_sequence, syscall_id);
    break;
  case __NR_exit_group:
    rv = handle_exit_group(ProvGraph, event_sequence, syscall_id);
    break;
  case __NR_connect:
  case __NR_accept: // yes, these share the same handler intentionally
    rv = handle_connect(ProvGraph, event_sequence, syscall_id);
    break;
  case __NR_sendto:
    rv = handle_sendto(ProvGraph, event_sequence, syscall_id);
    break;
  case __NR_recvfrom:
    rv = handle_recvfrom(ProvGraph, event_sequence, syscall_id);
    break;
  case __NR_mmap:
  case __NR_mprotect:
    // ignore mmap/mprotect syscalls

    state->entries_added -= delete_log_event(state->queue,syscall_id);
    state->events_added--;
    (state->syscall_ids).pop_back();

    break;

  // intentionally omitted: socket, listen, bind, shutdown
  // TODO: accept4, sendmsg, recvmsg, IPv6
  default:
    rv = handle_unsupportedSyscall(ProvGraph, event_sequence, syscall_id);
    break;
  }

 exit:
  return rv;
}


void delete_graph_event(PNEANet &ProvGraph, int event_id){

  TInt EdgeId = -1;
  TInt EventId = event_id;

  std::map<TInt,TInt>::iterator it = state->event_map.find(EventId);

  if ( state->event_map.find(EventId) == state->event_map.end() )
    return;
  else
    EdgeId =  it->second;

  TNEANet::TEdgeI edge = ProvGraph->GetEI(EdgeId);
  TInt SrcId = edge.GetSrcNId();
  TInt DstId = edge.GetDstNId();

  /* Delete the edge corresponding to event_id */
  ProvGraph->DelEdge(EdgeId);

  /* Check to see if we should delete source node too */
  TNEANet::TNodeI src = ProvGraph->GetNI(SrcId);
  if( !src.GetInDeg() && !src.GetOutDeg() )
    ProvGraph->DelNode(SrcId);

  /* Check to see if we should delete dest node too */
  TNEANet::TNodeI dst = ProvGraph->GetNI(DstId);
  if( !dst.GetInDeg() && !dst.GetOutDeg() )
    ProvGraph->DelNode(DstId);

}


struct Queue * curr_event_sequence = NULL;
TInt curr_syscall_id = -1;
int sequence_start = -1;

void process_entry(PNEANet &ProvGraph, struct Queue * queue, struct log_entry * entry){

  /* No matter what, add entry to the full queue */
  struct log_entry * temp;
  int item_id = enqueue(queue, (void *) entry);
  state->entries_added++;

  /* If this entry is a syscall,
     open new event sequence and add to queue */
  if(!strcmp(entry->type,"SYSCALL")) {
    
    /* If there was event loss, we may still
       have an in-progress event sequence.
       Attempt to update the graph with what we have */
    if(curr_syscall_id > 0 && curr_event_sequence) {
      if(curr_syscall_id < item_id){
        update_graph(ProvGraph, curr_event_sequence, curr_syscall_id, sequence_start);
      }

      /* Destroy the curr event sequence.
         DON'T FREE ITEMS because they're also stored in queue...*/
      destroyQueue(curr_event_sequence);
      curr_event_sequence = NULL;
      curr_syscall_id = -1;
    }

    /* Create new event sequence */
    curr_syscall_id = item_id;
    char ts_string[50];
    int rv = get_timestamp(entry->msg, ts_string, entry->msg_len);
    int ts = atoi(ts_string);
    
    if (rv > 0)
      sequence_start = ts;
    curr_event_sequence = createQueue();
    state->events_added++;
    
  }
  /* only add to the event sequence if one exists
     (e.g., what if there was dropped entries or we started in the middle of an event?)*/
  if(curr_syscall_id > 0 && curr_event_sequence) {
    enqueue(curr_event_sequence, entry);

    /* Ideally, we'll be updating the graph down here.
       Need to check for both SYSCALL and EOE though
       in case of entry loss */
    if(!strcmp(entry->type,"EOE")) {
      update_graph(ProvGraph, curr_event_sequence, curr_syscall_id, sequence_start);
      /* Destroy the curr event sequence.
         DON'T FREE ITEMS because they're also stored in queue...*/
      destroyQueue(curr_event_sequence);
      curr_event_sequence = NULL;
      curr_syscall_id = -1;
      sequence_start = -1;
    }

  }
 exit:
  return;

}
