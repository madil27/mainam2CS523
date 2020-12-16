#ifndef APPROX_H
#define APPROX_H

#include "regex.h"

struct Filename {
  std::string cwd;
  std::string path;
};

//thread_local State* state;

//voit init_approx_state(State* new_state);
int approx_filter(PNEANet &ProvGraph, struct Queue *queue);
void preprocess(PNEANet &ProvGraph, struct Queue *queue);
Filename get_filename(QNode *qnode);
std::string construct_filename(Filename f);
std::string construct_filename(char* cwd, char* path);
void overwrite(QNode *qnode, const std::string& cwd_regex, const std::string& path_regex);

/* Process ID (pid) -> inode -> Filename */
// are following unnecessary?
std::map<TInt, Filename> inode_to_filename_map;

/* The following are ordered consistently */
std::vector<TInt> inodes;
std::vector<std::string> cwds;
std::vector<std::string> paths;

/*void init_approx_state(State* new_state) {
  state = new_state;
}*/

int approx_filter(PNEANet &ProvGraph, struct Queue *queue){

  // output files for regex maps
  
  std::ofstream cwd_regex_stream("cwd_regex.txt", std::ofstream::trunc);
  std::ofstream path_regex_stream("path_regex.txt", std::ofstream::trunc);

  // fill process_inode_to_filename_map, cwds, paths
  preprocess(ProvGraph, queue);

  // learn regexes for cwds, paths
  std::vector<std::unordered_set<std::string> > cwd_groups = gen_groups_dir(cwds);
  std::map<std::string, std::string> cwd_regex_map = gen_regex_map_dir(cwd_groups);

  /*printf("cwd_regex_map\n");

  for(auto const& crm_it: cwd_regex_map){
    printf("%s: %s\n", crm_it.first.c_str(), crm_it.second.c_str());
  }*/
  
  for(auto const& crm_it: cwd_regex_map){
    cwd_regex_stream << crm_it.first << ": "
                     << crm_it.second << std::endl;
  }

  std::vector<std::unordered_set<std::string> > path_groups = gen_groups(paths);
  std::map<std::string, std::string> path_regex_map = gen_regex_map(path_groups);

  /*printf("path_regex_map\n");

  for(auto const& prm_it: path_regex_map){
    printf("%s: %s\n", prm_it.first.c_str(), prm_it.second.c_str());
  }*/

  for(auto const& prm_it: path_regex_map){
    path_regex_stream << prm_it.first << ": "
                      << prm_it.second << std::endl;
  }

  // group inodes, filter, overwrite

  std::map<std::string, std::map<std::string, std::vector<TInt> > > inode_groups;

  for(int i = 0; i < inodes.size(); i++){
    TInt inode = inodes[i];

    if(cwd_regex_map[cwds[i]].length() +
        path_regex_map[paths[i]].length() < LENGTH_THRESHOLD) continue;

    inode_groups[cwd_regex_map[cwds[i]]][path_regex_map[paths[i]]].push_back(inode);
  }

  for(auto const& ig_it: inode_groups){
    const std::string& cwd_regex = ig_it.first;
    const auto& inode_groups2 = ig_it.second;

    for(auto const& ig2_it: inode_groups2){
      const std::string& path_regex = ig2_it.first;
      const std::vector<TInt>& inode_group = ig2_it.second;
      // group of inodes corresponding to filename cwd_regex/path_regex

      // read edges out of group
      // write edges out of group

      std::map<TInt, std::vector<TInt> > pid_to_read_edges_map;
      std::map<TInt, std::vector<TInt> > pid_to_write_edges_map;

      for(auto const& inode: inode_group){
        FDFile f;
        f.type = FAUST_NODE_INODE;
        f.inode = inode;
        TInt inode_node_id = (state->fdfile_map)[f];
        TNEANet::TNodeI inode_node = ProvGraph->GetNI(inode_node_id);

        // read edges (in-edges to inode)
        // some dead edges not added to this list

        for(int i = 0; i < inode_node.GetInDeg(); i++){
          TInt edge_id = inode_node.GetInEId(i);
          TNEANet::TEdgeI edge = ProvGraph->GetEI(edge_id);

          if(ProvGraph->GetIntAttrDatE(edge_id, "rel")
             == FAUST_EDGE_USED){
            TInt process_node_id = edge.GetSrcNId();
            TInt pid = (state->process_id_map)[process_node_id];

            pid_to_read_edges_map[pid].push_back(edge_id);
          }
        }

        // write edges (out-node from inode)

        for(int i = 0; i < inode_node.GetOutDeg(); i++){
          TInt edge_id = inode_node.GetOutEId(i);
          TNEANet::TEdgeI edge = ProvGraph->GetEI(edge_id);

          if(ProvGraph->GetIntAttrDatE(edge_id, "rel")
             == FAUST_EDGE_WAS_GENERATED_BY){
            TInt process_node_id = edge.GetDstNId();
            TInt pid = (state->process_id_map)[process_node_id];

            pid_to_write_edges_map[pid].push_back(edge_id);
          }
        }
      }

      // for every process only pick one (oldest)
      // filter rest, and overwrite remaining with filename

      for(auto const& prem_it: pid_to_read_edges_map){
        TInt pid = prem_it.first;
        const std::vector<TInt>& read_edges = prem_it.second;

        // find oldest edge

        TInt oldest_edge_id = -1;
        TInt oldest_t_s_id = -1;

        for(TInt edge_id: read_edges){
          TInt t_s_id = ProvGraph->GetIntAttrDatE(edge_id, "T_s");

          if(oldest_t_s_id == -1 || t_s_id < oldest_t_s_id){
            oldest_t_s_id = t_s_id;
            oldest_edge_id = edge_id;
          }
        }

        // filter

        for(TInt edge_id: read_edges){
          if(edge_id != oldest_edge_id){
            TInt syscall_id = (state->event_id_map)[edge_id];
            filter_event(syscall_id, FAUST_FILTER_APPROX, DROP, state);
          }
        }

        // overwrite CWD, PATH

        if(oldest_edge_id != -1){
          TInt oldest_syscall_id = (state->event_id_map)[oldest_edge_id];
          QNode* qnode = queue_get(queue, oldest_syscall_id);

          filter_event(oldest_syscall_id, FAUST_FILTER_APPROX, MANGLE, state);
        
          overwrite(qnode, cwd_regex, path_regex);
        }
      }

      for(auto const& pwem_it: pid_to_write_edges_map){
        TInt pid = pwem_it.first;
        const std::vector<TInt>& write_edges = pwem_it.second;

        // find oldest edge

        TInt oldest_edge_id = -1;
        TInt oldest_t_s_id = -1;

        for(TInt edge_id: write_edges){
          TInt t_s_id = ProvGraph->GetIntAttrDatE(edge_id, "T_s");

          if(oldest_t_s_id == -1 || t_s_id < oldest_t_s_id){
            oldest_t_s_id = t_s_id;
            oldest_edge_id = edge_id;
          }
        }

        // filter

        for(TInt edge_id: write_edges){
          if(edge_id != oldest_edge_id){
            TInt syscall_id = (state->event_id_map)[edge_id];
            filter_event(syscall_id, FAUST_FILTER_APPROX, DROP, state);
          }
        }

        // overwrite CWD, PATH
        if(oldest_edge_id != -1){ 
          TInt oldest_syscall_id = (state->event_id_map)[oldest_edge_id];
          QNode* qnode = queue_get(queue, oldest_syscall_id);

          filter_event(oldest_syscall_id, FAUST_FILTER_APPROX, MANGLE, state);

          overwrite(qnode, cwd_regex, path_regex);
        }
      }
    }
  }

  inode_to_filename_map.clear();
  inodes.clear();
  cwds.clear();
  paths.clear();
}

/* Currently prints out all filenames in queue */

void preprocess(PNEANet &ProvGraph, struct Queue *queue){

  // prints all nodes in graph
  /* for(TNEANet::TNodeI n = ProvGraph->BegNI(); n != ProvGraph->EndNI(); n++){
    printf("node-id = %d, in-deg = %d, out-deg %d\n", n.GetId(), n.GetInDeg(), n.GetOutDeg());
  } */

  // loop through processes in process_map
  for(std::map<TInt, TInt>::iterator pm_it = (state->process_map).begin(); 
      pm_it != (state->process_map).end(); pm_it++){
    TInt pid = pm_it->first;
    TInt node_id = pm_it->second;

    TNEANet::TNodeI node = ProvGraph->GetNI(node_id);

    // printf("pid: %d, node-id = %d, in-deg = %d, out-deg = %d\n", pid, node.GetId(), node.GetInDeg(), node.GetOutDeg());

    // loop through in-edges for process (write events)
    for(int i = 0; i < node.GetInDeg(); i++){
      TInt edge_id = node.GetInEId(i);
      TNEANet::TEdgeI edge = ProvGraph->GetEI(edge_id);

      if(ProvGraph->GetIntAttrDatE(edge_id, "rel")
         != FAUST_EDGE_WAS_GENERATED_BY){
        continue;
      }

      // get inode for write event
      TInt inode_id = edge.GetSrcNId();
      FDFile f = (state->fdfile_id_map)[inode_id];
      if (f.type != FAUST_NODE_INODE)
        continue;

      TInt inode = f.inode;
      if(inode < 3){ // using std*
        continue;
      }

      // get syscall_id in queue for inode open
      // multiple accesses to the same file overwrites syscall_id
      TInt syscall_id = (state->process_fdfile_syscall_map)[pid][f];

      // get queue entry for syscall_id
      QNode* qnode = queue_get(queue, syscall_id);

      inode_to_filename_map[inode] = get_filename(qnode);

      Filename fn = inode_to_filename_map[inode];
      inodes.push_back(inode);
      cwds.push_back(fn.cwd);
      paths.push_back(fn.path);

      std::string filename = construct_filename(fn);
      // printf("write pid=%d (inode=%d): %s\n", pid, inode, filename.c_str());
    }

    // loop through out-edges for process (read events)
    for(int i = 0; i < node.GetOutDeg(); i++){
      TInt edge_id = node.GetOutEId(i);
      TNEANet::TEdgeI edge = ProvGraph->GetEI(edge_id);

      if(ProvGraph->GetIntAttrDatE(edge_id, "rel")
         != FAUST_EDGE_USED){
        continue;
      }

      // get inode for read event
      TInt inode_id = edge.GetDstNId();
      FDFile f = (state->fdfile_id_map)[inode_id];
      if (f.type != FAUST_NODE_INODE)
        continue;

      TInt inode = f.inode;
      if(inode < 3){ // using std*
        continue;
      }

      // get syscall_id in queue for inode open
      // multiple accesses to the same file overwrites syscall_id
      TInt syscall_id = (state->process_fdfile_syscall_map)[pid][f];

      // get queue entry for syscall_id
      QNode* qnode = queue_get(queue, syscall_id);

      inode_to_filename_map[inode] = get_filename(qnode);

      Filename fn = inode_to_filename_map[inode];
      inodes.push_back(inode);
      cwds.push_back(fn.cwd);
      paths.push_back(fn.path);
      std::string filename = construct_filename(fn);
      // printf("read pid=%d (inode=%d): %s\n", pid, inode, filename.c_str());
    }
  }
}

/* Gets filename from syscall at qnode */

Filename get_filename(QNode *qnode){

  // get cwd and path
  char cwd[256], path[256];
  struct log_entry *entry;
  char type_str[TYPE_LEN];

  qnode = qnode->next; // skip over SYSCALL entry
  while(qnode){
    entry = (struct log_entry *) qnode->item;

    int rv = get_event_field("type", type_str, entry->msg, entry->msg_len);
    if(rv < 0){
      printf("ERR (%s): '%s' field was not found in entry for syscall %d\n", __func__, "type", qnode->id);
    }

    if(!strcmp("SYSCALL", type_str)){
      break;
    }else if(!strcmp("CWD", type_str)){
      get_event_field("cwd", cwd, entry->msg, entry->msg_len);
    }else if(!strcmp("PATH", type_str)){
      get_event_field("name", path, entry->msg, entry->msg_len);
    }

    qnode = qnode->next;
  }

  // construct filename from cwd and path

  // Remote end quotes
  cwd[strlen(cwd) - 1] = '\0';
  path[strlen(path) - 1] = '\0';
  
  // '+ 1' removes initial quote
  return Filename{cwd + 1, path + 1};
}

/* Constructs filename from cwd and path */

std::string construct_filename(Filename fn){
  char cwd[256], path[256];
  strcpy(cwd, fn.cwd.c_str());
  strcpy(path, fn.path.c_str());
  return construct_filename(cwd, path);
}

std::string construct_filename(char *cwd, char *path){
  std::string filename = "";

  if(!strncmp(path, "/", 1)){ // absolute path
    filename.append(path);
  }else if(!strncmp(path, "./", 2)){ // ./filename
    return construct_filename(cwd, path+2);
  }else if(!strncmp(path, "../", 3)){ // ../filename
    for(int i = strlen(cwd)-1; i >= 0; i--){
      while(cwd[i] != '/'){
        cwd[i] = '\0';
      }
    }

    return construct_filename(cwd, path+3);
  }else{ // plain filename
    filename.append(cwd);
    filename.append("/");
    filename.append(path);
  }

  return filename;
}

/* Overwrite CWD entry with cwd_regex and PATH with path_regex */

void overwrite(QNode *qnode, const std::string& cwd_regex, const std::string& path_regex){

  struct log_entry *entry;
  char type_str[TYPE_LEN];

  qnode = qnode->next; // skip over SYSCALL entry

  while(qnode){
    entry = (struct log_entry *) qnode->item;

    int rv = get_event_field("type", type_str, entry->msg, entry->msg_len);
    if(rv < 0){
      printf("ERR (%s): '%s' field was not found in entry for syscall %d\n", __func__, "type", qnode->id);
    }

    if(!strcmp("SYSCALL", type_str)){
      break;
    }else if(!strcmp("CWD", type_str)){

      std::string entry_msg(entry->msg, entry->msg_len);
      size_t cwd_start = entry_msg.find("cwd") + 5; // skip ="
      size_t cwd_end = entry_msg.find("\"", cwd_start) - 1; // skip "

      entry_msg.replace(cwd_start, cwd_end - cwd_start + 1, cwd_regex);

      free(entry->msg);

      entry->msg = strdup(entry_msg.c_str());
      entry->msg_len = entry_msg.length();

    }else if(!strcmp("PATH", type_str)){

      std::string entry_msg(entry->msg, entry->msg_len);
      size_t path_start = entry_msg.find("name") + 5; // skip ="
      size_t path_end = entry_msg.find("\"", path_start) - 1; // skip "

      entry_msg.replace(path_start, path_end - path_start + 1, path_regex);

      free(entry->msg);
      entry->msg = strdup(entry_msg.c_str());
      entry->msg_len = entry_msg.length();
    }

    qnode = qnode->next;
  }
}

#endif /* APPROX_H */
