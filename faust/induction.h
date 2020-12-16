#ifndef INDUCTION_H
#define INDUCTION_H

#define OUTPUT_GRAMMAR true
#define OUTPUT_GRAMMAR_FILENAME "grammar.txt"

int induction_filter(PNEANet &ProvGraph, struct Queue *queue);
std::string get_process_name(QNode *qnode);

int induction_filter(PNEANet &ProvGraph, struct Queue *queue){
  
  // group process nodes by which process they correspond to
  
  std::map<std::string, std::vector<TInt> > process_groups;
  
  std::map<std::string, std::vector<std::string> > grammar;
   
  // loop through processes in process_map
  for(std::map<TInt, TInt>::iterator pm_it = (state->process_map).begin(); 
      pm_it != (state->process_map).end(); pm_it++){
    TInt pid = pm_it->first;
    TInt node_id = pm_it->second;

    TNEANet::TNodeI node = ProvGraph->GetNI(node_id);
    
    // find execve event associated with node
    
    // loop through out-edges for process
    for(int i = 0; i < node.GetOutDeg(); i++){
      TInt edge_id = node.GetOutEId(i);

      if(ProvGraph->GetIntAttrDatE(edge_id, "rel")
         == FAUST_EDGE_FORKED_BY){

        TInt event_id = state->event_id_map[edge_id];
        QNode* qnode = queue_get(queue, event_id);

        // find process name

        std::string process_name = get_process_name(qnode);

        process_groups[process_name].push_back(node_id);
      }
    }
  }

  // for every group
  // if group has more than 1 member
  // choose arbitrary invocation
  // for every (non-process) edge, check if present in other invocations
  // filter such edges, and create grammar rule for group

  for(std::map<std::string, std::vector<TInt> >::iterator pg_it
      = process_groups.begin(); pg_it != process_groups.end(); pg_it++){
    const std::string& process_name = pg_it->first;
    std::vector<TInt>& node_ids = pg_it->second;

    if(node_ids.size() <= 1) continue;

    std::map<TInt, int> in_nodes;   // frequency of in nodes
    std::map<TInt, int> out_nodes;  // frequency of out nodes

    for(TInt node_id: node_ids){
      TNEANet::TNodeI node = ProvGraph->GetNI(node_id);
      
      // loop through in-edges for process
      for(int i = 0; i < node.GetInDeg(); i++){
        TInt edge_id = node.GetInEId(i);
        TNEANet::TEdgeI edge = ProvGraph->GetEI(edge_id);

        TInt rel = ProvGraph->GetIntAttrDatE(edge_id, "rel");

        if(rel == FAUST_EDGE_FORKED_BY || rel == FAUST_EDGE_EXITED_BY){
          continue;
        }  

        TInt inode_id = edge.GetSrcNId();
        in_nodes[inode_id] += 1;
      }

      // loop through out-edges for process
      for(int i = 0; i < node.GetOutDeg(); i++){
        TInt edge_id = node.GetOutEId(i);
        TNEANet::TEdgeI edge = ProvGraph->GetEI(edge_id);

        TInt rel = ProvGraph->GetIntAttrDatE(edge_id, "rel");

        if(rel == FAUST_EDGE_FORKED_BY || rel == FAUST_EDGE_EXITED_BY){
          continue;
        }  

        TInt inode_id = edge.GetDstNId();
        out_nodes[inode_id] += 1;
      }
    }

    // for edges present in all other invocations, filter

    for(int k = 1; k < node_ids.size(); k++){
      TInt node_id = node_ids[k];
      TNEANet::TNodeI node = ProvGraph->GetNI(node_id);
      
      // loop through in-edges for process
      for(int i = 0; i < node.GetInDeg(); i++){
        TInt edge_id = node.GetInEId(i);
        TNEANet::TEdgeI edge = ProvGraph->GetEI(edge_id);

        TInt rel = ProvGraph->GetIntAttrDatE(edge_id, "rel");

        if(rel == FAUST_EDGE_FORKED_BY || rel == FAUST_EDGE_EXITED_BY){
          continue;
        }  

        TInt inode_id = edge.GetSrcNId();
        
        if(in_nodes[inode_id] == node_ids.size()){
          TInt syscall_id = (state->event_id_map)[edge_id];
          filter_event(syscall_id, FAUST_FILTER_INDUCTION, DROP, state);
        }
      }

      // loop through out-edges for process
      for(int i = 0; i < node.GetOutDeg(); i++){
        TInt edge_id = node.GetOutEId(i);
        TNEANet::TEdgeI edge = ProvGraph->GetEI(edge_id);

        TInt rel = ProvGraph->GetIntAttrDatE(edge_id, "rel");

        if(rel == FAUST_EDGE_FORKED_BY || rel == FAUST_EDGE_EXITED_BY){
          continue;
        }  

        TInt inode_id = edge.GetDstNId();
        
        if(out_nodes[inode_id] == node_ids.size()){
          TInt syscall_id = (state->event_id_map)[edge_id];
          filter_event(syscall_id, FAUST_FILTER_INDUCTION, DROP, state);
        }
      }
    }

    // create grammar for such edges
    // output to file

    TInt init_node_id = node_ids[0];
    TNEANet::TNodeI init_node = ProvGraph->GetNI(init_node_id);

    TInt pid = (state->process_id_map)[init_node_id];

    // loop through in-edges for process
    for(int i = 0; i < init_node.GetInDeg(); i++){
      TInt edge_id = init_node.GetInEId(i);
      TNEANet::TEdgeI edge = ProvGraph->GetEI(edge_id);

      TInt rel = ProvGraph->GetIntAttrDatE(edge_id, "rel");

      if(rel == FAUST_EDGE_FORKED_BY || rel == FAUST_EDGE_EXITED_BY){
        continue;
      }  

      TInt inode_id = edge.GetSrcNId();
      
      if(in_nodes[inode_id] == node_ids.size()){
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

        // no open event present
        if(syscall_id == 0) continue;

        // get queue entry for syscall_id
        QNode* qnode = queue_get(queue, syscall_id);

        Filename fn  = get_filename(qnode);
        std::string fn_str = construct_filename(fn);

        grammar[process_name].push_back(fn_str);
      }
    }

    // loop through out-edges for process
    for(int i = 0; i < init_node.GetOutDeg(); i++){
      TInt edge_id = init_node.GetOutEId(i);
      TNEANet::TEdgeI edge = ProvGraph->GetEI(edge_id);

      TInt rel = ProvGraph->GetIntAttrDatE(edge_id, "rel");

      if(rel == FAUST_EDGE_FORKED_BY || rel == FAUST_EDGE_EXITED_BY){
        continue;
      }  

      TInt inode_id = edge.GetDstNId();
      
      if(out_nodes[inode_id] == node_ids.size()){
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

        // no open event present
        if(syscall_id == 0) continue;

        // get queue entry for syscall_id
        QNode* qnode = queue_get(queue, syscall_id);

        Filename fn  = get_filename(qnode);
        std::string fn_str = construct_filename(fn);

        grammar[process_name].push_back(fn_str);
      }
    }
  }

  // output grammar
  
  if(OUTPUT_GRAMMAR){
    std::ofstream grammar_file(OUTPUT_GRAMMAR_FILENAME,
                               std::ofstream::trunc);

    grammar_file << "Epoch" << std::endl;
    grammar_file << std::endl;

    for(auto const& rule_it: grammar){
      const std::string& process_name = rule_it.first;
      const std::vector<std::string>& file_names = rule_it.second;

      grammar_file << process_name << std::endl;
      
      for(auto const& file_name: file_names){
        grammar_file << "\t" << file_name << std::endl;
      }

      grammar_file << std::endl;
    }
  }
}

// return process_name associated with execve call
std::string get_process_name(QNode *qnode){
  
  char proc_name[256];
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
    }else if(!strcmp("EXECVE", type_str)){
      get_event_field("a0", proc_name, entry->msg, entry->msg_len);
    }

    qnode = qnode->next;
  }

  std::string s(proc_name);
  return s;
}

#endif /* INDUCTION_H */
