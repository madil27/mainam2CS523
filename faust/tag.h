#ifndef TAG_H
#define TAG_H

#include <vector>
#include <string>

#define TRACE true

void backward(int syscall_id, PNEANet &ProvGraph, struct Queue * queue,
    std::set<int>& traced){
  if(traced.count(syscall_id) > 0) return;

  traced.insert(syscall_id);

  // go along *forward* edges (backward in time)

  if(state->event_map.count(syscall_id) == 0) return;
  TInt edge_id = state->event_map[syscall_id];
  if(!ProvGraph->IsEdge(edge_id)) return;
  TNEANet::TEdgeI edge = ProvGraph->GetEI(edge_id);

  TInt dst_node_id = edge.GetDstNId();
  TNEANet::TNodeI dst_node = ProvGraph->GetNI(dst_node_id);
  for(int i = 0; i < dst_node.GetOutDeg(); i++){
    TInt out_edge_id = dst_node.GetOutEId(i);
    if(state->event_id_map.count(out_edge_id) == 0) continue;
    int out_syscall_id = state->event_id_map[out_edge_id];
    backward(out_syscall_id, ProvGraph, queue, traced);
  }
}

void forward(int syscall_id, PNEANet &ProvGraph, struct Queue * queue,
    std::set<int>& traced){
  if(traced.count(syscall_id) > 0) return;

  traced.insert(syscall_id);

  // go along *backward* edges (forward in time)

  if(state->event_map.count(syscall_id) == 0) return;
  TInt edge_id = state->event_map[syscall_id];
  if(!ProvGraph->IsEdge(edge_id)) return;
  TNEANet::TEdgeI edge = ProvGraph->GetEI(edge_id);

  TInt src_node_id = edge.GetSrcNId();
  TNEANet::TNodeI src_node = ProvGraph->GetNI(src_node_id);
  for(int i = 0; i < src_node.GetInDeg(); i++){
    TInt in_edge_id = src_node.GetInEId(i);
    if(state->event_id_map.count(in_edge_id) == 0) continue;
    int in_syscall_id = state->event_id_map[in_edge_id];
    forward(in_syscall_id, ProvGraph, queue, traced);
  }
}

void tag_filter(PNEANet &ProvGraph, struct Queue * queue){
  std::set<int> tagged;
  std::set<int> traced;

  std::vector<std::string> keywords = {
    "whoami", // noor
    "ifconfig", // noor
    "/etc/shadow", // sneha
    "clean", // darpa
  };

  std::vector<std::string> cwds = {
    "/home/admin", // darpa
    "/home/admin", // darpa
    "/var/log", // darpa
  };

  std::vector<std::string> paths = {
    "clean", // darpa
    "profile", // darpa
    "xdev", // darpa
  };

  // loop through all events
  // tag those that match keywords

  for(auto syscall_id: state->syscall_ids){
    QNode* qnode = queue_get(queue, syscall_id);
    struct log_entry* entry = (struct log_entry *) qnode->item;

    // check SYSCALL entry
    std::string msg(entry->msg);
    for(auto& keyword: keywords){
      if(msg.find(keyword) != std::string::npos){
        tagged.insert(syscall_id);
        break;
      }
    }

    qnode = qnode->next;
    char type_str[TYPE_LEN];

    std::set<int> cwd_indices;

    while(qnode){
      entry = (struct log_entry *) qnode->item;
      int rv = get_event_field("type",
          type_str, entry->msg, entry->msg_len);

      if(!strcmp("SYSCALL", type_str)){
        break;
      }else if(!strcmp("CWD", type_str)){

        // check CWD entry
        std::string msg(entry->msg);
        for(int i = 0; i < cwds.size(); i++){
          if(msg.find(cwds[i]) != std::string::npos){
            cwd_indices.insert(i);
            break;
          }
        }

      }else if(!strcmp("PATH", type_str)){

        // check PATH entry
        std::string msg(entry->msg);
        for(int i = 0; i < paths.size(); i++){
          if(msg.find(paths[i]) != std::string::npos
              && cwd_indices.find(i) != cwd_indices.end()){
            tagged.insert(syscall_id);
            break;
          }
        }

      }

      qnode = qnode->next;
    }
  }

  // for each tagged event, do forward + backward trace
  // tag everything seen

  if(TRACE){
    for(auto syscall_id: tagged){
      backward(syscall_id, ProvGraph, queue, traced);
      forward(syscall_id, ProvGraph, queue, traced);
    }
  }

  // filter all untagged/untraced events

  if(TRACE){
    for(auto syscall_id: state->syscall_ids){
      if(traced.find(syscall_id) == traced.end()){
        filter_event(syscall_id, FAUST_FILTER_TAG, DROP, state);
      }
    }
  }else{
    for(auto syscall_id: state->syscall_ids){
      if(tagged.find(syscall_id) == tagged.end()){
        filter_event(syscall_id, FAUST_FILTER_TAG, DROP, state);
      }
    }
  }
}

#endif /* TAG_H */
