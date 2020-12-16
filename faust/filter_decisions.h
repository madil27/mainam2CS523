#ifndef FILTER_DECISIONS_H
#define FILTER_DECISIONS_H

#define OUTPUT_FILTER_DECISIONS true

double get_syscall_timestamp(struct Queue * queue, TInt syscall_id){
  
  // get queue entry for syscall_id
  QNode* qnode = queue_get(queue, syscall_id);
 
  struct log_entry *syscall_entry = (struct log_entry *) qnode->item;

  double timestamp;
  char msg_str[32];
  TInt rv = get_event_field("msg", msg_str, syscall_entry->msg, syscall_entry->msg_len);
  
  if(rv < 0) {
    fprintf(stderr,"ERR (%s): '%s' field was not found in entry for syscall %d\n", __func__, "msg", syscall_id);
  }
  else{
    char* colon = strchr(msg_str, ':');
    *colon = '\0';
    sscanf(msg_str + 6, "%lf", &timestamp);
  }

  return timestamp;
}

int get_syscall_size(struct Queue * queue, TInt syscall_id){

  // get queue entry for syscall_id
  QNode* qnode = queue_get(queue, syscall_id);

  struct log_entry* entry = (struct log_entry *) qnode->item;

  int total_size = entry->msg_len;

  qnode = qnode->next;

  char type_str[TYPE_LEN];

  while(qnode){

    entry = (struct log_entry *) qnode->item;

    int rv = get_event_field("type", type_str, entry->msg, entry->msg_len);
    if(rv < 0){
      printf("ERR (%s): '%s' field was not found in entry for syscall %d\n", __func__, "type", qnode->id);
    }

    if(!strcmp("SYSCALL", type_str)){
      break;
    }else{
      total_size += entry->msg_len;
    }

    qnode = qnode->next;
  }
  
  return total_size;
}

// int get_syscall_num(struct Queue * queue, TInt syscall_id){
  
//   // get queue entry for syscall_id
//   QNode* qnode = queue_get(queue, syscall_id);
 
//   struct log_entry *syscall_entry = (struct log_entry *) qnode->item;

//   TInt syscall;
//   char syscall_str[SYSCALL_STR_LEN];
//   TInt rv = get_event_field("syscall", syscall_str, syscall_entry->msg, syscall_entry->msg_len);
  
//   if(rv < 0) {
//     fprintf(stderr,"ERR (%s): '%s' field was not found in entry for syscall %d\n", __func__, "syscall", syscall_id);
//   }
//   else{
//     syscall = strtoul(syscall_str, NULL, 0);
//   }
  
//   return syscall;
// }

/* Output Filter Decisions to CSV */
void write_filter_decisions(State* state, PNEANet &ProvGraph, struct Queue * queue, std::string& filter_decisions_filename){

  // open file
  std::ofstream filter_decisions_file(filter_decisions_filename,
                                      std::ofstream::trunc);

  // write header
  // Syscall ID - Variable syscall_id (unique identifier)
  // Timestamp of Syscall Entry
  // (Hostname, Hash, ...)
  // Size - Size in Bytes of entire syscall entry
  // Syscall Num - Syscall Number in asm/unistd_64.h
  // List of Filters (filter_names)
  
  printf("WRITING TO FILE!!\n");
  filter_decisions_file << "Syscall ID,Timestamp,Size,Syscall Num";

  for(filters_t filter: active_filters){
    filter_decisions_file << "," << filter_to_name.find(filter)->second;
  }

  filter_decisions_file << std::endl;

  // for every syscall
  
  long long raw_size = 0, filtered_size = 0;

  for(auto sids_it = state->syscall_ids.begin(); 
      sids_it != state->syscall_ids.end(); sids_it++){
    TInt syscall_id = *sids_it;

    // compute syscall metadata

    double syscall_timestamp = get_syscall_timestamp(queue, syscall_id);
    int syscall_size = get_syscall_size(queue, syscall_id);
    // int syscall_num = get_syscall_num(queue, syscall_id);

    raw_size += syscall_size;

    // determine which filters made what decisions

    filter_actions_t decisions[TOTAL_NUM_FILTERS];
    std::fill(decisions, decisions + TOTAL_NUM_FILTERS, ALLOW);

    auto fl_it = state->filter_lists.find(syscall_id);

    // some filter did not accept
    if(fl_it != state->filter_lists.end()){
      std::vector<filters_t>& syscall_filter_list = fl_it->second;
      std::vector<filter_actions_t>& syscall_filter_actions_list =
        state->filter_actions_lists[syscall_id];

      for(int i = 0; i < syscall_filter_list.size(); i++){
        decisions[syscall_filter_list[i]] = 
          syscall_filter_actions_list[i];
      }

      if(decisions[FAUST_FILTER_DPRESERVE_SD] == DROP){
        filtered_size += syscall_size;
      }
    }

    // write to file

    // filter_decisions_file << std::setprecision(17)
    //                       << syscall_id << "," 
    //                       << syscall_timestamp << ","
    //                       << syscall_size << ","
    //                       << syscall_num;

    for(filters_t filter: active_filters){
      filter_decisions_file << "," << action_names[decisions[filter]];
    }

    filter_decisions_file << std::endl;
  }

  filter_decisions_file.close();

  printf("FILTER DECISIONS WRITTEN TO FILE\n"); 

  std::ofstream approx_reduction_file("approx_size.txt",
              std::ofstream::app);
  approx_reduction_file
    << raw_size << "\t"
    << filtered_size << std::endl;
  approx_reduction_file.close();
}

#endif /* FILTER_DECISIONS_H */
