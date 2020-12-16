#ifndef FILTERS_H
#define FILTERS_H

#include "structures.h"
// #include "filter_decisions.h"

#include <vector>
#include <map>

const std::vector<filters_t> active_filters = {
  FAUST_FILTER_REDUNDANT_IO,
  FAUST_FILTER_LOG_GC,
  FAUST_FILTER_APPROX,
  FAUST_FILTER_INDUCTION,
  FAUST_FILTER_IBURST,
  // FAUST_FILTER_UNSUPPORTED,
  // FAUST_FILTER_TAG,
  FAUST_FILTER_DPRESERVE_FD,
  FAUST_FILTER_DPRESERVE_SD,
  FAUST_FILTER_NODEMERGE,
};

const std::map<filters_t, const char*> filter_to_name = {
  {FAUST_FILTER_REDUNDANT_IO, "REDUNDANT_IO"} ,
  {FAUST_FILTER_LOG_GC,       "LOG_GC"},
  {FAUST_FILTER_APPROX,       "APPROX"},
  {FAUST_FILTER_INDUCTION,    "INDUCTION"},
  {FAUST_FILTER_UNSUPPORTED,  "UNSUPPORTED"},
  {FAUST_FILTER_IBURST,       "IBURST"},
  {FAUST_FILTER_TAG,          "TAG"},
  {FAUST_FILTER_DPRESERVE_FD, "DPRESERVE_FD"},
  {FAUST_FILTER_DPRESERVE_SD, "DPRESERVE_SD"},
  {FAUST_FILTER_NODEMERGE, "NODEMERGE"},
};

int get_syscall_num(struct Queue * queue, TInt syscall_id){
  
  // get queue entry for syscall_id
  QNode* qnode = queue_get(queue, syscall_id);
 
  struct log_entry *syscall_entry = (struct log_entry *) qnode->item;

  TInt syscall;
  char syscall_str[SYSCALL_STR_LEN];
  TInt rv = get_event_field("syscall", syscall_str, syscall_entry->msg, syscall_entry->msg_len);
  
  if(rv < 0) {
    fprintf(stderr,"ERR (%s): '%s' field was not found in entry for syscall %d\n", __func__, "syscall", syscall_id);
    fprintf(stderr,"ERR (%s): '%s' field was not found in entry for syscall %s\n", __func__, "syscall", syscall_entry->msg);

  }
  else{
    syscall = strtoul(syscall_str, NULL, 0);
    // printf("SYSCALL %d\n", syscall);
  }
  
  return syscall;
}



const int FAUST_NUM_FILTERS = active_filters.size();

bool is_active(filters_t filter){
  return std::find(active_filters.begin(), active_filters.end(), filter)
         != active_filters.end();
}

void filter_event(TInt syscall_id, filters_t filter, filter_actions_t filter_action, State* state){
  if(!is_active(filter)) return;

  if(std::find((state->filter_lists)[syscall_id].begin(),
               (state->filter_lists)[syscall_id].end(),
               filter) 
     == (state->filter_lists)[syscall_id].end()){
    (state->filter_lists)[syscall_id].push_back(filter);
    (state->filter_actions_lists)[syscall_id].push_back(filter_action);
  }
}

const char * action_names[3] = {"ALLOW", "MANGLE", "DROP"};

int delete_log_event(struct Queue * queue, int syscall_id){

  struct log_entry * entry;
  struct QNode * node;
  std::vector <TInt> entry_list;
  if(!queue || syscall_id < 0)
    return 0;

  char * type_str = (char *) malloc(TYPE_LEN);
  node = queue_get(queue, syscall_id);
  entry_list.push_back(node->id);
  node = node->next;
  while(node){
    entry = (struct log_entry *)node->item;

    int rv = get_event_field("type", type_str, entry->msg, entry->msg_len);
    if(rv < 0)
      printf("ERR (%s): '%s' field was not found in entry for syscall %d\n", __func__, "type", node->id);
    
    //printf("%s: type for %d is %s\n", __func__, node->id, type_str);

    if(!strcmp("SYSCALL",type_str))
      break;
    else
      entry_list.push_back(node->id);

    node = node->next;
  }
  free(type_str);
  
  int rv = 0;
  for (std::vector<TInt>::iterator it = entry_list.begin(); it != entry_list.end(); ++it){
    queue_remove(queue, *it);
    rv++;
  }

  return rv;
}

void filter(struct Queue * queue, State* state){


  /* Declare and initialize counters */
  std::map <TInt, std::vector<int> > csv_array;
  int events_removed = 0;
  int events_kept = 0;
  int filter_removal_counts[FAUST_NUM_FILTERS];
  int filter_confusion_matrix[FAUST_NUM_FILTERS][FAUST_NUM_FILTERS];
  for(int i=0; i< FAUST_NUM_FILTERS; i++){
    filter_removal_counts[i] = 0;
    for(int j=0; j<FAUST_NUM_FILTERS; j++){
      filter_confusion_matrix[i][j] = 0;
    }
  }

   for(int i = 0; i < state->syscall_ids.size(); i++){
    std::vector<int> temp_vector(10, 0); 
    csv_array[(state->syscall_ids[i])] = temp_vector; 
  }

  /* Iterate through filters lists
     Collect statistics for each syscall that is erased and by whom,
     then erase the syscall */
  // printf("------  size filter_lists %d ", state->filter_lists.size());
  // printf("------- size syscalls_ids %d ", state->syscall_ids.size());
  for (std::map<TInt, std::vector<filters_t> >::iterator syscall_it = state->filter_lists.begin(); syscall_it != state->filter_lists.end(); ++syscall_it){

    TInt syscall_id = syscall_it->first;
    std::vector<filters_t>& activated_filters = syscall_it->second;
    std::vector<filter_actions_t>& activated_filter_actions = state->filter_actions_lists[syscall_id];

    // all filters that dropped entry 
    std::vector<filters_t> drop_filters;

    // printf("\n ---EVENT--- \n");
    // printf("size activated_filters %d\n", activated_filters.size());
    // printf("size activated_filter_actions %d\n", activated_filter_actions.size());
    for(int i = 0; i < activated_filters.size(); i++){
      if(activated_filters[i] == FAUST_FILTER_UNSUPPORTED) {
        continue;
      }
      (csv_array[syscall_id])[(activated_filters[i])] = activated_filter_actions[i]; 
      // printf("activated_filter %d ", activated_filters[i]);
      // printf("activated_filter_action %d \n", activated_filter_actions[i]);
      if(activated_filter_actions[i] == DROP){
        // printf("activated_filter %d\n", activated_filters[i]);
        drop_filters.push_back(activated_filters[i]);
      } else {
        // printf("MANGELE??? %d\n", activated_filter_actions[i]);
      }
    }
     // break;

    //TODO, filter name code should be refactored
    for(std::vector<filters_t>::iterator af_it1 = drop_filters.begin();	af_it1 != drop_filters.end(); af_it1++){
	int active_fitler_1_index = find(active_filters.begin(), active_filters.end(),*af_it1) - active_filters.begin();
      for(std::vector<filters_t>::iterator af_it2 = drop_filters.begin(); af_it2 != drop_filters.end(); af_it2++){  
	int active_fitler_2_index = find(active_filters.begin(), active_filters.end(),*af_it2) - active_filters.begin();
	filter_confusion_matrix[active_fitler_1_index][active_fitler_2_index]++;
      }
      filter_removal_counts[active_fitler_1_index]++;
    }

    // if at least one filter dropped
    if(!drop_filters.empty()){
      // delete_log_event(state->queue,syscall_id);
      events_removed++;
    } else{
      events_kept++;
    }

    /*
    printf("%s: removed syscall %d.\n",
    	   __func__, syscall_id);
    */
  }

  if(events_removed) {
    printf("Total Events:\n");
    printf("\tKept:\t%d\n", events_kept);
    printf("\tUnhandled:\t%d\n", state->unsupported_events_removed);
    printf("\tHandled:\t%d\n", state->events_added - state->unsupported_events_removed);
    printf("\tFiltered\t%d\n\n", events_removed - state->unsupported_events_removed);

    std::ofstream approx_reduction_file("approx_reduction.txt",
                                      std::ofstream::app);
    approx_reduction_file
      << state->events_added - state->unsupported_events_removed << "\t"
      << events_removed - state->unsupported_events_removed << std::endl;
    approx_reduction_file.close();

    printf("Filter Performance:\n");
    for(int i = 0; i < FAUST_NUM_FILTERS; i++){
      if(active_filters[i] == FAUST_FILTER_UNSUPPORTED) {
        continue;
      }
      printf("%20s:\t", filter_to_name.find(active_filters[i])->second);
      
      printf("%d\t", filter_confusion_matrix[i][i]);
      printf("(%2.0f\%)\t", 100 * ((double)filter_confusion_matrix[i][i] / (events_removed - state->unsupported_events_removed)));

      printf("\n");
    }
    printf("\n");


    printf("Redundancy Matrix:\n");
    for(int i=0; i < FAUST_NUM_FILTERS; i++) {
      
      if(active_filters[i] == FAUST_FILTER_UNSUPPORTED) {
       	continue;
      }
      
      printf("%20s:\t", filter_to_name.find(active_filters[i])->second);
      for(int j=0; j < FAUST_NUM_FILTERS; j++) {
	if(active_filters[j] == FAUST_FILTER_UNSUPPORTED) {
	  continue;
	}
	
	printf("%3.0f%%  ",100 * ((double)filter_confusion_matrix[i][j] / (events_removed - state->unsupported_events_removed)));
      }
      printf("\n");
    }

    int entries_count  = 0;
    printf("WRITING TO FILE\n");
    std::string filename = "./mydecisions.csv";
    std::ofstream f_decisions(filename, std::ios_base::app);
    f_decisions << "ID,NUMBER,REDUNDANT_IO,LOG_GC,APPROX,INDUCTION,UNSUPPORTED,IBURST,TAG,DPRESERVE_FD,DPRESERVE_SD, NODEMERGE";
    f_decisions << std::endl;
    for (std::map<TInt, std::vector<int> >::iterator csv_entry = csv_array.begin(); csv_entry != csv_array.end(); ++csv_entry){
      TInt sys_id = csv_entry->first;
      int syscall_num = get_syscall_num(queue, sys_id);
      std::vector<int> filter_csv = csv_entry->second;
      // entries_count++;
      // printf("-----CSV entry----\n");
      f_decisions << sys_id << "," << syscall_num;
      for(int i=0; i<filter_csv.size(); i++){
        f_decisions << "," << filter_csv[i];
        // printf(",%d ", filter_csv[i]);
      }
      f_decisions << std::endl;
      // printf("\n");
    }
    f_decisions.close();
    printf("WRITING TO FILE DONE\n");
    printf("ENTRIES COUNT %d\n", entries_count );
  }
  state->filter_lists.clear();
  state->filter_actions_lists.clear();
  
}

#endif