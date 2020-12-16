#ifndef NODE_H
#define NODE_H

#include <bits/stdc++.h>

using namespace std;

#define TIMESTAMP_LENGTH 10

class Fap{
private:
  int timestamp;
  unordered_map<string, int> writeTS; // latest time stamp for a file being written
public:
  unordered_map<int, unordered_map<string, int>> files;
  unordered_map<int, vector<int>> pid_map;
  Fap();
  /* Getters and Setters */
  void printFap();
  int getTimestamp();
  void setTimestamp(int timestamp);

  /* Functionalities */
  int insert(string log, int sys_id);
  void filter();
};

Fap::Fap() {
  timestamp = 0;
}

void Fap::printFap() {
  cout<<"timestamp: "<<timestamp<<"\n\n";

  cout<<"writeTS size: "<<writeTS.size()<<endl;
  for (auto it = writeTS.begin(); it != writeTS.end(); it++)
    cout<<it->first<<" "<<it->second<<endl;
  cout<<endl;

  cout<<"files size: "<<files.size()<<endl;
  for (auto it = files.begin(); it != files.end(); it++) {
    cout<<"PID: "<<it->first<<": ";
    for (auto it2 = it->second.begin(); it2 != it->second.end(); it2++)
      cout<<"("<<it2->first<<", "<<it2->second<<") ";
    cout<<endl;
  }

  cout<<"End print."<<endl;
}

/**
  Public method for getting / setting new timestamp
*/
int Fap::getTimestamp() { return timestamp; }
void Fap::setTimestamp(int timestamp) {
  timestamp = timestamp;
}

/**
  Insert one log to Fap
  @return 0 if insert success, 0 otherwise
*/
int Fap::insert(string log, int sys_id) {
  // cout << log << endl;
  int idx = 0;

  /* get timestamp */
  int ts = 0;
  idx = log.find("audit(");
  if ((size_t)idx == string::npos)
    return 1;
  else
    idx += 6; // length of "audit(" = 6
  // cout  << "here1" << endl;
  ts = stoi(log.substr(idx, TIMESTAMP_LENGTH));
  if (ts && timestamp == 0)
      timestamp = ts;

  /* get syscall number */
  int syscall = 0;
  idx = log.find("syscall=");
  // cout << idx << endl;
  if ((size_t)idx == string::npos)
    return 1;
  else
    idx += 8;  // length of "syscall=" = 8
  for (; isdigit(log[idx]); idx++) {
    syscall = syscall * 10 + log[idx] - '0';
  }
  // cout  << "here2" << endl;
  /* get process ID */
  int pid = 0;
  idx = log.find(" pid=", idx);
  if ((size_t)idx == string::npos)
    return 1;
  else
    idx += 5;  // length of " pid=" = 4
  for (; isdigit(log[idx]); idx++) {
    pid = pid * 10 + log[idx] - '0';
  }
  // cout  << "here3" << endl;
  // cout << "IN INSERT MAKING AN INSERT 0" << endl;
  /* get file name */
  string file;
  idx = log.find("exe=", idx);
  if ((size_t)idx == string::npos){
    // cout << "RETURN" << endl;
    return 1;
  }
  else
    idx += 5;  // length of "exe="" = 5

  
  int start = idx;
  // cout  << "here4" << endl;
  for (; log[idx] != '\"'; idx++);
  // cout  << "here5" << endl;
  file = log.substr(start, idx-start);
  
  // cout << file << endl;
  // cout << "IN INSERT MAKING AN INSERT" << endl;
  /* check for read only file */
  if (syscall != 1) {
    if (writeTS.find(file) != writeTS.end() && writeTS[file] >= timestamp)
      return 1;
    files[pid][file] += 1;
    pid_map[pid].push_back(sys_id);
  }
  else {
    writeTS[file] = ts;
    return 1;
  }

  return 0;
}

/**
  Process logs after insertion, filter read only files for each pid
*/
void Fap::filter() {
  for (auto p = files.begin(); p != files.end();) {
    for (auto log = p->second.begin(); log != p->second.end();) {
      string f = log->first;
      if (writeTS.find(f) != writeTS.end() && writeTS[f] >= timestamp)
        log = p->second.erase(log);
      else {
        log++;
      }
    }

    if (p->second.empty())
      p = files.erase(p);
    else
      p++;
  }
}

void node_merge(struct Queue * queue){
  cout << " --------- NODE MERGE --------- " << endl;
  Fap fap;

  cout << "Inserting in FAP" << endl;

  int counter = 0;
  for(auto syscall_id: state->syscall_ids){
    QNode* qnode = queue_get(queue, syscall_id);
    struct log_entry* entry = (struct log_entry *) qnode->item;
    std::string input_entry(entry->msg);
    fap.insert(input_entry, syscall_id);
    counter++;
  }

  cout << "COUNTER: " << counter << endl;

  cout << "Filtering FAP" << endl;
  fap.filter();


  cout << "Reading templates.." << endl;

  std::ifstream templates("templates.txt");

  vector<vector<string>> node_templates;

  for (std::string line; getline(templates, line);) {
    // cout << line << endl;
    std::istringstream ss(line);
    std::string token;

    vector<string> temp_vector;
    while(std::getline(ss, token, ' ')) {
      temp_vector.push_back(token);
    }

    sort(temp_vector.begin(), temp_vector.end());

    if(temp_vector.size() > 1){
      node_templates.push_back(temp_vector);
    }
  }
  cout << "Templates read from file successfully" << endl;

  std::sort(node_templates.begin(), node_templates.end(), [](const vector<string> & a, const vector<string> & b){ return a.size() > b.size(); });

  // cout << "Templates sorted successfully" << endl;
  // cout << "node_templates[0].size()" << node_templates[0].size() << endl;
  // cout << "node_templates[1].size()" << node_templates[1].size() << endl;
  // cout << "node_templates[2].size()" << node_templates[2].size() << endl;


  //  cout << " ---------- PRINTING NODE TEMPLATES ----------" << endl;
  // cout << "SIZE: " << node_templates.size() << endl;
  // for (int i=0;i<10;i++){
  //   for (int j=0; j<node_templates[i].size();j++){
  //     cout << node_templates[i][j] << " -- ";
  //   }
  //   cout << endl;
  //   cout << endl;
  // }

  unordered_map<int, unordered_map<string, int>> myfiles =  fap.files;
  int hit_count = 0;
  int miss_count = 0;
  int hit;

  for (auto it = myfiles.begin(); it != myfiles.end(); it++) {
    vector<string> temp;
    for (auto it2 = it->second.begin(); it2 != it->second.end(); it2++){
      temp.push_back(it2->first);
    }

    sort(temp.begin() , temp.end());
    hit = 0;

    for (int i=0;i<node_templates.size();i++){
        // bool result = std::equal(temp.begin(), temp.end(), node_templates[i].begin());
        // bool result = temp == node_templates[i];
        bool result = std::includes(node_templates[i].begin(), node_templates[i].end(), temp.begin(), temp.end());

        if(result){
          // cout << "HIT!" << endl;
          vector<int> sys_ids = fap.pid_map[it->first];

          // code for finding the execve

          // QNode* tnode = queue_get(queue, sys_ids[0]);
          // bool execve_found = 0;
          // while(tnode && !execve_found){
          //   // check if same pid
          //   if(state->process_id_map[tnode->id] == it->first){
          //     // check if execve
          //     // int sys_no = get_syscall_num(queue, tnode->id);
          //     int sys_no = 59;
          //     if(sys_no == 59){
          //       // mangle
          //       // filter mangle
          //       // cout << "EXECVE FOUNDDD!" << endl;
          //       execve_found = 1;
          //     } 
          //   }
          //   tnode = tnode->prev;    
          // }

          int diff = node_templates[i].size() - temp.size();
          int loop_len = sys_ids.size() - diff;
          for(int m=0;m<loop_len;m++){
            filter_event(sys_ids[m], FAUST_FILTER_NODEMERGE, DROP, state);
            // cout << sys_ids[m] << " -- "; 
          }
          // cout << endl;
          hit = 1;
          hit_count++;
          // cout << "TEMPLATE " << i << " MATCHED!" << endl;
          break;
        }
      }

      if(!hit){
        miss_count++;
      }
  }

  cout << "HIT COUNT " << hit_count << endl;
  cout << "MISS COUNT " << miss_count << endl;  

}

#endif
