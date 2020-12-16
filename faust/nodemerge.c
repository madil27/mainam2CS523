#include "nodemerge.h"

#define TIMESTAMP_LENGTH 10

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
int Fap::insert(string log) {
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

vector<vector<string>> Fap::getSortedFap(){
  unordered_map<string, int> ctr;
  vector<vector<string>> ret;

  for (auto p = files.begin(); p != files.end(); p++) {
    for (auto log = p->second.begin(); log != p->second.end(); log++) {
      ctr[log->first] += log->second;
    }
  }

  for (auto p = files.begin(); p != files.end(); p++) {
    vector<pair<int,string>> row;
    for (auto log = p->second.begin(); log != p->second.end(); log++) {
      row.push_back(make_pair(ctr[log->first], log->first));
    }

    sort(row.begin(), row.end());

    vector<string> sortedRow;
    for (auto& r : row) {
      sortedRow.push_back(r.second);
    }
    ret.push_back(sortedRow);
  }

  // cout << " ---------- PRINTING SORTED FAP ---------- " << endl;
  // for (int i = 0; i < ret.size(); i++) {
  //   for(int j = 0; j < ret[i].size(); j++) {
  //     cout<<ret[i][j]<<" -- ";
  //   }
  //   cout<<endl;
  // }

  return ret;
}

FptreeNode::FptreeNode(string filename) {
  fileId = filename;
  counter = 1;
}

Fptree::Fptree(vector<vector<string>> fap) {
  root = new FptreeNode("");
  root->counter = 1000;
  // cout << " ---------- PRINTING FP TREE ---------- " << endl;
  for (auto& row : fap) {
    for (auto& it: root->children) 
      {
        // cout<<it->fileId<<" "<<it->counter<<" || ";
      }
    // cout<<endl;
    insertRow(row, 0, root);
  }
}

int Fptree::childExist(FptreeNode* node, string& filename) {
  for (int i = 0; i < node->children.size(); i++) {
    if (node->children[i]->fileId == filename)
      return i;
  }

  return -1;
}

void Fptree::insertRow(vector<string>& row, int idx, FptreeNode* cur) {
  if (idx == row.size()) return;

  FptreeNode* child;
  string filename = row[idx];
  int childIdx = childExist(cur, filename);


  if (childIdx >= 0) {
    child = cur->children[childIdx];
    child->counter++;
  }
  else {
    child = new FptreeNode(filename);
    cur->children.push_back(child);
  }

  insertRow(row, idx+1, child);
}

void Fptree::generateCFapHelper(FptreeNode* cur, vector<string>& cfap, vector<vector<string>>& ret) {
  // cout << "counter " <<  cur->counter << endl;
  if(cur->counter < 2){
    // cout << "CANCELLING" << endl;
    return;
  }
  if (cur->children.empty()) {
    // cout << "CFAP SIZE: "  << cfap.size() << endl;
    ret.push_back(cfap);
    // cout << "INSERTING IN CFAP" << endl;
    return;
  }

  for (auto& child : cur->children) {
    cfap.push_back(child->fileId);
    generateCFapHelper(child, cfap, ret);
    cfap.pop_back();
  }
}

vector<vector<string>> Fptree::generateCFap() {
  vector<vector<string>> ret;
  vector<string> cfap;

  generateCFapHelper(root, cfap, ret);
  
  std::ofstream templates_file("templates.txt",
                                      std::ofstream::trunc);

  // cout << " ---------- PRINTING CFAP ---------- " << endl;
  for (int i = 0; i < ret.size(); i++) {
    // cout << "T =" << " ";
    for (int j = 0; j < ret[i].size(); j++) {
      // cout<<ret[i][j]<<" -- ";
      templates_file <<ret[i][j]<< " ";
    }
    templates_file << std::endl;
    // cout<<"\n";
  }

  templates_file.close();

  // for (int i = 0; i < cfap.size(); i++) {
  //   for (int j = 0; j < cfap[i].size(); j++) {
  //     cout<<cfap[i][j]<<" ";
  //   }
  //   cout<<"\n";
  // }
  return ret;
}
