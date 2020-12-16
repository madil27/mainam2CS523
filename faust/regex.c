#include "regex.h"
#include <regex> // requires C++11

// global namespace directives
using ::std::vector;
using ::std::string;
using ::std::map;
using ::std::unordered_set;
using ::std::regex;


/* Filenames */


// returns edit distance between s1 and s2
size_t compute_dist(const string& s1, const string& s2){
  size_t s1_len = s1.length();
  size_t s2_len = s2.length();

  if(s1_len < s2_len){
    return compute_dist(s2, s1);
  }else if(s2_len == 0){
    return s1_len;
  }

  size_t *prev_row = new size_t[s2_len+1];
  size_t *curr_row = new size_t[s2_len+1];

  size_t insertions, deletions, substitutions;

  for(int i = 0; i < s2_len+1; i++) prev_row[i] = i;

  for(int i = 0; i < s1_len; i++){
    curr_row[0] = i+1;

    for(int j = 0; j < s2_len; j++){
      insertions = prev_row[j+1] + 1;
      deletions = curr_row[j] + 1;
      substitutions = prev_row[j] + (s1[i] != s2[j]);
      curr_row[j+1] = std::min({insertions, deletions, substitutions});
    }

    std::swap(prev_row, curr_row);
  }

  size_t ret_val = prev_row[s2_len];

  delete [] prev_row;
  delete [] curr_row;

  return ret_val;
}


// returns regex for string s1 and s2
string compute_regex(const string& s1, const string& s2){
  
  // compute levenshtein alignment
  
  size_t s1_len = s1.length();
  size_t s2_len = s2.length();

  size_t memo[s1_len+1][s2_len+1];
  size_t insertions, deletions, substitutions;
  
  for(int j = 0; j < s2_len+1; j++) memo[0][j] = j;
  
  for(int i = 1; i < s1_len+1; i++){
    memo[i][0] = i;

    for(int j = 1; j < s2_len+1; j++){
      insertions = memo[i-1][j] + 1;
      deletions = memo[i][j-1] + 1;
      substitutions = memo[i-1][j-1] + (s1[i-1] != s2[j-1]);

      memo[i][j] = std::min({insertions, deletions, substitutions});
    }
  }

  string s1_path;
  string s2_path;

  int i = s1_len;
  int j = s2_len;

  while(!(i == 0 && j == 0)){

    int temp_cost;

    if(i == 0 || j == 0){
      temp_cost = -1;
    }else{
      if(s1[i-1] == s2[j-1]){
        temp_cost = memo[i-1][j-1];
      }else{
        temp_cost = memo[i-1][j-1] + 1;
      }
    }

    if(i == 0){
      s1_path += '?';
      j -= 1;
      s2_path += s2[j];
    }else if(j == 0){
      i -= 1;
      s1_path += s1[i];
      s2_path += '?';
    }else{
      if(memo[i][j] == temp_cost){
        i -= 1;
        s1_path += s1[i];
        j -= 1;
        s2_path += s2[j];
      }else if(memo[i][j] == memo[i-1][j] + 1){
        i -= 1;
        s1_path += s1[i];
        s2_path += '?';
      }else if(memo[i][j] == memo[i][j-1] + 1){
        s1_path += '?';
        j -= 1;
        s2_path += s2[j];
      }
    }
  }

  std::reverse(s1_path.begin(), s1_path.end());
  std::reverse(s2_path.begin(), s2_path.end());

  // compute regex from alignment

  string rgx;

  for(int i = 0; i < s1_path.length(); i++){
    if(s1_path[i] != s2_path[i]){
      if(rgx.empty() || rgx.back() != '*'){
        rgx += '*';
      }
    }else{
      rgx += s1_path[i];
    }
  }

  return rgx;
}


vector<unordered_set<string>> gen_groups(const vector<string>& paths){
  vector<unordered_set<string>> groups;

  size_t num_paths = paths.size();

  unordered_set<int> selected;

  for(int i = 0; i < num_paths; i++){
    const string& s1 = paths[i];

    if(selected.find(i) == selected.end()){
      unordered_set<string> group;
      group.insert(s1);
      selected.insert(i);
      
      for(int j = 0; j < num_paths; j++){
        const string& s2 = paths[j];
        if(i < j && selected.find(j) == selected.end()){

          size_t max_len = std::max(s1.length(), s2.length());
          float similarity = (max_len - compute_dist(s1, s2)) / (float) max_len;

          if(similarity >= SIM_THRESHOLD){
            group.insert(s2);
            selected.insert(j);
          }
        }
      }

      groups.push_back(std::move(group));

    }
  }

  return groups; 
}


vector<string> gen_regexes(const vector<unordered_set<string>>& groups){
  vector<string> regexes;

  for(const unordered_set<string>& group: groups){
    if(group.size() == 0){
      regexes.push_back("");
    }else if(group.size() == 1){
      regexes.push_back(*(group.begin()));
    }else if(group.size() > 1){
      auto group_it = group.begin();
      string s1 = *group_it;
      group_it++;
      string s2 = *group_it;
      group_it++;

      string rgx = compute_regex(s1, s2);

      while(group_it != group.end()){
        rgx = compute_regex(rgx, *group_it);
        group_it++;
      }

      regexes.push_back(std::move(rgx));
    }
  }

  return regexes;
}


map<string, string> gen_regex_map(const vector<unordered_set<string>>& groups){
  map<string, string> regex_map;

  for(const unordered_set<string>& group: groups){
    if(group.size() == 0){
      continue;
    }else if(group.size() == 1){
      string s = *(group.begin());
      regex_map[s] = s;
    }else if(group.size() > 1){
      auto group_it = group.begin();
      string s1 = *group_it;
      group_it++;
      string s2 = *group_it;
      group_it++;

      string rgx = compute_regex(s1, s2);

      while(group_it != group.end()){
        rgx = compute_regex(rgx, *group_it);
        group_it++;
      }
      
      for(group_it = group.begin(); group_it != group.end(); group_it++){
        regex_map[*group_it] = rgx;
      }
    }
  }

  return regex_map;
}


/*vector<string> paths_to_regexes(const vector<string>& paths){
  vector<unordered_set<string>> groups = gen_groups(paths);
  return gen_regexes(groups);
}*/


/* File paths */


size_t compute_dist_dir(const string& s1, const string& s2){

  // if depths different, return 
  size_t depth = std::count(s1.begin(), s1.end(), '/');
  if(depth != std::count(s2.begin(), s2.end(), '/')){
    return MAX_DIR_DEPTH+1;
  }

  int s1_pos = 0;
  int s2_pos = 0;

  int s1_len = s1.length();
  int s2_len = s2.length();

  size_t dist_dir = 0;

  char s1_curr_dir[256];
  char s2_curr_dir[256];

  size_t curr_dir_len = 0;

  while(s1_pos < s1_len || s2_pos < s2_len){
    if(s1[s1_pos] == '/' && s2[s2_pos] == '/'){
      // check equality between s1_curr_dir and s2_curr_dir

      s1_curr_dir[curr_dir_len] = '\0';
      s2_curr_dir[curr_dir_len] = '\0';

      if(strncmp(s1_curr_dir, s2_curr_dir, curr_dir_len) != 0){
        dist_dir++;
      }

      curr_dir_len = 0;
    }else if(s1[s1_pos] == '/' || s2[s2_pos] == '/'){
      // unequal dir sizes
      
      if(s1[s1_pos] == '/'){
        while(s2[s2_pos] != '/') s2_pos++;
      }

      if(s2[s2_pos] == '/'){
        while(s1[s1_pos] != '/') s1_pos++;
      }

      dist_dir++;
      curr_dir_len = 0;
    }else{
      s1_curr_dir[curr_dir_len] = s1[s1_pos];
      s2_curr_dir[curr_dir_len] = s2[s2_pos];
      
      curr_dir_len++;
    }

    s1_pos++;
    s2_pos++;
  }

  if(curr_dir_len > 0){
    s1_curr_dir[curr_dir_len] = '\0';
    s2_curr_dir[curr_dir_len] = '\0';
    
    dist_dir += s1[s1_pos] != s2[s2_pos]
             || strncmp(s1_curr_dir, s2_curr_dir, curr_dir_len) != 0;
  }
 
  return dist_dir; 
}


string compute_regex_dir(const string& s1, const string& s2){
 
  // if depths different, return 
  size_t depth = std::count(s1.begin(), s1.end(), '/');
  if(depth != std::count(s2.begin(), s2.end(), '/')){
    return {};
  }

  int s1_pos = 0;
  int s2_pos = 0;

  int s1_len = s1.length();
  int s2_len = s2.length();

  size_t dist_dir = 0;

  string rgx;

  char s1_curr_dir[256];
  char s2_curr_dir[256];

  size_t curr_dir_len = 0;

  while(s1_pos < s1_len || s2_pos < s2_len){
    if(s1[s1_pos] == '/' && s2[s2_pos] == '/'){
      // check equality between s1_curr_dir and s2_curr_dir

      s1_curr_dir[curr_dir_len] = '\0';
      s2_curr_dir[curr_dir_len] = '\0';

      if(strncmp(s1_curr_dir, s2_curr_dir, curr_dir_len) != 0){
        rgx += "*/";
      }else{
        rgx.append(s1_curr_dir, curr_dir_len);
        rgx += '/';
      }

      curr_dir_len = 0;
    }else if(s1[s1_pos] == '/' || s2[s2_pos] == '/'){
      // unequal dir sizes
      
      if(s1[s1_pos] == '/'){
        while(s2[s2_pos] != '/') s2_pos++;
      }

      if(s2[s2_pos] == '/'){
        while(s1[s1_pos] != '/') s1_pos++;
      }

      rgx += "*/";

      curr_dir_len = 0;
    }else{
      s1_curr_dir[curr_dir_len] = s1[s1_pos];
      s2_curr_dir[curr_dir_len] = s2[s2_pos];
      
      curr_dir_len++;
    }

    s1_pos++;
    s2_pos++;
  }

  if(curr_dir_len > 0){
    s1_curr_dir[curr_dir_len] = '\0';
    s2_curr_dir[curr_dir_len] = '\0';
    
    if(s1[s1_pos] != s2[s2_pos]
       || strncmp(s1_curr_dir, s2_curr_dir, curr_dir_len) != 0){  
      rgx += '*';
    }else{
      rgx.append(s1_curr_dir, curr_dir_len);
    }
  }
 
  return rgx; 
}


vector<unordered_set<string>> gen_groups_dir(const vector<string>& paths){
  
  vector<unordered_set<string>> groups;

  size_t num_paths = paths.size();

  unordered_set<int> selected;

  for(int i = 0; i < num_paths; i++){
    const string& s1 = paths[i];

    if(selected.find(i) == selected.end()){
      unordered_set<string> group;
      group.insert(s1);
      selected.insert(i);
      
      for(int j = 0; j < num_paths; j++){
        const string& s2 = paths[j];
        if(i < j && selected.find(j) == selected.end()){

          size_t max_len = std::max(s1.length(), s2.length());
          float dist = compute_dist_dir(s1, s2);

          if(dist <= 1){
            group.insert(s2);
            selected.insert(j);
          }
        }
      }

      groups.push_back(std::move(group));

    }
  }

  return groups; 
}


vector<string> gen_regexes_dir(const vector<unordered_set<string>>& groups){
  
  vector<string> regexes;

  for(const unordered_set<string>& group: groups){
    if(group.size() == 0){
      regexes.push_back("");
    }else if(group.size() == 1){
      regexes.push_back(*(group.begin()));
    }else if(group.size() > 1){
      auto group_it = group.begin();
      string s1 = *group_it;
      group_it++;
      string s2 = *group_it;
      group_it++;

      string rgx = compute_regex_dir(s1, s2);

      while(group_it != group.end()){
        rgx = compute_regex_dir(rgx, *group_it);
        group_it++;
      }

      regexes.push_back(std::move(rgx));
    }
  }

  return regexes;
}


map<string, string> gen_regex_map_dir(const vector<unordered_set<string>>& groups){
  
  map<string, string> regex_map;

  for(const unordered_set<string>& group: groups){
    if(group.size() == 0){
      continue;
    }else if(group.size() == 1){
      string s = *(group.begin());
      regex_map[s] = s;
    }else if(group.size() > 1){
      auto group_it = group.begin();
      string s1 = *group_it;
      group_it++;
      string s2 = *group_it;
      group_it++;

      string rgx = compute_regex_dir(s1, s2);

      while(group_it != group.end()){
        rgx = compute_regex_dir(rgx, *group_it);
        group_it++;
      }

      for(group_it = group.begin(); group_it != group.end(); group_it++){
        regex_map[*group_it] = rgx;
      }
    }
  }

  return regex_map;
}


/* Compiling regexes */


/*map<string, regex> compile_regexes(vector<string> regexes){ 
  map<string, regex> compiled_regexes;
  
  for(const string& r: regexes){
    // TODO: generate cregexes from regexes
  }

  return compiled_regexes;
}*/


/*map<string, string> gen_regex_map(const vector<string>& paths, const vector<string>& regexes){
  map<string, regex> compiled_regexes = compile_regexes(regexes);
  map<string, string> regex_map;

  for(const string& path: paths){
    for(const auto& cr_kv: compiled_regexes){
      string sregex = cr_kv.first;
      regex cregex = cr_kv.second;

      if(regex_match(path, cregex)){
        regex_map[path] = sregex;
        break;
      }
    }
  }

  return regex_map;
}*/
