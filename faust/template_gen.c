#include "nodemerge.c"
#include "config.c"
#include <dirent.h>

using namespace std;
faust_config config;

int main(void) {
  /* load configuration file */
  cout << "Generating Node Merge Templates" << endl;
  load_config(&config);

  DIR *dir;
  struct dirent *ent;
  if ((dir = opendir (config.input_folder.c_str())) == NULL) {
    /* could not open directory */
    perror ("Configuration Error");
    return EXIT_FAILURE;
  }

  // printf("dir %s\n", config.input_folder.c_str());

  // printf("here\n");

  /* build FAPs */
  Fap fap;
  int insert_count = 0;

  int counter = 0;
  /* get all the files and directories within directory */
  while ((ent = readdir (dir)) != NULL) {
    counter = 0;
    std::string path(config.input_folder + ent->d_name);

    /* check if file is valid */
    if (strlen(ent->d_name) < 3) {
      // printf("name %s\n", ent->d_name);
      continue;
    }

    /* read files */
    cout << "READING FILE..." << endl;
    ifstream f(path);
    if(!f.is_open()) continue;
    for (string line; getline(f, line);) {
      // cout << "line " << line  << endl;
      if(1 || counter < 100000){
        fap.insert(line);
        insert_count++;
      }
      else{
        break;
      }
      counter++;
    }

    f.close();
  }

  cout << "INSERT COUNT " << insert_count << endl;

  // cout << "done inserting" << endl;

  fap.filter();
  // cout << "no filter" << endl;
  // cout << " ---------- PRINTING FAP ---------- " << endl;
  // fap.printFap();
  vector<vector<string>> ret;
  ret = fap.getSortedFap();
  Fptree tree(fap.getSortedFap());
  // cout << " ---------- GENERATING CFAP ---------- " << endl;
  tree.generateCFap();
  // std::ifstream templates("templates.txt");

  // vector<vector<string>> node_templates;

  // for (std::string line; getline(templates, line);) {
  //   // cout << line << endl;
  //   std::istringstream ss(line);
  //   std::string token;

  //   vector<string> temp_vector;
  //   while(std::getline(ss, token, ' ')) {
  //     temp_vector.push_back(token);
  //   }

  //   sort(temp_vector.begin(), temp_vector.end());

  //   if(temp_vector.size() > 1){
  //     node_templates.push_back(temp_vector);
  //   }
  // }
  cout << "Templates wrote to file successfully" << endl;

  // cout << " ---------- PRINTING NODE TEMPLATES ----------" << endl;
  // cout << "SIZE: " << node_templates.size() << endl;
  // for (int i=0;i<10;i++){
  //   for (int j=0; j<node_templates[i].size();j++){
  //     cout << node_templates[i][j] << " -- ";
  //   }
  //   cout << endl;
  //   cout << endl;
  // }

  // unordered_map<int, unordered_map<string, int>> myfiles =  fap2.files;
  // int hit_count = 0;
  // int miss_count = 0;
  // int hit;

  // for (auto it = myfiles.begin(); it != myfiles.end(); it++) {
  //   // cout<<"PID: "<<it->first<< endl;
  //   vector<string> temp;
  //   for (auto it2 = it->second.begin(); it2 != it->second.end(); it2++){
  //     temp.push_back(it2->first);
  //   }

  //   sort(temp.begin() , temp.end());
  //   hit = 0;

  //   for (int i=0;i<node_templates.size();i++){
  //       // bool result = std::equal(node_templates.begin(), node_templates.end(), node_templates[i].begin());
  //       bool result = temp == node_templates[i];

  //       if(result){
  //         hit = 1;
  //         hit_count++;
  //         // cout << "TEMPLATE " << i << " MATCHED!" << endl;
  //         break;
  //       }
  //     }

  //     if(!hit){
  //       miss_count++;
  //     }
  // }

  // cout << "HIT COUNT " << hit_count << endl;
  // cout << "MISS COUNT " << miss_count << endl;  


  return 0;
}
