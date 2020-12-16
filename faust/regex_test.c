#include "regex.h"
#include <assert.h>
#include <iostream>

int main(void){
  std::vector<std::string> paths = {"helloworld", "helloworle", "heloworld", "oops", "oop", "oopse", "nope"};
  
  // printf("%zu\n", compute_dist(paths[0], paths[1]));
  // std::cout << compute_regex(paths[0], paths[1]) << std::endl;
  // assert(compute_dist(paths[0], paths[1]) == 0);

  std::vector<std::string> cwds = {"/he/wh/wwe", "/he/wi/wwe", "/he/wii/wwe", "/var/log/audit", "/etc/audisp", "/etc/auditd"};

  // printf("%zu\n", compute_dist_dir(cwds[0], cwds[1]));
  // std::cout << compute_regex_dir(cwds[0], cwds[1]) << std::endl;

  std::vector<std::unordered_set<std::string> > cwd_groups = gen_groups_dir(cwds);

  for(const auto& group: cwd_groups){
    for(const auto&elem: group){
      std::cout << elem << " ";
    }
    std::cout << std::endl;
  }

  std::cout << std::endl;

  std::vector<std::string> cwd_regexes = gen_regexes_dir(cwd_groups);
  std::map<std::string, std::string> cwd_regex_map = gen_regex_map_dir(cwd_groups);

  for(const auto& prm_it: cwd_regex_map){
    std::cout << prm_it.first << " " << prm_it.second << std::endl;
    // std::cout << prm_it << std::endl;
  }

}
