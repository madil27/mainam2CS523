#ifndef REGEX_H
#define REGEX_H

#include <vector>
#include <map>
#include <unordered_set>
#include <string>
#include <cstring>

#define SIM_THRESHOLD .70
#define THRESHOLD_DIR 1
#define MAX_DIR_DEPTH 4096
#define LENGTH_THRESHOLD 10

std::vector<std::unordered_set<std::string> > gen_groups(const std::vector<std::string>& paths);
std::vector<std::string> gen_regexes(const std::vector<std::unordered_set<std::string> >& groups);
std::map<std::string, std::string> gen_regex_map(const std::vector<std::unordered_set<std::string> >& groups);

std::vector<std::unordered_set<std::string> > gen_groups_dir(const std::vector<std::string>& paths);
std::vector<std::string> gen_regexes_dir(const std::vector<std::unordered_set<std::string> >& groups);
std::map<std::string, std::string> gen_regex_map_dir(const std::vector<std::unordered_set<std::string> >& groups);

/* For Testing */

size_t compute_dist(const std::string& s1, const std::string& s2);
std::string compute_regex(const std::string& s1, const std::string& s2);

size_t compute_dist_dir(const std::string& s1, const std::string& s2);
std::string compute_regex_dir(const std::string& s1, const std::string& s2);

#endif /* REGEX_H */
