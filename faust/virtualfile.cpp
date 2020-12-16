#include "virtualfile.h"

#include <cstdio>
#include <fstream>
#include <regex>
#include <string>
#include <vector>

/* match if virtual. instantiated by load_virtregexs */
static std::vector<std::regex> virtregexs;

bool load_virtregexs(const char *path) {
  std::ifstream f(path);
  if (!f) {
    std::perror(path);
    return false;
  }

  std::string line;
  while (std::getline(f, line)) {
    if (!line.empty() && line[0] != '#') {
      virtregexs.push_back(std::regex(line));
    }
  }

  f.close();
  return true;
}

bool is_virtual(const char *path) {
  for (const auto &regex : virtregexs) {
    if (std::regex_match(path, regex)) {
      return true;
    }
  }
  return false;
}
