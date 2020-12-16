#ifndef CONFIG_H
#define CONFIG_H

#include <iostream>
#include <string>
#include <string.h>

struct faust_config
{
  std::string input_method;
  std::string output_method;
  std::string input_folder;
  std::string output_logfile;
  std::string output_address;
  std::string output_port;
  std::string filter_decisions_file;
  std::string sock_path;
};

struct kw_pair
{
  const char * name;
  const int idx;
};

void init_config(struct faust_config * config);
int load_config(struct faust_config * config);
void kw_parser(struct faust_config * config, int kw_idx, char * val);

#endif
