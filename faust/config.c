#include "config.h"
#define KEYWORD_NUM 8

static const kw_pair keywords[] =
  {{"input_method", 0}, {"output_method", 1}, {"input_folder", 2},
   {"output_logfile", 3}, {"output_address", 4}, {"output_port", 5},
   {"filter_decisions_file", 6}, {"sock_path", 7}};

/* Initialize configuration to default */
void init_config(struct faust_config * config) {
  config->input_method = "unix";
  config->output_method = "local";
  config->input_folder = "./input";
  config->output_logfile = "./localLog.txt";
  config->output_address = "127.0.0.1";
  config->output_port = "8080";
  config->filter_decisions_file = "./decisions.txt";
  config->sock_path = "/var/run/audispd_events";
}

/* Load configuration from faust.conf */
int load_config(struct faust_config * config) {
  FILE * f;
  char * buffer = NULL;
  size_t buffer_size = 64;
  ssize_t read;

  init_config(config);

  /* open the file */
	f = fopen("./faust.conf", "r");
  if (f == NULL) {
		printf("Configuration file not found.\n");
		return 1;
	}

  while ((read = getline(&buffer, &buffer_size, f)) != -1) {
    if (read < 1 || buffer[0] == '#') continue;
    char * key = strtok(buffer, "=");
    char * val = strtok(NULL, "=");

    for (int i = 0; i < KEYWORD_NUM; i++) {
      if (strncmp(key, keywords[i].name, strlen(keywords[i].name)) == 0) {
        kw_parser(config, keywords[i].idx, val);
        break;
      }
    }
  }
  free(buffer);
  fclose(f);

  return 0;
}

void kw_parser(struct faust_config * config, int kw_idx, char * val) {
  // convert char* to string and escape "\n\r"
  std::string str = std::string(val);
  while (str.back() == '\n' || str.back() == '\r')
    str.pop_back();

  switch (kw_idx) {
    case 0:
      config->input_method = str;
      return;
    case 1:
      config->output_method = str;
      return;
    case 2:
      config->input_folder = str;
      return;
    case 3:
      config->output_logfile = str;
      return;
    case 4:
      config->output_address = str;
      return;
    case 5:
      config->output_port = str;
      return;
    case 6:
      config->filter_decisions_file = str;
      return;
    case 7:
      config->sock_path = str;
      return;
    default:;
  }
}
