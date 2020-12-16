#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <string>
#include <fstream>
#include <iostream>
#include <iomanip>
#include "listener.h"

#define SOCK_PATH "log_replay"

struct timespec start_ts;
struct timespec log_start_ts;

void get_time(struct timespec *ts){
  timespec_get(ts, TIME_UTC);
}

void convert(double time, struct timespec* ts){
  ts->tv_sec = (int) time;
  double remainder = time - ts->tv_sec;
  ts->tv_nsec = (int) (remainder * 1000000000.0);
}

double convert(struct timespec* ts){
  return ts->tv_sec + (ts->tv_nsec / 1000000000.0);
}

double get_timestamp(std::string &line){
  double timestamp;
  char msg_str[32];
  get_event_field("msg", msg_str,
      const_cast<char*>(line.c_str()), line.length());

  char* colon = strchr(msg_str, ':');
  *colon = '\0';
  sscanf(msg_str + 6, "%lf", &timestamp);

  return timestamp;
}

// c = a - b
struct timespec operator-(struct timespec &a, struct timespec &b){
  struct timespec c;
  c.tv_sec = a.tv_sec - b.tv_sec;
  c.tv_nsec = a.tv_nsec - b.tv_nsec;
  if(c.tv_nsec < 0){
    c.tv_sec -= 1;
    c.tv_nsec += 1000000000;
  }
  return c;
}

void replay(std::ifstream &f, int s){
  for (std::string line; getline(f, line);) {
    double timestamp = get_timestamp(line);

    struct timespec log_ts;
    convert(timestamp, &log_ts);

    if(log_start_ts.tv_sec == 0){ // uninit. log start time
      log_start_ts = log_ts;
    }
    
    struct timespec curr_ts;
    get_time(&curr_ts);

    struct timespec elapsed_ts = curr_ts - start_ts;
    struct timespec log_elapsed_ts = log_ts - log_start_ts;

    // wait if log time ahead

    if(convert(&elapsed_ts) < convert(&log_elapsed_ts)){
      struct timespec diff = log_elapsed_ts - elapsed_ts;
      nanosleep(&diff, NULL);
    }
    
    // send log

    if (send(s, line.c_str(), line.length(), 0) < 0) {
      perror("send");
    }

    if (send(s, "\n", 1, 0) < 0) {
      perror("send");
    }
  }
}

int main(int argc, char *argv[]){
  char *filename;

  if(argc > 1){
    filename = argv[1];
  }else{
    filename = (char *) "input/audit.log";
  }
  printf("here\n");
  timespec_get(&start_ts, TIME_UTC);
  printf("here2\n");
  // init. unix socket server
  // http://beej.us/guide/bgipc/html/multi/unixsock.html

  int s, s2;
  socklen_t t, len;
  struct sockaddr_un local, remote;
  char str[100];

  if((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1){
    perror("socket");
      exit(1);
  }
  printf("here3\n");

  local.sun_family = AF_UNIX;
  strcpy(local.sun_path, SOCK_PATH);
  unlink(local.sun_path);
  len = strlen(local.sun_path) + sizeof(local.sun_family);
  printf("here4\n");
  if (bind(s, (struct sockaddr *)&local, len) == -1) {
    perror("bind");
      exit(1);
  }
  printf("here5\n");

  if(listen(s, 5) == -1){
    perror("listen");
      exit(1);
  }
  printf("here6\n");

  if((s2 = accept(s, (struct sockaddr *)&remote, &t)) == -1){
    printf("hereerror\n");
    perror("accept");
      exit(1);
  }
  printf("here7\n");

  std::ifstream f(filename);
  if(!f.is_open()) return 1;

  printf("here8\n");
  printf("beggining\n");
  replay(f, s2);
  printf("beggining\n");

  close(s2);
  close(s);

  return 0;
}
