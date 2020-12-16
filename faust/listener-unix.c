#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <bits/stdc++.h>
#include <algorithm>

#include "listener.h"

/*contains structs and enums*/
#include "structures.h"

/* bloom filter */
#include "bloom.h"

/* configuration file */
#include "config.h"

/* generic queue data structure */
#include "queue.h"

/* Graph datastructure for causality analysis */
#include "Snap.h"
#include "event_analysis.h"

/* approximation filter */
#include "approx.h"

/* induction filter */
#include "induction.h"

/* tag filter */
#include "tag.h"

/* filter decision output routines (to csv) */
#include "filter_decisions.h"

/* virtual file decisions (must initialize in main) */
#include "virtualfile.h"

/* dependency preserving reductions filters */
#include "dpreserve.h"

/* node merge filters */
#include "node.h"

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
/*               CONFIGURATION SETTINGS                */
/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

//#define NULL_LOGGER                /* Uncomment if you'd like the logger to receive messages
           /* from auditd but take no other action */

#define EPOCH_MAX_TIME 30          /* Set epoch time to 5 minutes */
#define EPOCH_MAX_QUEUE 0          /* Feature not yet support */

#define EVENT_CACHE_MAX 100        /* Max cache size in bytes */

#define BUFFER_SIZE 65536

#define CHUNK_SIZE 100000     /* for reading from files (curr. inf)*/

typedef struct bloom bloom;

faust_config config;

static pthread_t flush_thread_id = -1;
static struct Queue** flush_workqueue;
pthread_mutex_t flush_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t flush_cond = PTHREAD_COND_INITIALIZER;
sig_atomic_t shouldExit = 0;

struct timespec start_ts;

double convert(struct timespec&& ts){
  return ts.tv_sec + (ts.tv_nsec / 1000000000.0);
}

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

void exit_cleanup() {
  pthread_mutex_lock(&flush_mutex);
  shouldExit = 1;
  pthread_mutex_unlock(&flush_mutex);
  pthread_cond_signal(&flush_cond);
  pthread_join(flush_thread_id, NULL);
  destroyQueue(*flush_workqueue);
  free(flush_workqueue);
}

void write_tcp(PNEANet &ProvGraph, struct Queue * queue) {
  int socket_fd, conn_fd;
  struct sockaddr_in address;
  int port = std::stoi(config.output_port);

  // creating socket file descriptor
  if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    perror("Could not create a socket");
    exit(EXIT_FAILURE);
  }
  bzero(&address, sizeof(address));

  address.sin_family = AF_INET;
  address.sin_addr.s_addr = inet_addr(&config.output_address[0]);
  address.sin_port = htons(port);

  // connect the client socket to server socket
  if (connect(socket_fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
    printf("connection with the server failed...\n");
    exit(EXIT_FAILURE);
  }
  else
    printf("connected to the server..\n");

  // send logs via TCP
  int event_id;
  log_entry * entry;

  while ( (event_id = dequeue(queue, (void **)&entry) ) ){
    char * msg = entry->msg;
    send(socket_fd, msg, strlen(msg), 0);

    free(entry->msg);
    free(entry);

    // Let's see if Clr does the trick...
    delete_graph_event(ProvGraph, event_id);
  }

  close(socket_fd);
}

void write_local(PNEANet &ProvGraph, struct Queue * queue) {
  // Open file stream
  FILE * fp;
  char* filename = &config.output_logfile[0];

  if ((fp = fopen(filename, "w+") ) == NULL) {
     printf("Error: can't create file");
     return;
  }

  int event_id;
  log_entry * entry;

  while ( (event_id = dequeue(queue, (void **)&entry) ) ){
    fprintf(fp, "%s\n", (char *)entry->msg);
    // printf("%s: FLUSH#%d <%s>\n",__func__, event_id, entry->msg);

    free(entry->msg);
    free(entry);

    // Let's see if Clr does the trick...
    delete_graph_event(ProvGraph, event_id);
  }

  fflush(fp);

  fclose(fp);
}

void* flush_epoch(void*) {
  /* Approximation Filter */
  for (;;) {
    pthread_mutex_lock(&flush_mutex);

    while ((*flush_workqueue)->size == 0) {

      if (shouldExit) {
        // printf ("Worker thread exiting\n");
        pthread_mutex_unlock(&flush_mutex);
        return NULL;
      }

      pthread_cond_wait(&flush_cond, &flush_mutex);
    }

    State* state;
    dequeue(*flush_workqueue, (void**)&state);
    pthread_mutex_unlock(&flush_mutex);

    PNEANet* p_ProvGraph = (state->ProvGraph);
    PNEANet ProvGraph = *p_ProvGraph;
    struct Queue* queue = state->queue;

    // init maps
    init_listener_state(state);

    struct timespec before_ts;
    timespec_get(&before_ts, TIME_UTC);

    if(is_active(FAUST_FILTER_APPROX)){
      approx_filter(ProvGraph, queue);
    }

    struct timespec after_ts;
    timespec_get(&after_ts, TIME_UTC);

    if(is_active(FAUST_FILTER_INDUCTION)){
      induction_filter(ProvGraph, queue);
    }

    if(is_active(FAUST_FILTER_TAG)){
      tag_filter(ProvGraph, queue);
    }

    if (is_active(FAUST_FILTER_DPRESERVE_FD)) {
      DPreserve::fd(*state);
    }

    if (is_active(FAUST_FILTER_DPRESERVE_SD)) {
      DPreserve::sd(*state);
    }

    if (is_active(FAUST_FILTER_NODEMERGE)) {
      node_merge(queue);
    }

    /* Output Filter Decisions to CSV */
    if(0 && OUTPUT_FILTER_DECISIONS){
      write_filter_decisions(state, ProvGraph, queue, config.filter_decisions_file);
    }

    /* Lets try filtering the queue here */
    filter(queue,state);

    /* Store output log */
    if (config.output_method == "local")
      write_local(ProvGraph, queue);
    else if (config.output_method == "tcp")
      write_tcp(ProvGraph, queue);
    else printf("Invalid output method.\n");

    ProvGraph.Clr();
    state->process_map.clear();
    state->process_id_map.clear();
    state->process_fd_fdfile_map.clear();
    state->process_fdfile_syscall_map.clear();
    state->fdfile_map.clear();
    state->fdfile_id_map.clear();
    state->edge_map.clear();
    state->event_map.clear();
    state->event_id_map.clear();
    state->filter_lists.clear();
    state->filter_actions_lists.clear();
    destroyQueue(queue);
    delete p_ProvGraph;
    delete state;
  }

  return NULL;
}

/* int process_epoch(int socket_fd, int conn_fd, struct sockaddr_in address, int addrlen){
     in: socket and connection information
     out: This function returns under two conditions:
          rv = 0 If connection was closed, but epoch is ongoing
          rv = 1 if epoch concluded, but connection is still open
*/
int process_epoch(int conn_fd, time_t elapsed){

  int rv = -1;

  /* Declare variables for setting epoch time and queue size */
  time_t start = elapsed;
  time_t curr;
  int epoch_expired = 0;

  /* Initialize buffers for reading and parsing auditd events */
  char filename[] = "localLog.txt";
  char* net_buffer = (char*) malloc(sizeof(char) * (BUFFER_SIZE));
  int bytes_read = 0;
  char * entry_str = (char*) malloc(sizeof(char) * (BUFFER_SIZE));
  int entry_str_len = 0;

  net_buffer[0] = '\0';
  entry_str[0] = '\0';

  /* Initialize data structures for log buffering */
  State* state = new State();
  state->ProvGraph = new PNEANet(new TNEANet()); // Holds the graph version of the audit log for analysis
  state->queue = createQueue(); // Buffer for storing individual event representations
  state->events_added = 0;
  state->unsupported_events_removed = 0;
  state->entries_added = 0;

  init_listener_state(state);

  /* Stuff for polling the socket */
  int poll_timeout = 100; /* Poll every .1 seconds */
  int poll_result;
  struct pollfd poll_fds[1];
  poll_fds[0].fd = conn_fd;
  poll_fds[0].events = POLLIN;

  for(;;) {

    poll_result = poll(poll_fds, 1, poll_timeout);

    if( poll_result < 0 ) {
      /* perror("Attempt to poll connection failed. exiting..."); */
      close(conn_fd);
      rv = 0;
      goto exit;
    }

    if ( poll_result == 1 ) {
      bytes_read = recv(conn_fd, net_buffer, BUFFER_SIZE-1, 0);
      net_buffer[bytes_read] = '\0';
      // printf("%s: Attempted recv, %d bytes read\n", __func__,bytes_read);

      // If 0 bytes read, close connection
      if( !bytes_read ) {
  printf("connection closed. exiting...\n");
  close(conn_fd);
  rv = 0;
  goto exit;
      }
    }


#ifndef NULL_LOGGER

    // Individual events can be batched in one message;
    //   they can also be segmented across messages
    //   We need to split/merge them into individual event strings
    char * net_buffer_ptr = net_buffer;
    char * end_of_entry_ptr;
    int bytes_remaining = bytes_read;
    log_entry * entry;
    while(net_buffer_ptr < net_buffer + bytes_read){
      bytes_remaining = bytes_read - (net_buffer_ptr - net_buffer);
      // printf("%s: %d bytes left in buffer\n",__func__,bytes_remaining);

      end_of_entry_ptr = NULL;
      end_of_entry_ptr = strstr(net_buffer_ptr,"\n");

      // Complete entry message
      if(end_of_entry_ptr) {

  /* Determine mem copy length */
  int copylen = end_of_entry_ptr - net_buffer_ptr;
  /* Apparently, we need to worry about freaky-long entries...
     current solution is to truncate if it would overflow the buffer*/
  if( (entry_str_len + (end_of_entry_ptr - net_buffer_ptr)) >= BUFFER_SIZE )
    copylen = BUFFER_SIZE - (entry_str_len + 1);

  // Start from entry_str + entry_str_len in case a partial entry message was already received
  memcpy(entry_str + entry_str_len, net_buffer_ptr, end_of_entry_ptr - net_buffer_ptr);
  entry_str_len += copylen;
  entry_str[entry_str_len] = '\0';

  entry = parse_entry(entry_str, entry_str_len);
  process_entry(*(state->ProvGraph), state->queue, entry);

  // Erase the entry string the handled entry from the net buffer
  memset(entry_str, 0, entry_str_len);
  entry_str_len = 0;

  //Advance to remainder of net_buffer if anything is left
  /* net_buffer_ptr = &end_of_entry_ptr[1]; */
  net_buffer_ptr = end_of_entry_ptr + 1;
      }
      // Incomplete entry message
      else {
  // printf("HEYYYY I'm processing an incomplete message for a change!\n Here's what's left: %s.\n",net_buffer_ptr);
  int remainder = bytes_read - (net_buffer_ptr - net_buffer);

  if(remainder > 0){
    //Copy beginning of entry message to entry_str and update entry_str_len
    memcpy(entry_str, net_buffer_ptr, remainder);
    entry_str_len += remainder;
  }
  break;
      }
    }
#endif

    memset(net_buffer, 0, bytes_read);
    bytes_read = 0;

    /* Check if the epoch clock has expired */
    curr = time(NULL);
    if( (curr - start) > EPOCH_MAX_TIME ) {
      pthread_mutex_lock(&flush_mutex);
      enqueue(*flush_workqueue, (void*)state);
      pthread_cond_signal(&flush_cond);
      pthread_mutex_unlock(&flush_mutex);

      rv = 1;
      goto exit;
    }

  }

 exit:
  free(net_buffer);
  free(entry_str);
  return rv;
}

int listen_from_unix() {
  int socket_fd, conn_fd;
  struct sockaddr_un address;
  int addrlen = sizeof(address);


  // creating socket file descriptor
  if( (socket_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == 0) {
    perror("Could not create a socket");
    exit(EXIT_FAILURE);
  }


  // trying to connect
  address.sun_family = AF_UNIX;
  strcpy(address.sun_path, config.sock_path.c_str());
  addrlen = strlen(address.sun_path) + sizeof(address.sun_family);

  if(connect(socket_fd, (struct sockaddr *)&address, addrlen) == -1) {
    perror("Could not connect to socket");
    exit(EXIT_FAILURE);
  }

  int epoch_rv = -1;
  time_t start;
  for(;;) {

    /* The epoch concluded (time expired) but the connection is still open */
    /* We just need to reset the clock and process the next epoch */
    if(epoch_rv == 1 || epoch_rv == -1) {
      printf("Starting new epoch...\n");
      start = time(NULL);
    }

    epoch_rv = process_epoch( socket_fd, start );
  }

  return 0;
}

int listen_from_tcp() {
  int socket_fd, conn_fd;
  struct sockaddr_in address;
  int opt = 1;
  int port = 60;
  int addrlen = sizeof(address);

  /* creating socket file descriptor */
  if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
    perror("Faust TCP Socket Error");
    exit(EXIT_FAILURE);
  }

  /* port reuse */
  if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
    perror("Faust TCP Socket Error");
    exit(EXIT_FAILURE);
  }
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl( INADDR_ANY );
  address.sin_port = htons( port );

  /* forcefully attaching socket to the port */
  if (bind(socket_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    perror("Faust TCP Socket Error");
    exit(EXIT_FAILURE);
  }
  /* listen to the port */
  if (listen(socket_fd, 5) < 0) {
    perror("Faust TCP Socket Error");
    exit(EXIT_FAILURE);
  }

  int epoch_rv = -1;
  time_t start;
  for(;;) {
    /* If there is not an open connection ... */
    if(epoch_rv == 0 || epoch_rv == -1) {
      // wait for connection
      if ((conn_fd = accept(socket_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
        perror("Faust TCP Connection Error");
        exit(EXIT_FAILURE);
      }
    }

    /* The epoch concluded (time expired) but the connection is still open */
    /* We just need to reset the clock and process the next epoch */
    if(epoch_rv == 1 || epoch_rv == -1) {
      printf("Starting new epoch...\n");
      start = time(NULL);
    }

    epoch_rv = process_epoch( conn_fd, start );
  }

  return 0;
}

bool read_file_chunk(std::ifstream &f){
  printf("----------------readinggg chunk\n");
  bool keep_reading = false;

  if(f.peek() == EOF) return keep_reading;

  log_entry * entry;
  char line_str[4096];

  /* Initialize data structures for log buffering */
  State* state = new State();
  state->ProvGraph = new PNEANet(new TNEANet()); // Holds the graph version of the audit log for analysis
  state->queue = createQueue(); // Buffer for storing individual event representations
  state->events_added = 0;
  state->unsupported_events_removed = 0;
  state->entries_added = 0;

  init_listener_state(state);

  int num_lines = 0;

  for (std::string line; getline(f, line);) {
    strncpy(line_str, line.c_str(), line.length());
    line_str[line.length()] = '\0';

    entry = parse_entry(line_str, line.length());
    process_entry(*(state->ProvGraph), state->queue, entry);

    num_lines++;
    // printf("done with line\n");
    // if(num_lines >= CHUNK_SIZE){
    //   printf("CHUNK SIZE %d\n", CHUNK_SIZE);
    //   printf("--------------breakingg\n");
    //   keep_reading = true;
    //   break;
    // }
  }

  pthread_mutex_lock(&flush_mutex);
  enqueue(*flush_workqueue, (void*)state);
  pthread_cond_signal(&flush_cond);
  pthread_mutex_unlock(&flush_mutex);
  
  return keep_reading;
}

int read_from_local() {
  DIR *dir;
  struct dirent *ent;
  const char* input_folder = config.input_folder.c_str();
  printf("Input folder is: %s\n", input_folder);
  if ((dir = opendir (config.input_folder.c_str())) == NULL) {
    /* could not open directory */
    perror ("Configuration Error");
    return EXIT_FAILURE;
  }

  /* get all the files and directories within directory */
  while ((ent = readdir (dir)) != NULL) {
    std::string path(config.input_folder + ent->d_name);

    /* check if file is valid */
    if (strlen(ent->d_name) < 3
        || path.find(".log") == std::string::npos){
      continue;
    }

    std::cout << path << std::endl;
    /* read files */
    std::ifstream f(path);
    if(!f.is_open()) continue;

    while(read_file_chunk(f));

    f.close();
  }

  closedir (dir);
  return 0;
}

int main(void) {

  timespec_get(&start_ts, TIME_UTC);

  /* load configuration file */
  load_config(&config);

  load_virtregexs(".faustvirtual");

  //queue of FlushData objects
  flush_workqueue = (struct Queue**)malloc(sizeof(struct Queue*));
  *flush_workqueue = createQueue();
  pthread_create(&flush_thread_id, NULL, flush_epoch, NULL);

  atexit(exit_cleanup);

  if (config.input_method == "unix")
    listen_from_unix();
  else if (config.input_method == "tcp")
    listen_from_tcp();
  else if (config.input_method == "local")
    read_from_local();
  else printf("Invalid input method.\n");

  // destroyQueue(*flush_workqueue);
  // free(flush_workqueue);

  return 0;
}
