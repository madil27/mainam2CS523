#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "listener.h"

/* bloom filter */
#include "bloom.h"

/* generic queue data structure */
#include "queue.h"

/* Graph datastructure for causality analysis */
#include "Snap.h"
#include "event_analysis.h"

/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
/*               CONFIGURATION SETTINGS                */
/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

//#define NULL_LOGGER                /* Uncomment if you'd like the logger to receive messages 
				   /* from auditd but take no other action */

#define EPOCH_MAX_TIME 5 * 60      /* Set epoch time to 5 minutes */  
#define EPOCH_MAX_QUEUE 0          /* Feature not yet support */
 
#define EVENT_CACHE_MAX 100        /* Max cache size in bytes */

#define BUFFER_SIZE 2048

typedef struct bloom bloom;

void process_event(PNEANet ProvGraph, struct Queue * queue, char * event_msg, int len){

  log_entry * event;  // parsed log buffer
  //bloom bloom_set;  // bloom filter
  //bloom_init(&bloom_set, 1000, 0.01);

  event = parse_event(event_msg, len);
  if (event) {
    /* We only want to process syscalls from this point forward */
    if(!strcmp(event->type,"SYSCALL")){
      printf("MSG(%d): %s\n", len, event->msg);
      //printf("\tnode: %s\n", event->node);
      //printf("\ttype: %s\n", event->type);
      //printf("\ttimestamp: %s\n", event->timestamp);
      printf("\tsyscall: %d\n", event->syscall);
      printf("\tsuccess: %s\n", event->success);
      printf("\tpid: %i\n", event->pid);
      printf("\tuid: %i\n", event->uid);
      printf("\texe: %s\n", event->exe);     

      int event_id = enqueue(queue, (void *) event);;
      update_graph(ProvGraph, event, event_id);

    }
    else{
      printf("IGN(%d): %s\n", len, event->msg);
    }

    // remove_duplicate(entry, &bloom_set);	
    // write_to_file(filename, log_buffer);
  }
}


int remove_duplicate(log_entry * entry, bloom * bloom_set) {
  // conver pid from int to string
  int pid_len = 5;
  char str_pid[pid_len];
  sprintf(str_pid, "%d", entry->pid);

  // generate string for bloom filter
  int buf_len = strlen(entry->type) + strlen(str_pid);
  char buffer[buf_len];
  strcpy(buffer, entry->type);
  strcat(buffer, str_pid);

  // check if string exist
  if (bloom_check(bloom_set, buffer, buf_len)) {
    /* printf("Log already exist, IGNORED!\n\n"); */
    return 1;
  } else {
    bloom_add(bloom_set, buffer, buf_len);
    return 0;
  }
}

int write_to_file(char* filename, char* data) {
  FILE *fp;
  /* printf("Write to file: %s\n\n", filename); */

  // count bytes in log entry
  int len = 0;
  for (int i = 0; i < BUFFER_SIZE; i++, data++, len++) {
    if ((int)data[0] > 64 && (int)data[0] < 123)
      break;
  }
  len += strlen(data+len);

  // write to file
  if ((fp = fopen(filename, "a") ) == NULL) {
     printf("Error: can't create file");
     return 1;
  }
  fwrite(data, 1, len, fp);
  fclose(fp);

  return 0;
}


/* int process_epoch(int socket_fd, int conn_fd, struct sockaddr_in address, int addrlen){
     in: socket and connection information
     out: This function returns under two conditions:
          rv = 0 If connection was closed, but epoch is ongoing
          rv = 1 if epoch concluded, but connection is still open
*/
int process_epoch(int socket_fd, int conn_fd, 
		  struct sockaddr_in address, int addrlen,
		  time_t elapsed){

  int rv = -1;

  /* Declare variables for setting epoch time and queue size */
  time_t start = elapsed;
  time_t curr;

  /* Initialize buffers for reading and parsing auditd events */
  char filename[] = "localLog.txt";
  char* net_buffer = (char*) malloc(sizeof(char) * (BUFFER_SIZE));  
  int bytes_read = 0;
  char * entry_str = (char*) malloc(sizeof(char) * (BUFFER_SIZE)); 
  int entry_str_len = 0;

  /* Initialize data structures for log buffering */
  PNEANet ProvGraph = TNEANet::New(); // Holds the graph version of the audit log for analysis
  struct Queue * queue = createQueue(); // Buffer for storing individual event representations
  
  /* Stuff for polling the socket */
  int poll_timeout = 100; /* Poll every .1 seconds */
  int poll_result;
  struct pollfd poll_fds[1];
  poll_fds[0].fd = conn_fd;
  poll_fds[0].events = POLLIN;

  for(;;) {

    poll_result = poll(poll_fds, 1, poll_timeout);
    
    if( poll_result < 0 ) {
      perror("Attempt to poll connection failed. exiting...");
      close(conn_fd);
      rv = 0;
      goto exit;
    }

    if ( poll_result == 1 ) {
      bytes_read = recv(conn_fd, net_buffer, BUFFER_SIZE-1, 0);      
      /* printf("Attempted recv, %d bytes read\n", bytes_read); */

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
    char * end_of_entry_ptr = NULL;
    while(net_buffer_ptr < net_buffer + bytes_read){
      end_of_entry_ptr = strstr(net_buffer_ptr,"\n");

      // Complete event message
      if(end_of_entry_ptr){
	// Start from entry_str + entry_str_len in case a partial event message was already received
	memcpy(entry_str + entry_str_len, net_buffer_ptr, end_of_entry_ptr - net_buffer_ptr);
	entry_str_len += (end_of_entry_ptr - net_buffer_ptr);
	entry_str[entry_str_len] = '\0';
	
	process_event(ProvGraph, queue, entry_str, entry_str_len);
	
	// Erase the entry string (handle the event message above)
	memset(net_buffer, 0, entry_str_len);
	entry_str_len = 0;
	
	//Advance to remainder of net_buffer if anything is left
	net_buffer_ptr = &end_of_entry_ptr[1];
      }
      // Incomplete event message
      else {
	int remainder = strlen(net_buffer_ptr);
	if(remainder > 0){
	  //Copy beginning of event message to entry_str and update entry_str_len
	  memcpy(entry_str, net_buffer_ptr, remainder);
	  entry_str_len += remainder;
	}
	break;
      }
    }

#endif

    /* Check if the epoch clock has expired */	
    curr = time(NULL);      
    if( (curr - start) > EPOCH_MAX_TIME ) {
      printf("EPOCH_MAX_TIME exceeded (%d seconds). exiting...\n", curr-start);
      rv = 1;
      goto exit;
    }

  }

 exit:
  free(net_buffer);
  free(entry_str);
  return rv;
}

int main(void) {

  int socket_fd, conn_fd;
  struct sockaddr_in address;
  int opt = 1;
  int port = 60;
  int addrlen = sizeof(address);

  // creating socket file descriptor
  if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
    perror("Could not create a socket");
    exit(EXIT_FAILURE);
  }

  // port reuse
  if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
    perror("Could not set socket options");
    exit(EXIT_FAILURE);
  }
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl( INADDR_ANY );
  address.sin_port = htons( port );

  // forcefully attaching socket to the port
  if (bind(socket_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    perror("Could not bind socket to address");
    exit(EXIT_FAILURE);
  }
  // listen to the port
  if (listen(socket_fd, 5) < 0) {
    perror("Listen error");
    exit(EXIT_FAILURE);
  }

  int epoch_rv = -1;
  time_t start;
  for(;;) {

    /* If there is not an open connection ... */
    if(epoch_rv == 0 || epoch_rv == -1) {
      // wait for connection
      while ((conn_fd = accept(socket_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
	perror("Accept conn_fdection failure");
	exit(EXIT_FAILURE);
      }
    }

    /* The epoch concluded (time expired) but the connection is still open */
    /* We just need to reset the clock and process the next epoch */
    if(epoch_rv == 1 || epoch_rv == -1) {
      printf("Starting new epoch...\n");
      start = time(NULL);
    }    

    epoch_rv = process_epoch( socket_fd, conn_fd,  address, addrlen, start );
  }

  return 0;
}
