#ifndef LISTENER_H
#define LISTENER_H

#define MSG_LEN 64


#define PID_STR_LEN 8
#define INODE_STR_LEN 12
#define SYSCALL_STR_LEN 8
#define FD_STR_LEN 6
#define TYPE_LEN 32
#define PATH_STR_LEN 4099

struct log_entry {
  char type[TYPE_LEN];

  /* The whole message for safe keeping... */
  int msg_len;
  char * msg;
};
typedef struct log_entry log_entry;

/* field name passed in must NOT include the '=' sign */
int get_event_field(const char * field, char * dst, char * event_msg, int len) { 

  int rv = -1;

  if(!field)
    return rv;

  /* Copy message so that we can tokenize it */
  char * msg_cpy = (char *) malloc(len+1);
  strcpy(msg_cpy, event_msg);

  char *saveptr;

  /* Search for field */
  char * word = strtok_r(msg_cpy," ", &saveptr);
  while(word){
    if (strncmp(word, field, strlen(field)) == 0) {
      // Add one so that we don't grab the equals sign      
      sscanf(word + 1 + strlen(field), "%99[^ ]", dst);
      //sscanf(word + 1 + strlen(field), "%s", dst);
      rv = strlen(dst);
      goto exit;
    }
    word = strtok_r(NULL, " ", &saveptr);    
  }

 exit:
  free(msg_cpy);
  return rv;
}

/* 
   Note: This function wrecks event_msg by calling str_tok on it 
   Shouldn't be a big deal because process_epoch zeros out 
   event_msg after process_event is called.
*/
log_entry* parse_entry(char * entry_msg, int len) {

  log_entry * entry = (log_entry *) malloc(sizeof(log_entry));
  entry->msg = (char *) malloc( (sizeof(char) * len) + 1 );


  entry->type[0] = '\0';
  entry->msg_len = len;

  strcpy(entry->msg, entry_msg); 

  char *saveptr;

  // extract log entries
  char * word = strtok_r(entry_msg, " ", &saveptr);
  while (word != NULL) {
    if (strncmp(word, "type=", 5) == 0) {
      sscanf(word, "type=%99[^ ]", entry->type);
      break;
    }
    word = strtok_r(NULL, " ", &saveptr);
  }

  return entry;
}

log_entry * copy_entry(log_entry * entry) {

  log_entry * dup = (log_entry *) malloc(sizeof(log_entry));

  strcpy(dup->type, entry->type);

  dup->msg_len = entry->msg_len;

  dup->msg = (char *) malloc( (sizeof(char) * entry->msg_len) );
  dup->msg = strdup(entry->msg);

  return dup;
}

int get_timestamp(char* entry_msg, char* dst, int len) {
  char msg_field[MSG_LEN];
  int actual_msg_len = get_event_field("msg", msg_field, entry_msg, len);

  char msg_copy[actual_msg_len + 1];
  strncpy(msg_copy, msg_field, actual_msg_len+1);

  char* msg_copy_pt = msg_copy;
  msg_copy_pt = msg_copy_pt + 6;
  char *saveptr;
  char* timestamp = strtok_r(msg_copy_pt, ".", &saveptr);

  int rv = -1;
  if(timestamp) {
    sscanf(timestamp, "%99[^ ]", dst);
    rv = strlen(dst);
    goto exit;
  }

  exit:
    return rv;

}

#endif
