#include "queue.h"

// A utility function to create a new linked list node. 
struct QNode* newNode(void * i)
{ 
  if(!i)
    return NULL;

  struct QNode *temp = (struct QNode*)malloc(sizeof(struct QNode)); 
  temp->item = i; 
  temp->next = NULL; 
  return temp; 
} 

// A utility function to create an empty queue 
struct Queue *createQueue() 
{ 
  struct Queue *q = (struct Queue*)malloc(sizeof(struct Queue)); 
  q->id_counter = 0;
  q->size = 0;
  q->front = q->rear = NULL; 
  return q; 
} 

// A utility function to destroy the queue
void destroyQueue(struct Queue * q){

  struct QNode * curr = q->front;
  struct QNode * next;
  while(curr != NULL){
    /* printf("%s: %d\t%p\n",__func__,curr->id,curr); */
    next = curr->next;
    free(curr);
    curr = next;
  }
  free(q);
}


// The function to add a key i to queue 
int enqueue(struct Queue *q, void * i) 
{ 
  // Create a new LL node 
  struct QNode *temp = newNode(i); 

  /* Set id of new node */
  q->id_counter++;
  temp->id = q->id_counter;
  temp->prev = q->rear;

  // If queue is empty, then new node is front and rear both 
  if (q->rear == NULL) 
    { 
      q->front = q->rear = temp; 
      q->size++;
      return temp->id; 
    } 

  // Add the new node at the end of queue and change rear 
  q->rear->next = temp; 
  q->rear = temp; 

  q->size++;

  return temp->id;
 } 

// Function to remove an item from given queue q 
int dequeue(struct Queue *q, void ** item) 
{ 
   int rv = 0;

   // If queue is empty, return NULL. 
   /* printf("%s: If queue is empty, return NULL.\n", __func__); */
   if (q->front == NULL) 
     return rv; 

   // Store previous front and move front one node ahead 
   /* printf("%s: Store previous front and move front one node ahead\n", __func__); */
   struct QNode *temp = q->front; 
   q->front = q->front->next; 

   // If front becomes NULL, then change rear also as NULL 
   /* printf("%s: If front becomes NULL, then change rear also as NULL\n", __func__); */
   if (q->front == NULL) 
     q->rear = NULL; 
   else
     q->front->prev = NULL;

   /* printf("%s: looking at QNode temp (%p)\n", __func__, temp); */
   *item = temp->item;
   rv = temp->id;
   /* printf("%s: \t%d\t%p\n", __func__,temp->id,temp); */
   free(temp);

   q->size--;

   return rv;

 } 

// Function to remove a specific key from linked list
void queue_remove(struct Queue *q, int tgt_id){

  /* Start from rear */
  struct QNode * curr = q->rear;

  if(curr == NULL)
    return;

  while(curr != NULL){
    if(curr->id == tgt_id){

      /* If tgt is not at beginning or end of list ... */
      if( curr->prev != NULL && curr-> next != NULL ) {
	      curr->prev->next = curr->next;
	      curr->next->prev = curr->prev;
      }
      else if ((curr->next == NULL) && (curr->prev == NULL)) {
        q->front = q->rear = NULL;       
      }
      /* If tgt is at end of list ... */
      else if ( curr->next == NULL ) {	
        curr->prev->next = NULL;
	      q->rear = curr->prev;	
      }
      /* If tgt is at beginning of list ... */
      else if ( curr->prev == NULL ) {
	      curr->next->prev = NULL;
	      q->front = curr->next;
      }
	
      curr->item = NULL;
      free(curr);
      q->size--;
      return;
    }

    curr = curr->prev;
  }
}

struct QNode * queue_get(struct Queue *q, int tgt_id) {
  /* Start from rear */
  struct QNode * curr = q->rear;

  while(curr != NULL){
    if(curr->id == tgt_id){
      return curr;
    }
    curr = curr->prev;
  }
  return NULL;
}
/*

int test(void) {

  char * msg;
  struct Queue *q = createQueue();
  int one = enqueue(q, (void *) "One");
  int two = enqueue(q, (void *) "Two");
  int dup = enqueue(q, (void *) "Two");
  int three = enqueue(q, (void *) "Three");
  msg = (char *)dequeue(q);
  printf("%s\n",msg);

  remove(q, one);

  int four = enqueue(q, (void *) "Four");
  while ( (msg = (char *)dequeue(q) ) ){
    printf("%p\n",msg);
    printf("%s\n",msg);
  }

  int five = enqueue(q, (void *) "Five");
  destroyQueue(q);

  return 0;
}

*/
