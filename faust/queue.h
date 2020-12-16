#ifndef QUEUE_H
#define QUEUE_H

// A C program for a (doubly) linked list based 
#include <stdlib.h> 
#include <stdio.h> 

// A linked list (LL) node to store a queue entry 
struct QNode 
{ 
  int id;
  void * item;
  struct QNode *prev, *next; 
}; 

// The queue, front stores the front node of LL and rear stores the 
// last node of LL 
struct Queue 
{ 
  int id_counter;
  int size;
  struct QNode *front, *rear; 
}; 

// A utility function to create a new linked list node. 
struct QNode* newNode(void * i);

// A utility function to create an empty queue 
struct Queue *createQueue() ;

// A utility function to destroy the queue
void destroyQueue(struct Queue * q);

// The function to add a key i to queue 
int enqueue(struct Queue *q, void * i);

// Function to remove a key from given queue q 
int dequeue(struct Queue *q, void ** item);

// Function to remove specitic entry from queue
void queue_remove(struct Queue *q, int id);

// Function to retrieve specitic entry from queue
struct QNode* queue_get(struct Queue *q, int id);

#endif
