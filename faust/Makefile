CC = gcc
#CFLAGS = -g -Wall -O3 -std=c11
FPIC = -fPIC

CC = g++
CFLAGS += -std=c++11
CFLAGS += -fopenmp -lpthread
CFLAGS += -g -O0
#CFLAGS += -DNDEBUG -O3
LDFLAGS +=
LIBS += -lrt -lm

SNAPPATH=/home/adil/Desktop/Snap-5.0

default: faust

faust: listener-unix.o bloom.o murmurhash2.o queue.o regex.o config.o virtualfile.o logGC.o dpreserve.o structures.h event_analysis.h filters.h approx.h filter_decisions.h tag.h node.h
	$(CC) $(CFLAGS) -o faust listener-unix.o bloom.o murmurhash2.o queue.o regex.o config.o virtualfile.o dpreserve.o logGC.o $(LDFLAGS) $(SNAPPATH)/snap-core/Snap.o -I$(SNAPPATH)/snap-core -I$(SNAPPATH)/snap-adv -I$(SNAPPATH)/snap-exp -I$(SNAPPATH)/glib-core $(LIBS)

faust-tcp: listener-tcp.o bloom.o murmurhash2.o queue.o config.o virtualfile.o logGC.o dpreserve.o filters.h structures.h logGC.o
	$(CC) $(CFLAGS) -o faust-tcp listener-tcp.o bloom.o murmurhash2.o queue.o config.o virtualfile.o dpreserve.o logGC.o $(LDFLAGS) $(SNAPPATH)/snap-core/Snap.o -I$(SNAPPATH)/snap-core -I$(SNAPPATH)/snap-adv -I$(SNAPPATH)/snap-exp -I$(SNAPPATH)/glib-core $(LIBS)

queue: queue.o
	$(CC) $(CFLAGS) -o queue_test queue.o

listener-unix.o: listener-unix.c listener.h queue.h structures.h event_analysis.h filters.h approx.h filter_decisions.h induction.h tag.h dpreserve.h
	$(CC) $(CFLAGS) -c listener-unix.c  $(SNAPPATH)/snap-core/Snap.o -I$(SNAPPATH)/snap-core -I$(SNAPPATH)/snap-adv -I$(SNAPPATH)/snap-exp -I$(SNAPPATH)/glib-core

listener-tcp.o: listener-tcp.c listener.h queue.h event_analysis.h filters.h structures.h
	$(CC) $(CFLAGS) -c listener-tcp.c $(SNAPPATH)/snap-core/Snap.o -I$(SNAPPATH)/snap-core -I$(SNAPPATH)/snap-adv -I$(SNAPPATH)/snap-exp -I$(SNAPPATH)/glib-core

logGC.o: logGC.cpp logGC.h
	$(CC) $(CFLAGS) -c logGC.cpp $(SNAPPATH)/snap-core/Snap.o -I$(SNAPPATH)/snap-core -I$(SNAPPATH)/snap-adv -I$(SNAPPATH)/snap-exp -I$(SNAPPATH)/glib-core

provGraph.o: provGraph.h
	$(CC) $(CFLAGS) -c provGraph.h
queue.o: queue.c queue.h
	$(CC) $(CFLAGS) -c queue.c

bloom.o: bloom.c bloom.h
	$(CC) $(CFLAGS) $(FPIC) -c bloom.c

murmurhash2.o: murmurhash2.c murmurhash2.h
	$(CC) $(CFLAGS) $(FPIC) -c murmurhash2.c

regex: regex_test.c regex.o
	$(CC) $(CFLAGS) -o regex_test regex_test.c regex.o

regex.o: regex.c regex.h
	$(CC) $(CFLAGS) $(FPIC) -c regex.c

config.o:	config.c config.h
	$(CC) $(CFLAGS) $(FPIC) -c config.c

virtualfile.o: virtualfile.cpp virtualfile.h
	$(CC) $(CFLAGS) $(FPIC) -c $<

dpreserve.o: dpreserve.cpp dpreserve.h filters.h structures.h
	$(CC) $(CFLAGS) $(FPIC) -c $< $(SNAPPATH)/snap-core/Snap.o -I$(SNAPPATH)/snap-core -I$(SNAPPATH)/snap-adv -I$(SNAPPATH)/snap-exp -I$(SNAPPATH)/glib-core

replay: replay.c
	$(CC) $(CFLAGS) -o replay replay.c

template: template_gen.c
	$(CC) $(CFLAGS) -o template_gen template_gen.c
clean:
	$(RM) listener *.o *~ faust regex_test replay
