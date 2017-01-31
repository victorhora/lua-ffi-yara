CC=gcc
CFLAGS=-c -Wall -Werror -g -fpic

LIBS=-lpthread -lcrypto
STATIC_LIBS=-lyara

LIB=libyawrap
LIB_NAME=libyawrap.so
OBJ_NAME=yawrap.o

SHARED_OPTS=-shared -o $(LIB_NAME) $(OBJ_NAME) -Wl,-Bstatic $(STATIC_LIBS) \
-Wl,-Bdynamic $(LIBS)

PWD=`pwd`

all: $(LIB)

libyawrap: yawrap.o
	$(CC) $(SHARED_OPTS)

yawrap.o: $@

clean:
	rm -f $(LIB_NAME) $(OBJ_NAME)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) $<
