TOPPROJ ?= ..
TARGET = pcapread

LDFLAGS += -lpcap -lm

SRCS = $(TARGET).c disorder.c
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

$(TARGET).o: Makefile

clean: 
	rm -f *.o

distclean: clean
	rm -f $(TARGET)

