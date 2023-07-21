CC=g++
CFLAGS=-c -Wall
LDFLAGS=-lpcap
SOURCES=pcap-test.cpp
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=pcap-test

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf $(OBJECTS) $(EXECUTABLE)
