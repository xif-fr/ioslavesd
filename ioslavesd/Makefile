CXX=clang++
CXX_FLAGS = $(CXXFLAGS) -Wall -std=c++0x
LDFLAGS = $(shell pkg-config --libs-only-l socketxx) -lconfig++ -lminiupnpc -lldns -ltopp -ldl

ifndef $(LD)
	LD=$(CXX)
endif

all: ioslavesd

ioslavesd: common.o log_slave.o slave.o upnp.o status.o master-impl.o
	$(LD) -o $@ $^ $(LDFLAGS)

common.o: common.cpp common.hpp 
log_slave.o: log_slave.cpp log.h 
slave.o: slave.cpp log.h main.h common.hpp api.h
upnp.o: upnp.cpp main.h
status.o: status.cpp main.h
master-impl.o: master.hpp master-impl.cpp

%.o: %.cpp
	$(CXX) -o $@ -c $< $(CXX_FLAGS)

.PHONY: clean

clean:
	rm *.o
