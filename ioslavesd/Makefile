CXX=clang++
CXX_FLAGS = $(CXXFLAGS) -Wall
LD_FLAGS = $(LDFLAGS) $(shell pkg-config --libs-only-l socketxx) -lconfig++ -lminiupnpc -lldns -ltopp -ldl

ifndef $(LD)
	LD=$(CXX)
endif

all: ioslavesd

ioslavesd: common.o log_slave.o slave.o upnp.o status.o master-impl.o keys.o
	$(LD) -o $@ $^ $(LD_FLAGS)

common.o: common.cpp common.hpp 
log_slave.o: log_slave.cpp log.h 
slave.o: slave.cpp log.h main.h common.hpp api.h
upnp.o: upnp.cpp main.h
keys.o: keys.cpp main.h
status.o: status.cpp main.h
master-impl.o: master.hpp master-impl.cpp

%.o: %.cpp
	$(CXX) -o $@ -c $< $(CXX_FLAGS)

.PHONY: clean

clean:
	rm *.o
