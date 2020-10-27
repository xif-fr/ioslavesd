CXX = clang++
CXX_FLAGS = $(CXXFLAGS) -Wall -Wno-dollar-in-identifier-extension
LD_FLAGS = $(LDFLAGS) $(shell pkg-config --libs-only-l socketxx) -lldns -lconfig++ -ldl

ifndef $(LD)
	LD=$(CXX)
endif

all: ioslaves-master

ioslaves-master: common.o master.o master-impl.o dyn_slaves.o wol.o
	$(LD) -o $@ $^ $(LD_FLAGS)

common.o: common.cpp common.hpp 
master.o: master.hpp master.cpp
master-impl.o: master.hpp master-impl.cpp
dyn_slaves.o: master.hpp dyn_slaves.cpp
wol.o: master.hpp wol.cpp

%.o: %.cpp
	$(CXX) -o $@ -c $< $(CXX_FLAGS)

.PHONY: clean

clean:
	rm -rf *.o
