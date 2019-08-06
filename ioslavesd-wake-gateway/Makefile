CXX=clang++
CXX_FLAGS = $(CXXFLAGS) -Wall -std=c++0x -fPIC
LD_FLAGS = $(LDFLAGS) $(shell pkg-config --libs-only-l socketxx) -lldns -lconfig++

ifndef $(LD)
	LD=$(CXX)
endif

all: wake-gateway.iosldl

wake-gateway.iosldl: common.o wake-gateway.o master-impl.o dyn_slaves.o wol.o
	$(LD) -o $@ $^ $(LD_FLAGS) -shared

common.o: common.cpp common.hpp 
wake-gateway.o: wake-gateway.cpp
master-impl.o: master.hpp master-impl.cpp
dyn_slaves.o: master.hpp dyn_slaves.cpp
wol.o: master.hpp wol.cpp

%.o: %.cpp
	$(CXX) -o $@ -c $< $(CXX_FLAGS)

.PHONY: clean

clean:
	rm -rf *.o
