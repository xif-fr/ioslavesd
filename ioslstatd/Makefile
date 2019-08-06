CXX = clang++
CXX_FLAGS = $(CXXFLAGS) -Wall -std=gnu++0x $(shell pkg-config --cflags nopoll)
LD_FLAGS = $(LDFLAGS) $(shell pkg-config --libs-only-l socketxx nopoll) -lldns -lconfig++

ifndef $(LD)
	LD=$(CXX)
endif

all: ioslstatd

ioslstatd: common.o ioslstatd.o master-impl.o 
	$(LD) -o $@ $^ $(LD_FLAGS)

common.o: common.cpp common.hpp 
ioslstatd.o: ioslstatd.cpp
master-impl.o: master.hpp master-impl.cpp

%.o: %.cpp
	$(CXX) -o $@ -c $< $(CXX_FLAGS)

.PHONY: clean

clean:
	rm -rf *.o
