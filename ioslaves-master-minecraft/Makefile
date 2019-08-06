CXX = clang++
CXX_FLAGS = $(CXXFLAGS) -Wall -Wno-dollar-in-identifier-extension -std=gnu++0x $(shell pkg-config --cflags nopoll)
LD_FLAGS = $(LDFLAGS) $(shell pkg-config --libs-only-l socketxx nopoll) -lconfig++ -lldns -ldl

ifndef $(LD)
	LD=$(CXX)
endif

all: minecraft-master

minecraft-master: common.o minecraft-master.o dyn_slaves.o master-impl.o wol.o
	$(LD) -o $@ $^ $(LD_FLAGS)

common.o: common.cpp common.hpp 
minecraft-master.o: master.hpp minecraft.h minecraft-master.cpp
dyn_slaves.o: master.hpp dyn_slaves.cpp
wol.o: master.hpp wol.cpp
master-impl.o: master.hpp master-impl.cpp keystore.hpp

%.o: %.cpp
	$(CXX) -o $@ -c $< $(CXX_FLAGS)

.PHONY: clean

clean:
	rm -rf *.o
