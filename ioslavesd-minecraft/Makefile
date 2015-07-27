CXX=clang++
CXX_FLAGS = $(CXXFLAGS) -Wall -std=gnu++0x -fPIC -g
LDFLAGS = $(shell pkg-config --libs-only-l socketxx) -lconfig++

ifndef $(LD)
	LD=$(CXX)
endif

all: minecraft.iosldl

minecraft.iosldl: common.o minecraft.o ftp-auth-mc.o
	$(LD) -o $@ $^ $(LDFLAGS) -shared -fPIC

common.o: common.cpp common.hpp 
minecraft.o: minecraft.h minecraft.cpp
ftp-auth-mc.o: minecraft.h ftp-auth-mc.cpp

%.o: %.cpp
	$(CXX) -o $@ -c $< $(CXX_FLAGS)

.PHONY: clean

clean:
	rm -rf *.o
