CXX=clang++
CXX_FLAGS = $(CXXFLAGS) -Wall -fPIC
LD_FLAGS = $(LDFLAGS) $(shell pkg-config --libs-only-l socketxx) -lconfig++

ifndef $(LD)
	LD=$(CXX)
endif

all: minecraft.iosldl

minecraft.iosldl: common.o minecraft.o ftp-auth-mc.o
	$(LD) -o $@ $^ $(LD_FLAGS) -shared -fPIC

common.o: common.cpp common.hpp 
minecraft.o: minecraft.h minecraft.cpp
ftp-auth-mc.o: minecraft.h ftp-auth-mc.cpp

%.o: %.cpp
	$(CXX) -o $@ -c $< $(CXX_FLAGS)

.PHONY: clean

clean:
	rm -rf *.o
