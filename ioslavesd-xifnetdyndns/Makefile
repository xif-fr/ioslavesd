CXX=clang++
CXX_FLAGS = $(CXXFLAGS) -Wall -fPIC
LD_FLAGS = $(LDFLAGS) $(shell pkg-config --libs-only-l socketxx)

ifndef $(LD)
	LD=$(CXX)
endif

all: xifnetdyndns.iosldl

xifnetdyndns.iosldl: common.o xifnetdyndns.o
	$(LD) -o $@ $^ $(LD_FLAGS) -shared

common.o: common.cpp common.hpp 
xifnetdyndns.o: xifnetdyndns.cpp

%.o: %.cpp
	$(CXX) -o $@ -c $< $(CXX_FLAGS)

.PHONY: clean

clean:
	rm -rf *.o
