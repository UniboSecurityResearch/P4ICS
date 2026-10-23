LIBS = definition.so

CXX = g++
CXXFLAGS = -Wall -Wextra -g -O2 -fPIC
LDFLAGS = -shared

.PHONY: all clean

all: $(LIBS)

%.so: %.cpp p4ics_crypto.h p4ics_aes_tables.h
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -f $(LIBS)
