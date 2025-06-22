.PHONY: all build-receive-ether build-send-ether wire-shark clean

CXX := g++
CXXFLAGS := -Wall -Wextra -O2

all: build-receive-ether build-send-ether
	@echo "✅ Built successfully."

build-receive-ether: receive-ether.cpp
	@echo "🔧 Building receive-ether..."
	$(CXX) $(CXXFLAGS) -o receive-ether receive-ether.cpp -lpcap

build-send-ether: send-ether.cpp
	@echo "🔧 Building send-ether..."
	$(CXX) $(CXXFLAGS) -o send-ether send-ether.cpp -lpcap

wire-shark:
	wireshark capture_output.pcap
