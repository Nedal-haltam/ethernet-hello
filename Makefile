.PHONY: all build-ether build-save-ether build-send-ether build-raw wire-shark clean

CXX := g++
CXXFLAGS := -Wall -Wextra -O2

all: build-ether build-save-ether build-send-ether build-raw
	@echo "✅ Built successfully."

build-ether: main.cpp
	@echo "🔧 Building ether..."
	$(CXX) $(CXXFLAGS) -DDEFAULT -o ether main.cpp -lpcap

build-save-ether: main.cpp
	@echo "🔧 Building save-ether..."
	$(CXX) $(CXXFLAGS) -o save-ether main.cpp -lpcap

build-send-ether: send-ether.cpp
	@echo "🔧 Building send-ether..."
	$(CXX) $(CXXFLAGS) -o send-ether send-ether.cpp -lpcap

build-raw: raw.cpp
	@echo "🔧 Building raw..."
	$(CXX) $(CXXFLAGS) -o raw raw.cpp

wire-shark:
	wireshark capture_output.pcap

clean:
	@echo "🧹 Cleaning up..."
	rm -f raw ether save-ether
