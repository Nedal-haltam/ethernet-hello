.PHONY: all build-main build-raw wire-shark clean

CXX := g++
CXXFLAGS := -Wall -Wextra -O2

all: build-main build-raw
	@echo "✅ Built successfully."

build-main: main.cpp
	@echo "🔧 Building main..."
	$(CXX) $(CXXFLAGS) -o main main.cpp -lpcap

build-raw: raw.cpp
	@echo "🔧 Building raw..."
	$(CXX) $(CXXFLAGS) -o raw raw.cpp

wire-shark:
	wireshark capture_output.pcap

clean:
	@echo "🧹 Cleaning up..."
	rm -f raw pcap save-pcap
