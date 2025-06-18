.PHONY: all build-raw build-pcap build-save-pcap wire-shark clean

CXX := g++
CXXFLAGS := -Wall -Wextra -O2

all: build-raw build-pcap build-save-pcap
	@echo "✅ Built successfully."

build-raw: raw.cpp
	@echo "🔧 Building raw..."
	$(CXX) $(CXXFLAGS) -o raw raw.cpp

build-pcap: pcap.cpp
	@echo "🔧 Building pcap..."
	$(CXX) $(CXXFLAGS) -o pcap pcap.cpp -lpcap

build-save-pcap: save-pcap.cpp
	@echo "🔧 Building save-pcap..."
	$(CXX) $(CXXFLAGS) -o save-pcap save-pcap.cpp -lpcap

wire-shark:
	wireshark capture_output.pcap

clean:
	@echo "🧹 Cleaning up..."
	rm -f raw pcap save-pcap
