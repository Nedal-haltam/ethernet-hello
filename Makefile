.PHONY: all build-receive-ether build-send-ether run-echo run-arp wire-shark

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

run-echo:
	sudo ./send-ether -d eth0 -mode echo -sip 172.30.160.245 -dip 192.168.100.1 -smac 0x00155D0CDB26 -dmac 0x00155D0CD85E -n 10

# DestinationIP = "172.30.160.1";
run-arp:
	sudo ./send-ether -d eth0 -mode arpreq -sip 172.30.160.245 -dip 172.30.160.1 -smac 0x00155D0CDB26 -n 1

wire-shark:
	wireshark capture_output.pcap
