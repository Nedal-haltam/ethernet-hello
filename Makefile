.PHONY: all build-receive-ether build-send-ether build-aes-gcm-test build-hls run-echo run-macsec-echo run-arp wire-shark

CXX := g++
CXXFLAGS := -Wall -Wextra -O2

all: build-receive-ether build-send-ether build-aes-gcm-test build-hls
	@echo "✅ Built successfully."

build-receive-ether: receive-ether.cpp
	@echo "🔧 Building receive-ether..."
	$(CXX) $(CXXFLAGS) -o receive-ether receive-ether.cpp -lpcap -lcryptopp

build-send-ether: send-ether.cpp
	@echo "🔧 Building send-ether..."
	$(CXX) $(CXXFLAGS) -o send-ether send-ether.cpp -lpcap -lcryptopp

build-aes-gcm-test: aes-gcm-test.cpp
	@echo "🔧 Building aes-gcm-test..."
	$(CXX) $(CXXFLAGS) -o aes-gcm-test aes-gcm-test.cpp -lpcap -lcryptopp

build-hls: hls.c
	@echo "🔧 Building hls..."
	gcc $(CXXFLAGS) -o hls hls.c

run-echo:
	sudo ./send-ether -d eth0 -mode echo -sip 172.30.160.245 -dip 192.168.100.1 -smac 0x00155d0cd15d -dmac 0x00155D5DC81A -n 10

run-macsec-echo:
	sudo ./send-ether -d eth0 -macsec -mode echo -sip 172.30.160.245 -dip 192.168.100.1 -smac 0x00155d0cd15d -dmac 0x00155D5DC81A -n 10

# DestinationIP = "172.30.160.1";
run-arp:
	sudo ./send-ether -d eth0 -mode arpreq -sip 172.30.160.245 -dip 172.30.160.1 -smac 0x00155d0cd15d -n 1

wire-shark:
	wireshark capture_output.pcap
