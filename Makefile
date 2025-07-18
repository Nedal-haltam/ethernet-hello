.PHONY: all build-receive-ether build-send-ether build-golden-aes-gcm build-aes-gcm run-echo run-macsec-echo run-arp wire-shark

CXX := g++
CXXFLAGS := -Wall -Wextra -O3

all: build-receive-ether build-send-ether build-golden-aes-gcm build-macsec
	@echo "✅ Built successfully."

build-receive-ether: receive-ether.cpp
	@echo "🔧 Building receive-ether..."
	$(CXX) $(CXXFLAGS) -o receive-ether receive-ether.cpp -lpcap -lcryptopp

build-send-ether: send-ether.cpp
	@echo "🔧 Building send-ether..."
	$(CXX) $(CXXFLAGS) -o send-ether send-ether.cpp -lpcap -lcryptopp

build-golden-aes-gcm: golden-aes-gcm.cpp
	@echo "🔧 Building golden-aes-gcm..."
	$(CXX) $(CXXFLAGS) -o golden-aes-gcm golden-aes-gcm.cpp -lpcap -lcryptopp

build-macsec: build-macsec-sender build-macsec-listener
	@echo "🔧 Building macsec..."

build-macsec-sender: macsec-sender.cpp
	@echo "🔧 Building macsec-sender..."
	$(CXX) $(CXXFLAGS) -o macsec-sender macsec-sender.cpp -lpcap -lcryptopp
build-macsec-listener: macsec-listener.cpp
	@echo "🔧 Building macsec-listener..."
	$(CXX) $(CXXFLAGS) -o macsec-listener macsec-listener.cpp -lpcap -lcryptopp

run-echo:
	sudo ./send-ether -d eth0 -mode echo -sip 172.30.160.245 -dip 192.168.100.1 -smac 0x00155d0cd15d -dmac 0x00155D5DC81A -n 10

run-macsec-echo:
	sudo ./send-ether -d eth0 -macsec -mode echo -sip 172.30.160.245 -dip 192.168.100.1 -smac 0x00155d0cd15d -dmac 0x00155D5DC81A -n 10

# DestinationIP = "172.30.160.1";
run-arp:
	sudo ./send-ether -d eth0 -mode arpreq -sip 172.30.160.245 -dip 172.30.160.1 -smac 0x00155d0cd15d -n 1

wire-shark:
	wireshark capture_output.pcap
