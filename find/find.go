// Copyright 2020 The go-ego Project Developers.
//
// Licensed under the Apache License, Version 2.0 (the "License"): you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

// package find is tcpp tools

package find

import (
	"fmt"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

const (
	TypeIP  = 0x0800
	TypeARP = 0x0806
	TypeIP6 = 0x86DD

	IPICMP = 1
	IPINIP = 4
	IPTCP  = 6
	IPUDP  = 17
)

var (
	// Will reuse these for each packet
	ethLayer layers.Ethernet
	ipLayer  layers.IPv4
	ip6Layer layers.IPv6

	tcpLayer layers.TCP
	udpLayer layers.UDP
	tlsLayer layers.TLS
)

// Pacp pacp struct
type Pacp struct {
	Device string
	H      *pcap.Handle

	Ofile string
	Read  string

	Snaplen     int
	Promiscuous bool
	Hexdump     bool

	Count int
	// Timeout int
	Timeout time.Duration
}

// Open device for offline pcap file
func (p *Pacp) Open(pcapFile string) (*pcap.Handle, error) {
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		return nil, err
	}
	// defer handle.Close()

	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		fmt.Println(packet)
	}

	return handle, err
}

// Info pcap version info
func (p *Pacp) Info() string {
	return pcap.Version()
}

// FindAllDevs find all devices
func (p *Pacp) FindAllDevs() ([]pcap.Interface, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Fprintln(os.Stderr, "tcpp: can't find any devices: ", err)
		return nil, err
	}

	return devs, err
}

// ReadFilter open device for Live Capture and set BPF filter
func (p *Pacp) ReadFilter(expr ...string) (*pcap.Handle, error) {
	h, err := pcap.OpenLive(p.Device, int32(p.Snaplen), p.Promiscuous, p.Timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tcpp: %v", err)
		return nil, err
	}
	// defer h.Close()

	if len(expr) > 0 && expr[0] != "" {
		fmt.Println("tcpp: setting filter to ", expr)
		ferr := h.SetBPFFilter(expr[0])
		if ferr != nil {
			fmt.Println("tcpp:", ferr)
			return nil, err
		}
	}

	return h, nil
}

// OpenDump device for offline pacp file
func OpenDump(file string) (*pcap.Handle, error) {
	h, err := pcap.OpenOffline(file)
	if err != nil {
		return nil, err
	}

	return h, err
}

// Write write pcap file
func (p *Pacp) Write(files string) {
	// Open output pcap file and write header
	f, _ := os.Create(files)
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(uint32(p.Snaplen), layers.LinkTypeEthernet)
	defer f.Close()

	// Start processing packets
	packetSource := gopacket.NewPacketSource(p.H, p.H.LinkType())
	for packet := range packetSource.Packets() {
		// Process packet here
		fmt.Println(packet)
		w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		p.Count++

		// Only capture 100 and then stop
		if p.Count > 100 {
			break
		}
	}
}

// TimeOut set timeout
func (p *Pacp) TimeOut() {
	time.AfterFunc(p.Timeout, func() {
		p.H.Close()
		os.Exit(1)
	})
}

// Decode decoding packets faster
func (p *Pacp) Decode(expr ...string) {
	packetSource := gopacket.NewPacketSource(p.H, p.H.LinkType())
	// packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		parser := gopacket.NewDecodingLayerParser(
			layers.LayerTypeEthernet,
			&ethLayer,
			&ipLayer,
			&ip6Layer,
			&tcpLayer,
			&udpLayer,
			&tlsLayer,
		)
		foundLayerTypes := []gopacket.LayerType{}

		err := parser.DecodeLayers(packet.Data(), &foundLayerTypes)
		if err != nil {
			fmt.Println("Trouble decoding layers: ", err)
		}

		for _, layerType := range foundLayerTypes {
			if layerType == layers.LayerTypeIPv4 {
				fmt.Println("IPv4: ", ipLayer.SrcIP, "->", ipLayer.DstIP)
				fmt.Printf("IP4: %v", ipLayer.Payload)
			}

			if layerType == layers.LayerTypeIPv6 {
				fmt.Println("IPv6: ", ip6Layer.SrcIP, "->", ip6Layer.DstIP)
				fmt.Printf("IP6: %v", ip6Layer.Payload)
			}

			if layerType == layers.LayerTypeTCP {
				fmt.Println("TCP Port: ", tcpLayer.SrcPort, "->", tcpLayer.DstPort)
				fmt.Println("TCP SYN:", tcpLayer.SYN, " | ACK:", tcpLayer.ACK)
			}

			if layerType == layers.LayerTypeUDP {
				fmt.Println("UDP Port: ", udpLayer.SrcPort, "->", udpLayer.DstPort)
			}

			if layerType == layers.LayerTypeTLS {
				fmt.Printf("TSL: %v %v \n", tlsLayer.BaseLayer.LayerContents(),
					tlsLayer.BaseLayer.LayerPayload())

				data := tlsLayer.AppData
				for i := 0; i < len(data); i++ {
					fmt.Printf("TSL: %v\n", data[i].Payload)
				}
			}
		}
	}
}
