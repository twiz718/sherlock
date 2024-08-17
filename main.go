package main

import (
	"flag"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/miekg/dns"
)

func showUsage() {
	flag.PrintDefaults()
}
func main() {

	iface := flag.String("if", "lo", "Interface to listen on")
	proto := flag.String("proto", "udp", "Protocol to filter on")
	port := flag.Int("port", 15300, "Port to filter on")
	flag.Parse()
	flag.Usage = showUsage

	if handle, err := pcap.OpenLive(*iface, 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter(fmt.Sprintf("%v and port %v", *proto, *port)); err != nil {
		panic(err)
	} else {
		fmt.Printf("Live capturing on INTERFACE [%v] PROTOCOL [%v] PORT[%v]\n", *iface, *proto, *port)
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			handlePacket(packet)
		}
	}
}

func handlePacket(packet gopacket.Packet) {
	fmt.Printf("----------------------------\n")
	defer fmt.Printf("----------------------------\n\n")
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}
	var (
		udp     = udpLayer.(*layers.UDP)
		payload = udp.LayerPayload()
	)

	fmt.Printf("SRC PORT [%v] ", udp.SrcPort)
	fmt.Printf("DST PORT [%v] ", udp.DstPort)
	fmt.Printf("LEN [%v] ", udp.Length)
	fmt.Printf("CHECKSUM [%v]\n", udp.Checksum)
	if len(payload) == 0 {
		return
	}

	var (
		msg = new(dns.Msg)
		err error
	)

	err = msg.Unpack(payload)
	if err != nil {
		fmt.Println(err)
		return
	}

	var (
		hasQuestion = len(msg.Question) > 0
		hasAnswer   = len(msg.Answer) > 0
	)

	// DNS Answer
	if hasAnswer {
		fmt.Println("[DNS ANSWERS]")
		for _, a := range msg.Answer {
			fmt.Printf("\t%v\n", a.String())
		}
		return
	}

	if hasQuestion {
		fmt.Println("[DNS QUESTIONS]")
		for _, q := range msg.Question {
			fmt.Printf("\t%v\n", q.String())
		}
	}

}
