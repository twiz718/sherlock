package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/miekg/dns"
)

func showUsage() {
	flag.PrintDefaults()
}

type DnsMetadata struct {
	port  int
	msg   dns.Msg
	srcIP string
	dstIP string
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
		questionsChan := make(chan *DnsMetadata, 1000)
		answersChan := make(chan *DnsMetadata, 1000)
		go processQuestions(questionsChan)
		go processAnswers(answersChan)
		fmt.Printf("Live capturing on INTERFACE [%v] PROTOCOL [%v] PORT [%v]\n", *iface, *proto, *port)
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			handlePacket(packet, questionsChan, answersChan)
		}
	}
}

func handlePacket(packet gopacket.Packet, questions chan *DnsMetadata, answers chan *DnsMetadata) {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}
	var (
		udp     = udpLayer.(*layers.UDP)
		payload = udp.LayerPayload()
	)

	netLayer := packet.Layer(layers.LayerTypeIPv4)
	if netLayer == nil {
		return
	}
	net := netLayer.(*layers.IPv4)

	fmt.Printf("SRC IP [%v] ", net.SrcIP)
	fmt.Printf("SRC PORT [%v] ", udp.SrcPort)
	fmt.Printf("DST IP [%v] ", net.DstIP)
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
		answers <- &DnsMetadata{port: int(udp.DstPort), msg: *msg, srcIP: net.SrcIP.String(), dstIP: net.DstIP.String()}
		return
	}

	// DNS Question
	if hasQuestion {
		questions <- &DnsMetadata{port: int(udp.SrcPort), msg: *msg, srcIP: net.SrcIP.String(), dstIP: net.DstIP.String()}
	}

}

func processQuestions(questions <-chan *DnsMetadata) {
	for {
		q := <-questions
		msgId := getMsgId(q)
		fmt.Printf("Processing Question with msg ID [%v]\n", msgId)
		err := saveToFile(msgId, q.msg)
		if err != nil {
			fmt.Println("error saving:", err)
		}

	}
}

func processAnswers(answers <-chan *DnsMetadata) {
	for {
		a := <-answers
		// fmt.Println("Hey look an Answer arrived!")
		// fmt.Printf("%+v\n", a)
		msgId := getMsgId(a)
		fmt.Printf("Processing Answer with msg ID [%v]\n", msgId)
		err := saveToFile(msgId, a.msg)
		if err != nil {
			fmt.Println("error saving:", err)
		}
	}
}

func getMsgId(dmd *DnsMetadata) string {
	questionOrAnswer := "QUESTION"
	ip := dmd.srcIP
	if dmd.msg.Response {
		questionOrAnswer = "ANSWER"
		ip = dmd.dstIP
	}
	qTypeStr := dns.TypeToString[dmd.msg.Question[0].Qtype]
	qName := dmd.msg.Question[0].Name
	return fmt.Sprintf("%v_%v_%v_%v_%v_%v_%v",
		questionOrAnswer,
		ip,
		"msgid-"+strconv.FormatUint(uint64(dmd.msg.Id), 10),
		"port-"+strconv.Itoa(dmd.port),
		qTypeStr,
		qName[:len(qName)-1],
		strconv.FormatInt(time.Now().UTC().Unix(), 10))
}

func saveToFile(msgId string, msg dns.Msg) error {
	// Save the JSON representation of the dns message
	j, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	jsonFile := msgId + ".json"
	f, err := os.Create(jsonFile)
	if err != nil {
		return err
	}
	n, err := f.Write(j)
	if err != nil {
		return err
	}
	fmt.Printf("  Wrote %v bytes to %v\n", n, jsonFile)
	err = f.Close()
	if err != nil {
		return err
	}

	// Save the binary representation of the dns message
	msgPacked, err := msg.Pack()
	if err != nil {
		return err
	}
	binFile := msgId + ".bin"
	f2, err := os.Create(binFile)
	if err != nil {
		return err
	}
	n2, err := f2.Write(msgPacked)
	if err != nil {
		return err
	}
	fmt.Printf("  Wrote %v bytes to %v\n", n2, binFile)
	err = f2.Close()
	if err != nil {
		return err
	}
	return nil
}
