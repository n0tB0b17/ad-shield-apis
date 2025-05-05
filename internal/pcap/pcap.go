package pcap

import (
	"fmt"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type PCAPReader struct {
	filename string
}

func NewPCAPReader(filename string) *PCAPReader {
	return &PCAPReader{
		filename: filename,
	}
}

func (reader *PCAPReader) ReadPackets(packetChan chan<- gopacket.Packet, wg *sync.WaitGroup) {
	defer wg.Done()

	handler, err := pcap.OpenOffline(reader.filename)
	if err != nil {
		fmt.Printf("error while opening pcap file: %v \n", err)
		close(packetChan)
		return
	}
	defer handler.Close()

	packetSRC := gopacket.NewPacketSource(handler, handler.LinkType())
	for packet := range packetSRC.Packets() {
		packetChan <- packet
	}

	close(packetChan)
}
