package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"strings"
)

type Addresses struct {
	Items []net.IP
}

func (v *Addresses) String() string {
	var items []string
	for _, item := range v.Items {
		items = append(items, item.String())
	}
	return strings.Join(items, ",")
}

func (v *Addresses) Set(raw string) error {
	for _, item := range strings.Split(raw, ",") {
		addr := net.ParseIP(item)
		if addr == nil {
			return fmt.Errorf("%s is invalid IPv4", item)
		}
		v.Items = append(v.Items, addr.To4())
	}
	return nil
}

func main() {
	var iface string
	var addrs Addresses
	flag.StringVar(&iface, "i", iface, "Interface")
	flag.Var(&addrs, "addrs", "IPv4")
	flag.Parse()

	// Mở card mạng
	h, err := pcap.OpenLive(iface, 65535, true, pcap.BlockForever)
	if err != nil {
		// Mở lỗi
		panic(err)
	}
	for { // Lặp vô hạn để đọc
		b, _, err := h.ReadPacketData() // Lấy 1 gói packet
		if err != nil {
			// Lấy lỗi
			panic(err)
		}
		// Phân tích gói
		p := gopacket.NewPacket(b, layers.LayerTypeEthernet, gopacket.DecodeOptions{
			Lazy:   true, // Phân tích từng phần
			NoCopy: true, // Tái sử dụng body
		})
		// Lấy tầng Ethernet
		etherLayer := p.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
		if etherLayer == nil || etherLayer.EthernetType != layers.EthernetTypeIPv4 {
			// Nếu không có tầng Ethernet hoặc gói Ethernet không phải IPv4 thì bỏ qua packet
			continue
		}
		// Lấy tầng IPv4
		ipv4Layer := p.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if ipv4Layer == nil || ipv4Layer.Protocol != layers.IPProtocolICMPv4 {
			// Nếu không có tầng IPv4 hoặc gói IPv4 không phải ICMPv4 thì bỏ qua packet
			continue
		}
		// Lấy tầng ICMPv4
		icmp4Layer := p.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
		if icmp4Layer == nil || icmp4Layer.TypeCode.Type() != layers.ICMPv4TypeEchoRequest {
			// Nếu không có tầng ICMPv4 hoặc ICMPv4 không phải EchoRequest thì bỏ qua packet
			continue
		}

		// Kiểm tra xem gói có khớp với quy tắc
		match := false
		for _, item := range addrs.Items {
			if item.Equal(ipv4Layer.DstIP) {
				// Khớp
				match = true
				break
			}
		}
		if !match {
			// Không khớp thì bỏ qua
			continue
		}

		payloadLayer := p.Layer(icmp4Layer.NextLayerType())
		log.Println(fmt.Sprintf("%s -> %s: type=%s id=%v seq=%v", ipv4Layer.SrcIP, ipv4Layer.DstIP, icmp4Layer.TypeCode.String(), icmp4Layer.Id, icmp4Layer.Seq))

		// Làm giả gói trả lời
		icmp4ResponseLayer := &layers.ICMPv4{
			// Đánh dấu gói là trả lời
			TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),

			// Sao chép từ gói nhận được
			Id:  icmp4Layer.Id,
			Seq: icmp4Layer.Seq,
		}

		ipv4ResponseLayer := &layers.IPv4{
			// Đảo địa chỉ nhận/gửi
			SrcIP: ipv4Layer.DstIP,
			DstIP: ipv4Layer.SrcIP,

			// Sao chép từ gói nhận được
			Version:    ipv4Layer.Version,
			IHL:        ipv4Layer.IHL,
			TOS:        ipv4Layer.TOS,
			Id:         ipv4Layer.Id,
			Flags:      ipv4Layer.Flags,
			FragOffset: ipv4Layer.FragOffset,
			TTL:        ipv4Layer.TTL,
			Protocol:   ipv4Layer.Protocol,
			Options:    ipv4Layer.Options,
			Padding:    ipv4Layer.Padding,
		}

		etherResponseLayer := &layers.Ethernet{
			// Đảo địa chỉ nhận/gửi
			SrcMAC: etherLayer.DstMAC,
			DstMAC: etherLayer.SrcMAC,

			// Sao chép từ gói nhận được
			EthernetType: etherLayer.EthernetType,
		}

		// Tạo gói trả lời
		s := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}
		// Tạo packet dạng bytes
		err = gopacket.SerializeLayers(s, opts, etherResponseLayer, ipv4ResponseLayer, icmp4ResponseLayer, payloadLayer.(gopacket.SerializableLayer))
		if err != nil {
			// Tạo lỗi
			panic(err)
		}
		// Gửi nó vào card mạng
		err = h.WritePacketData(s.Bytes())
		if err != nil {
			// Gửi lỗi
			panic(err)
		}

		log.Println(fmt.Sprintf("REPLY %s -> %s: type=%s id=%v seq=%v", ipv4ResponseLayer.SrcIP, ipv4ResponseLayer.DstIP, icmp4ResponseLayer.TypeCode.String(), icmp4ResponseLayer.Id, icmp4ResponseLayer.Seq))
	}
}
