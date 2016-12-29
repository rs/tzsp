package main

import (
	"flag"
	"log"
	"net"

	"github.com/rs/tzsp"
)

func main() {
	listenAddr := flag.String("listen", ":37008", "Address to listen for TZSP UDP packets.")
	flag.Parse()

	addr, err := net.ResolveUDPAddr("udp", *listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatal(err)
	}

	buf := make([]byte, 65535)
	for {
		l, _, err := conn.ReadFrom(buf)
		if err != nil {
			panic(err)
		}
		p, err := tzsp.Read(buf[:l])
		if err != nil {
			panic(err)
		}
		print(p.String())
	}
}
