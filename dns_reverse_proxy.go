package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/miekg/dns"
)

var (
	address = flag.String("address", ":53", "Address to listen to (TCP and UDP)")

	defaultServer = flag.String("default", "",
		"Default DNS server where to send queries if no route matched (host:port)")
	mxRecords = flag.String("mx-records", "",
		"Default DNS server where to send queries if no route matched (host:port)")

	routes map[string]string
)

func main() {
	flag.Parse()

	routes = make(map[string]string)

	for i := 0; i <= 255; i++ {
		backend := fmt.Sprintf("10.30.%d.255:53", i)
		name := fmt.Sprintf("%d.orionet.re.", i)
		reverse := fmt.Sprintf("%d.30.10.in-addr.arpa.", i)
		routes[name] = backend
		routes[reverse] = backend
	}

	udpServer := &dns.Server{Addr: *address, Net: "udp"}
	tcpServer := &dns.Server{Addr: *address, Net: "tcp"}
	dns.HandleFunc(".", route)
	go func() {
		if err := udpServer.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()
	go func() {
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()

	// Wait for SIGINT or SIGTERM
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	udpServer.Shutdown()
	tcpServer.Shutdown()
}

func route(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 || !allowed(req) {
		dns.HandleFailed(w, req)
		return
	}

	lcName := strings.ToLower(req.Question[0].Name)
	for name, addrs := range routes {
		// All DS records should be forwarded to the default server (which is the autoritative DNS server)
		for _, q := range req.Question {
			switch q.Qtype {
			case dns.TypeIXFR, dns.TypeDS:
				proxy(*defaultServer, w, req)
				return
			case dns.TypeMX:
				if name == lcName {
					m := new(dns.Msg)
					m.SetReply(req)
					m.Compress = false
					rr, err := dns.NewRR(fmt.Sprintf("%s IN MX 10 mail.orionet.re", lcName))

					if err != nil {
						dns.HandleFailed(w, req)
						return
					}

					rrMailServer4, _ := dns.NewRR("mail.orionet.re. IN A 194.163.144.50")
					rrMailServer6, _ := dns.NewRR("mail.orionet.re. IN AAAA 2a02:c206:2201:3371::1")
					m.Extra = append(m.Extra, rrMailServer4, rrMailServer6)

					m.Answer = append(m.Answer, rr)

					w.WriteMsg(m)
				}
			}
		}

		// Check if the dns name in under
		if strings.HasSuffix(lcName, fmt.Sprintf(".%s", name)) || lcName == name {
			addr := addrs
			proxy(addr, w, req)
			return
		}
	}

	if *defaultServer == "" {
		dns.HandleFailed(w, req)
		return
	}

	proxy(*defaultServer, w, req)
}

func isTransfer(req *dns.Msg) bool {
	for _, q := range req.Question {
		switch q.Qtype {
		case dns.TypeIXFR, dns.TypeAXFR:
			return true
		}
	}
	return false
}

func allowed(req *dns.Msg) bool {
	return !isTransfer(req)
}

func proxy(addr string, w dns.ResponseWriter, req *dns.Msg) {
	transport := "udp"
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		transport = "tcp"
	}
	c := &dns.Client{Net: transport}
	resp, _, err := c.Exchange(req, addr)
	if err != nil {
		dns.HandleFailed(w, req)
		fmt.Printf("Error while proxying %s", err.Error())
		return
	}
	w.WriteMsg(resp)
}
