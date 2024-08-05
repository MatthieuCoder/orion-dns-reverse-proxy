package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"

	"gopkg.in/yaml.v3"
)

var (
	address = flag.String("address", ":53", "Address to listen to (TCP and UDP)")

	defaultServer = flag.String("default", "",
		"Default DNS server where to send queries if no route matched (host:port)")
	certificatesDir = flag.String("certs", "./",
		"Default DNS server where to send queries if no route matched (host:port)")

	routes map[string]string
)

type PrivateKeyFile struct {
	Algorithm  string
	PrivateKey string
	Created    int64
	Publish    int64
	Activate   int64
}

func loadPrivate(path string) (*RRSetKey, error) {
	fmt.Printf("Loading %s\n", path)

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := new(PrivateKeyFile)
	err = yaml.Unmarshal(content, &out)
	if err != nil {
		return nil, err
	}
	dst := []byte{}
	_, err = base64.StdEncoding.Decode(dst, []byte(out.PrivateKey))
	if err != nil {
		panic(err)
	}
	p := new(ecdsa.PrivateKey)
	p.D = new(big.Int)
	p.D.SetBytes(dst)
	p.Curve = elliptic.P384()

	return &RRSetKey{
		PrivateKey: p,
		Activate:   int(out.Activate),
	}, nil
}

type RRSetKey struct {
	Tag        uint16
	PrivateKey *ecdsa.PrivateKey
	SignerName string
	Activate   int
}

func loadKeys() map[string]*RRSetKey {
	log.Println("Starting to load the certificates...")
	keys := make(map[string]*RRSetKey)

	files, err := os.ReadDir(*certificatesDir)

	if err != nil {
		log.Fatal(err)
	}

	for _, file := range files {
		name := filepath.Join(*certificatesDir, file.Name())
		if strings.HasSuffix(name, ".private") {
			re := regexp.MustCompile(`/K([^\+]*)\+[^\+]+\+(\d+)\.private`)
			match := re.FindStringSubmatch(name)
			id, err := strconv.Atoi(match[2])
			signerName := match[1]

			if err != nil {
				panic(err)
			}
			key, err := loadPrivate(name)
			if err != nil {
				panic(err)
			}
			key.SignerName = signerName
			key.Tag = uint16(id)
			keys[signerName] = key
		}
	}

	return keys
}

var (
	Keys map[string]*RRSetKey
)

func main() {
	flag.Parse()
	Keys = loadKeys()

	routes = make(map[string]string)

	for i := 0; i <= 255; i++ {
		backend := fmt.Sprintf("10.30.%d.255:53", i)
		name := fmt.Sprintf("%d.orionet.re.", i)
		reverse := fmt.Sprintf("%d.30.10.in-addr.arpa.", i)
		routes[name] = backend
		routes[reverse] = backend
		log.Printf("Adding %s for %s and %s", backend, name, reverse)
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

	log.Println("Server is loaded.")

	// Wait for SIGINT or SIGTERM
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	udpServer.Shutdown()
	tcpServer.Shutdown()
}

func rrSign(rr *[]dns.RR, key *RRSetKey) error {
	// nception, Expiration, KeyTag, SignerName and Algorithm
	sig := &dns.RRSIG{
		KeyTag:     key.Tag,
		SignerName: key.SignerName,
		Algorithm:  dns.ECDSAP384SHA384,
		Inception:  uint32(time.Now().Add(-time.Hour * 7).Unix()),
		Expiration: (uint32(time.Now().Add(time.Hour * 24 * 7).Unix())),
	}
	err := sig.Sign(key.PrivateKey, *rr)
	if err != nil {
		return err
	}
	*rr = append(*rr, sig)
	return nil
}

func signRRSet(rrset *dns.Msg, lc string) {
	key := Keys[lc]
	rrSign(&rrset.Extra, key)
	rrSign(&rrset.Answer, key)
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
					m.Authoritative = true

					signRRSet(m, lcName)

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
