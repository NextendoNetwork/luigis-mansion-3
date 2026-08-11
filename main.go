package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	nex "github.com/NextendoNetwork/nextendo-nex"
)

const (
	// LM3 Key
	accessKey     = "aab95246"
	gameServerID  = 0x20DE2100
	nexVersion    = 40000
	securePID     = 2
	sessionKeyLen = 32
	lm3AppID      = "0100dca0064a6000"
)

var (
	nextendoHost   = envOr("NEXTENDO_HOST", "127.0.0.1")
	authPort       = envOrInt("AUTH_PORT", 443)
	securePort     = envOrInt("SECURE_PORT", 60009)        // 60006 collides with the Minecraft server
	securePassword = envOr("NEXTENDO_SECURE_PASSWORD", "") // no public default: main() fails fast if unset
	certFile       = envOr("CERT_FILE", "cert.pem")
	keyFile        = envOr("KEY_FILE", "key.pem")

	// lm3 uses 5.17 pia
	piaMode = strings.ToLower(envOr("LM3_PIA_MODE", "legacy"))

	nextendoSecret     = loadNextendoSecret()
	requireAccount     = os.Getenv("NEXTENDO_REQUIRE_ACCOUNT") == "1"
	effectiveAccessKey = envOr("LM3_ACCESS_KEY", accessKey)

	// used last before entering a lm3 lobby reports what Nat type.
	// must be on different IPS for it to attempt stun
	nncsUDPPort1   = envOrInt("NNCS_UDP_PORT_1", 10025)
	nncsUDPPort2   = envOrInt("NNCS_UDP_PORT_2", 10125)
	nncsSinkhole1  = envOrInt("NNCS_SINKHOLE_1", 33334)
	nncsSinkhole2  = envOrInt("NNCS_SINKHOLE_2", 33335)
	nncsNatFile    = envOr("NNCS_NAT_FILE", defaultNATFilePath())
	nncsTypeFile   = envOr("NNCS_TYPE_FILE", defaultNATTypeFilePath())
	nncsReportedIP = envOr("NEXTENDO_HOST", "127.0.0.1")
)

var (
	natMu       sync.Mutex
	natMap      = map[string]string{}
	natSeen     = map[string]map[int]int{}
	natLastSeen = map[string]time.Time{}
	natDirty    bool
)

const (
	natTTL        = 5 * time.Minute
	natMaxIPs     = 8192
	natFlushEvery = 2 * time.Second
)

func defaultNATFilePath() string {
	if tmp := os.Getenv("TEMP"); tmp != "" {
		return tmp + "\\nncs_nat_endpoints.txt"
	}
	if tmp := os.Getenv("TMP"); tmp != "" {
		return tmp + "\\nncs_nat_endpoints.txt"
	}
	return "nncs_nat_endpoints.txt"
}

func defaultNATTypeFilePath() string {
	if tmp := os.Getenv("TEMP"); tmp != "" {
		return tmp + "\\nncs_nat_types.txt"
	}
	if tmp := os.Getenv("TMP"); tmp != "" {
		return tmp + "\\nncs_nat_types.txt"
	}
	return "nncs_nat_types.txt"
}

func ipToU32(ip net.IP) uint32 {
	if v4 := ip.To4(); v4 != nil {
		return binary.BigEndian.Uint32(v4)
	}
	return 0
}

func recordNAT(ip string, port int) {
	natMu.Lock()
	defer natMu.Unlock()
	natMap[ip] = strconv.Itoa(port)
	natLastSeen[ip] = time.Now()
	// A co-located host probes through loopback or its LAN interface
	// (NEXTENDO_NAT_IP_1/2 = 127.0.0.1 / 192.168.x — its router does no hairpin),
	// but the natbridge looks observations up by the PUBLIC station address. Same
	// port either way — it is the host's real P2P socket — so mirror the
	// observation under NEXTENDO_HOST.
	if src := net.ParseIP(ip); src != nil && (src.IsLoopback() || src.IsPrivate()) && reportedIPIsPublic() {
		natMap[nncsReportedIP] = strconv.Itoa(port)
		natLastSeen[nncsReportedIP] = time.Now()
	}
	natDirty = true // flushed off the packet path by natFileFlusher
}

func reportedIPIsPublic() bool {
	ip := net.ParseIP(nncsReportedIP)
	if ip == nil {
		return false
	}
	return !ip.IsLoopback() && !ip.IsPrivate()
}

func classifyNAT(ip string, dstPort, srcPort int) {
	natMu.Lock()
	defer natMu.Unlock()
	m := natSeen[ip]
	if m == nil {
		m = map[int]int{}
		natSeen[ip] = m
	}
	m[dstPort] = srcPort
	natLastSeen[ip] = time.Now()
	natDirty = true // flushed off the packet path by natFileFlusher
}

// natFileFlusher debounces NAT-observation disk writes OFF the packet path: the UDP
// responder only mutates in-memory maps (cheap, under lock); this goroutine prunes
// stale/overflow entries and serializes both files at most once per natFlushEvery.
// Writing the whole map per packet (the previous behaviour) turned a UDP flood into
// O(N^2) disk work under a shared lock, stalling NAT/matchmaking for every player.
func natFileFlusher() {
	t := time.NewTicker(natFlushEvery)
	defer t.Stop()
	for range t.C {
		natMu.Lock()
		if !natDirty {
			natMu.Unlock()
			continue
		}
		pruneNATLocked()
		natBody := renderNATMapLocked()
		typeBody := renderNATTypesLocked()
		natDirty = false
		natMu.Unlock()
		_ = os.WriteFile(nncsNatFile, []byte(natBody), 0644)
		_ = os.WriteFile(nncsTypeFile, []byte(typeBody), 0644)
	}
}

// pruneNATLocked drops observations older than natTTL and, if still over natMaxIPs,
// the oldest ones — so a spoofed-source-IP UDP flood cannot grow the maps without bound.
func pruneNATLocked() {
	now := time.Now()
	for ip, seen := range natLastSeen {
		if now.Sub(seen) > natTTL {
			delete(natMap, ip)
			delete(natSeen, ip)
			delete(natLastSeen, ip)
		}
	}
	if len(natLastSeen) > natMaxIPs {
		type kv struct {
			ip string
			t  time.Time
		}
		all := make([]kv, 0, len(natLastSeen))
		for ip, seen := range natLastSeen {
			all = append(all, kv{ip, seen})
		}
		sort.Slice(all, func(i, j int) bool { return all[i].t.Before(all[j].t) })
		for _, e := range all[:len(all)-natMaxIPs] {
			delete(natMap, e.ip)
			delete(natSeen, e.ip)
			delete(natLastSeen, e.ip)
		}
	}
}

func renderNATMapLocked() string {
	var b strings.Builder
	for k, v := range natMap {
		b.WriteString(k + " " + v + "\n")
	}
	return b.String()
}

func renderNATTypesLocked() string {
	var b strings.Builder
	for cip, ports := range natSeen {
		sym := false
		var first int
		got := false
		for _, sp := range ports {
			if !got {
				first, got = sp, true
			} else if sp != first {
				sym = true
			}
		}
		kind := "cone"
		if sym {
			kind = "sym"
		}
		b.WriteString(cip + " " + kind + "\n")
	}
	return b.String()
}

func serveNNCS(port int) {
	serverIP := ipToU32(net.ParseIP(nncsReportedIP))
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: port})
	if err != nil {
		fmt.Printf("[NNCS] bind UDP :%d failed: %v\n", port, err)
		return
	}
	fmt.Printf("[NNCS] NAT-check responder listening on UDP :%d\n", port)
	buf := make([]byte, 128)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		if n < 16 {
			fmt.Printf("[NNCS] :%d short %d-byte probe from %s (ignored)\n", port, n, src)
			continue
		}
		word0 := binary.BigEndian.Uint32(buf[0:4])
		srcIP := ipToU32(src.IP)
		resp := make([]byte, 16)
		binary.BigEndian.PutUint32(resp[0:4], word0)
		binary.BigEndian.PutUint32(resp[4:8], uint32(src.Port))
		binary.BigEndian.PutUint32(resp[8:12], srcIP)
		binary.BigEndian.PutUint32(resp[12:16], serverIP)
		if _, err := conn.WriteToUDP(resp, src); err != nil {
			fmt.Printf("[NNCS] :%d reply to %s failed: %v\n", port, src, err)
			continue
		}
		fmt.Printf("[NNCS] :%d test=%d <- %s:%d  replied ext=%s:%d\n", port, word0, src.IP, src.Port, src.IP, src.Port)
		recordNAT(src.IP.String(), src.Port)
		classifyNAT(src.IP.String(), port, src.Port)
		if src.IP.IsLoopback() || src.IP.String() == nncsReportedIP {
			fmt.Printf("[NNCS] >>> co-located host P2P port %d: FORWARD UDP %d on the router\n", src.Port, src.Port)
		}
	}
}

func nncsSinkhole(port int) {
	serverIP := ipToU32(net.ParseIP(nncsReportedIP))
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: port})
	if err != nil {
		fmt.Printf("[NNCS] sinkhole bind :%d failed: %v\n", port, err)
		return
	}
	fmt.Printf("[NNCS] sinkhole + anchor responding on UDP :%d\n", port)
	buf := make([]byte, 512)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < 16 {
			continue
		}
		// The anchor port is the co-located host's station address; its resolve job
		// probes it with the same 16-byte format used on the NAT-check ports, so
		// answer in kind (and record the observation, which is also what lets the
		// natbridge find the host's real P2P port).
		word0 := binary.BigEndian.Uint32(buf[0:4])
		srcIP := ipToU32(src.IP)
		resp := make([]byte, 16)
		binary.BigEndian.PutUint32(resp[0:4], word0)
		binary.BigEndian.PutUint32(resp[4:8], uint32(src.Port))
		binary.BigEndian.PutUint32(resp[8:12], srcIP)
		binary.BigEndian.PutUint32(resp[12:16], serverIP)
		if _, err := conn.WriteToUDP(resp, src); err != nil {
			continue
		}
		fmt.Printf("[NNCS] :%d anchor test=%d <- %s:%d replied ext=%s:%d\n", port, word0, src.IP, src.Port, src.IP, src.Port)
		recordNAT(src.IP.String(), src.Port)
		classifyNAT(src.IP.String(), port, src.Port)
		if src.IP.IsLoopback() || src.IP.String() == nncsReportedIP {
			fmt.Printf("[NNCS] >>> co-located host P2P port %d: FORWARD UDP %d on the router\n", src.Port, src.Port)
		}
	}
}

// nncsRelay runs the anchor port as BOTH the probe responder and a station relay.
// It answers the 16-byte resolve/NAT-check probes in kind (exactly like the sinkhole,
// recording the observations the natbridge reads), AND forwards PRUDP station traffic
// between peers: every packet's source connection id is remembered as its endpoint,
// and the packet is forwarded to the endpoint of its destination connection id —
// resolved lazily from the secure endpoint (the connection's observed UDP port) when
// not seen yet.
//
// Why this is the missing piece: both players are behind firewalled NATs with no port
// forwarding, so a direct punch between their real endpoints can never land (the punch
// fails with rtt=0). The station URLs the server hands out (Register response rewrite
// + natbridge relay mode) point BOTH players' sockets at THIS port instead, so every
// packet — resolve probe, punch SYN, data — arrives here, and this loop makes the two
// endpoints talk to each other. Both players keep a NAT mapping toward this port alive
// by virtue of sending here, which is what makes the forwards reach them.
func nncsRelay(port int, ep *nex.Endpoint) {
	serverIP := ipToU32(net.ParseIP(nncsReportedIP))
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: port})
	if err != nil {
		fmt.Printf("[NNCS] relay bind UDP :%d failed: %v\n", port, err)
		return
	}
	fmt.Printf("[NNCS] relay + anchor responding on UDP :%d\n", port)

	answerProbe := func(buf []byte, n int, src *net.UDPAddr) {
		word0 := binary.BigEndian.Uint32(buf[0:4])
		srcIP := ipToU32(src.IP)
		resp := make([]byte, 16)
		binary.BigEndian.PutUint32(resp[0:4], word0)
		binary.BigEndian.PutUint32(resp[4:8], uint32(src.Port))
		binary.BigEndian.PutUint32(resp[8:12], srcIP)
		binary.BigEndian.PutUint32(resp[12:16], serverIP)
		if _, err := conn.WriteToUDP(resp, src); err != nil {
			return
		}
		fmt.Printf("[NNCS] :%d relay probe test=%d <- %s:%d replied ext=%s:%d\n", port, word0, src.IP, src.Port, src.IP, src.Port)
		recordNAT(src.IP.String(), src.Port)
		classifyNAT(src.IP.String(), port, src.Port)
	}

	// peers: connection id -> endpoint to forward packets for that cid to. The host's
	// cid is resolved lazily from the secure endpoint (its Register/ReplaceURL
	// connection + observed UDP port); friends' cids are learned from the source
	// endpoint of their packets. The host never sends first, so its entry MUST be
	// resolvable this way — it is, once the host has done its NAT check.
	peers := map[uint16]*net.UDPAddr{}
	resolvePeer := func(cid uint16) *net.UDPAddr {
		c := ep.FindConnectionByID(uint32(cid))
		if c == nil {
			return nil
		}
		host, _, err := net.SplitHostPort(c.RemoteAddr)
		if err != nil {
			return nil
		}
		p, ok := nex.NatPortForIP(host)
		if !ok {
			return nil
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return nil
		}
		return &net.UDPAddr{IP: ip, Port: p}
	}

	buf := make([]byte, 2048)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		if n < 12 {
			continue
		}

		// Not PRUDP station traffic: the 16-byte resolve/NAT-check probe format.
		if buf[0] != 0x62 && buf[0] != 0xA2 {
			if n >= 16 {
				answerProbe(buf, n, src)
			}
			continue
		}

		// PRUDP header sniffing. The source/destination connection ids are u16 LE
		// fields; the one thing we do NOT want to get wrong is their order, and the
		// two station protocol versions disagree about where they sit (v0 has them
		// right after the substream id, v1 behind a 20-byte header with a checksum).
		// So generate every candidate layout and pick the one that validates against
		// the known connection ids; if a layout's "destination" turns out to be the
		// sender itself, the forward logic below flips it. A wrong guess is still
		// logged, never silent.
		var srcCID, dstCID uint16
		ok := false
		known := map[uint16]bool{}
		for _, id := range ep.ConnectionIDs() {
			known[uint16(id)] = true
		}
		var cands [][2]uint16
		pktType := byte(0)
		if buf[0] == 0x62 {
			// v0: 12-byte header, cids at [5:7]/[7:9]; type in the low nibble of [1].
			cands = [][2]uint16{
				{binary.LittleEndian.Uint16(buf[5:7]), binary.LittleEndian.Uint16(buf[7:9])},
				{binary.LittleEndian.Uint16(buf[7:9]), binary.LittleEndian.Uint16(buf[5:7])},
			}
			pktType = buf[1] & 0x0F
		} else if n >= 20 {
			// v1: 20-byte header, cids around [5:7]/[9:11]; type in [1].
			cands = [][2]uint16{
				{binary.LittleEndian.Uint16(buf[9:11]), binary.LittleEndian.Uint16(buf[11:13])},
				{binary.LittleEndian.Uint16(buf[11:13]), binary.LittleEndian.Uint16(buf[9:11])},
				{binary.LittleEndian.Uint16(buf[7:9]), binary.LittleEndian.Uint16(buf[5:7])},
				{binary.LittleEndian.Uint16(buf[5:7]), binary.LittleEndian.Uint16(buf[7:9])},
			}
			pktType = buf[1]
		}
		// Prefer layouts where BOTH ids are known, then dst-known, then src-known.
		for _, c := range cands {
			if known[c[0]] && known[c[1]] {
				srcCID, dstCID, ok = c[0], c[1], true
				break
			}
		}
		if !ok {
			for _, c := range cands {
				if known[c[1]] {
					srcCID, dstCID, ok = c[0], c[1], true
					break
				}
			}
		}
		if !ok {
			for _, c := range cands {
				if known[c[0]] {
					srcCID, dstCID, ok = c[0], c[1], true
					break
				}
			}
		}
		if !ok {
			// Probably a resolve probe whose test id happens to look like a PRUDP
			// magic byte — answer it as a probe rather than drop it.
			if n == 16 {
				answerProbe(buf, n, src)
			} else {
				fmt.Printf("[NNCS] :%d relay no known cids from %s:%d (magic=0x%02x n=%d) — dropped\n", port, src.IP, src.Port, buf[0], n)
			}
			continue
		}

		if srcCID != 0 {
			peers[srcCID] = src
		}
		dst := peers[dstCID]
		if dst == nil {
			dst = resolvePeer(dstCID)
		}
		if dst != nil && sameUDPAddr(dst, src) && srcCID != dstCID {
			// The sniffed "destination" is the sender itself: the header layout
			// guess was inverted. Flip the pair and re-resolve.
			fmt.Printf("[NNCS] :%d relay self-loop from %s:%d (sniffed src=%d dst=%d) -> swapping to src=%d dst=%d\n",
				port, src.IP, src.Port, srcCID, dstCID, dstCID, srcCID)
			srcCID, dstCID = dstCID, srcCID
			dst = peers[dstCID]
			if dst == nil {
				dst = resolvePeer(dstCID)
			}
		}
		if dst == nil {
			fmt.Printf("[NNCS] :%d relay no endpoint for cid=%d (src cid=%d from %s:%d) — dropped\n", port, dstCID, srcCID, src.IP, src.Port)
			continue
		}
		if sameUDPAddr(dst, src) {
			// A genuine self-targeted packet (a station keep a socket sends to its
			// own station URL, which is this relay). Nothing to do.
			continue
		}
		if _, err := conn.WriteToUDP(buf[:n], dst); err != nil {
			fmt.Printf("[NNCS] :%d relay forward %s -> %s failed: %v\n", port, src, dst, err)
			continue
		}
		// The punch/connection setup is a handful of packets and is the whole point
		// of the relay — say so when it moves. DATA/PING stay silent.
		if pktType == 0 || pktType == 1 {
			fmt.Printf("[NNCS] :%d relay fwd type=%d cid %d -> %d: %s:%d -> %s\n",
				port, pktType, srcCID, dstCID, src.IP, src.Port, dst)
		}
	}
}

// sameUDPAddr reports whether two UDP addresses denote the same endpoint.
func sameUDPAddr(a, b *net.UDPAddr) bool {
	return a != nil && b != nil && a.Port == b.Port && a.IP.Equal(b.IP)
}

func zncHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("[ZNC] %s %s from %s\n", r.Method, r.URL.Path, r.RemoteAddr)
	// Bound and drain the body on this public :443 handler; do NOT log full
	// headers/body (they can carry tokens — the request line is enough).
	_, _ = io.Copy(io.Discard, http.MaxBytesReader(w, r.Body, 64<<10))
	_ = r.Body.Close()

	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<GetTokenResponse>
  <AccessToken>dGVzdF9hY2Nlc3NfdG9rZW4=</AccessToken>
  <ServerURL>https://friends.nintendo.net</ServerURL>
</GetTokenResponse>`))
}

func main() {
	if effectiveAccessKey == "" || len(effectiveAccessKey) < 8 {
		fmt.Println("[LM3] FATAL: NEX access key not set.")
		fmt.Println("[LM3] Recover it from the binary (re/LM3_NETWORKING.md §6), then either:")
		fmt.Println("        set LM3_ACCESS_KEY=........")
		fmt.Println("      or edit the const accessKey in main.go")
		fmt.Println("[LM3] Refusing to listen with a bogus key (PRUDP would only confuse captures).")
		os.Exit(1)
	}

	// Fail fast rather than fall back to the public default Kerberos password: a server
	// silently running on "securepasswordplz1" would let anyone who knows that value forge
	// tickets. Force a strong, per-deployment NEXTENDO_SECURE_PASSWORD (auth+secure share it).
	if securePassword == "" {
		fmt.Println("[LM3] FATAL: NEXTENDO_SECURE_PASSWORD is not set.")
		fmt.Println("[LM3] Set it to a strong per-deployment secret and restart.")
		os.Exit(1)
	}

	// Debounce NAT-observation disk writes off the UDP packet path.
	go natFileFlusher()

	// The natbridge (in nextendo-nex) reads the observations via the NNCS_NAT_FILE
	// env var; without it the bridge falls back to the Linux path /data/nat_endpoints.txt
	// and misses on Windows, so the bridge SKIPs and peers get raw unreachable urls.
	os.Setenv("NNCS_NAT_FILE", nncsNatFile)
	os.Setenv("NNCS_TYPE_FILE", nncsTypeFile)

	// Embedded friends mode: when LM3_FRIENDS_FILE is set and the user did not point
	// at a real nextendo-account, the gates/friends HTTP calls (gates.go, friends.go)
	// hit this process's own dashboard server over loopback - one binary, no setup.
	if os.Getenv("NEXTENDO_ACCOUNT_URL") == "" && friendsFilePath != "" {
		accountBaseURL = "http://127.0.0.1:" + envOr("DASH_PORT", "8082")
		fmt.Printf("[Friends] embedded account endpoints (self) at %s\n", accountBaseURL)
	}

	settings := nex.NewSwitchSettings(effectiveAccessKey, nexVersion)

	secureURL := nex.NewStationURL("prudps")
	secureURL.Set("address", nextendoHost)
	secureURL.SetInt("port", securePort)
	secureURL.SetInt("CID", 1)
	secureURL.SetInt("PID", securePID)
	secureURL.SetInt("sid", 1)
	secureURL.SetInt("stream", 10)
	secureURL.SetInt("type", 2)

	// Split-horizon secure URL: a client that authenticates from a loopback address
	// (the operator's own emulator, no hairpin NAT needed) is told to reach the
	// secure server at 127.0.0.1; everyone else (friends over the internet) gets the
	// public NEXTENDO_HOST address. The station URL is swapped for the duration of
	// one auth RMC call under a mutex.
	localURL := nex.NewStationURL("prudps")
	localURL.Set("address", "127.0.0.1")
	localURL.SetInt("port", securePort)
	localURL.SetInt("CID", 1)
	localURL.SetInt("PID", securePID)
	localURL.SetInt("sid", 1)
	localURL.SetInt("stream", 10)
	localURL.SetInt("type", 2)

	var authMu sync.Mutex

	authEndpoint := nex.NewEndpoint(settings)
	authCfg := &nex.AuthConfig{
		Settings:         settings,
		SecurePID:        securePID,
		SecurePassword:   securePassword,
		SecureStationURL: secureURL,
		ServerName:       "Nextendo",
		SessionKeyLength: sessionKeyLen,
		ResolveUser:      resolveUser,
	}
	ticketGrantingHandler := authCfg.Handler()
	authEndpoint.Register(nex.ProtocolTicketGranting, func(c *nex.Connection, req *nex.RMCMessage) *nex.RMCMessage {
		authMu.Lock()
		if host, _, err := net.SplitHostPort(c.RemoteAddr); err == nil {
			if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
				authCfg.SecureStationURL = localURL
			} else {
				authCfg.SecureStationURL = secureURL
			}
		} else {
			authCfg.SecureStationURL = secureURL
		}
		resp := ticketGrantingHandler(c, req)
		authMu.Unlock()
		return resp
	})
	authEndpoint.RegisterFallback(func(c *nex.Connection, req *nex.RMCMessage) *nex.RMCMessage {
		fmt.Printf("[Auth Fallback] pid=%d %s call=%d bodyLen=%d body=%x\n",
			c.PID, rmcName(req.Protocol, req.Method), req.CallID, len(req.Body), req.Body)
		return nex.NewRMCSuccess(c.Settings, req.Protocol, req.Method, req.CallID, nil)
	})
	authEndpoint.OnRMC = logRMC("Auth")
	authEndpoint.OnConnect = func(c *nex.Connection) {
		fmt.Printf("[LM3 Auth] connected pid=%d id=%d addr=%s\n", c.PID, c.ID, c.RemoteAddr)
	}
	authServer := nex.NewServer(authEndpoint)
	authServer.CustomHTTPHandler = zncHandler

	secureSettings := nex.NewSwitchSettings(effectiveAccessKey, nexVersion)
	secureSettings.PrudpMinorVersion = 0
	secureEndpoint := nex.NewEndpoint(secureSettings)
	secureEndpoint.SetSecureAccount(securePassword, securePID)

	mm := nex.NewMatchmaking()
	// Friend list for MatchmakeExtension 9/10/13 (friends rooms): sourced from
	// nextendo-account's friend graph (see friends.go). nil when unconfigured.
	mm.FriendPIDs = accountFriendPIDs
	// Display name for method-15 friend entries (the "with friends" menu).
	mm.FriendName = dispName
	// LM3's host client never calls UpdateNotificationData (0x6D/9) itself: publish the
	// host's "room open" event on session create so friends see the room via m10/m13.
	// Layout is tunable via env (LM3_FRIEND_EVENT_TYPE / LM3_FRIEND_EVENT_MODE), see
	// publishFriendSession in friends.go.
	mm.OnFriendSessionCreated = func(pid uint64, gid uint32) {
		publishFriendSession(mm, pid, gid)
	}

	switch piaMode {
	case "switch", "519", "ssbu":
		fmt.Println("[LM3] SecureConnection: Switch/Pia5.19-style (type=0x0B + Pa)")
		secureEndpoint.Register(nex.ProtocolSecureConnection, nex.SecureConnectionHandler())
	default:
		fmt.Println("[LM3] SecureConnection: LegacyPia (type=0x03, no Pa) — Pia 5.17 default guess")
		legacyCfg := nex.LegacyPiaConfig()
		// Co-located-host correction (same switch as Splatoon 2): a host on this
		// machine probes via hairpin and reports its XLink Kai/VPN adapter address
		// (25.x) as its station — a candidate no peer can reach. Repoint such hosts
		// at the server's own public IP (NEXTENDO_HOST) so friends can actually join.
		if os.Getenv("NEXTENDO_COLOCATED_FIX") != "0" {
			legacyCfg.PublicHost = nextendoHost
			// Anchor the co-located host's station at a fixed UDP port that ALSO
			// answers the 16-byte probe format (the sinkhole now responds), so its
			// resolve job completes via hairpin instead of dying on 25.x.
			legacyCfg.P2PAnchorPort = nncsSinkhole1
		}
		if os.Getenv("NEXTENDO_RELAY") != "0" {
			// Relay mode: the server stands in for EVERY host's station so two NAT'd
			// players with no port forwarding can still talk. Both players' station
			// URLs (Register response + natbridge) point at the sinkhole port, and
			// nncsRelay forwards the PRUDP traffic between them there. Without this
			// the joiner's hole-punch to the host's real endpoint fails (rtt=0) and
			// the session dies at MatchMakingExt.
			legacyCfg.P2PRelay = true
			legacyCfg.PublicHost = nextendoHost
			legacyCfg.P2PAnchorPort = nncsSinkhole1
			nex.SetStationRelay(nextendoHost, nncsSinkhole1)
		}
		secureConnectionHandler := nex.SecureConnectionHandlerWithConfig(legacyCfg)
		secureEndpoint.Register(nex.ProtocolSecureConnection, func(c *nex.Connection, req *nex.RMCMessage) *nex.RMCMessage {
			resp := secureConnectionHandler(c, req)
			// Every client's Register RESPONSE is repointed at the anchor station so
			// its resolve job always has a probe-able target. The library's remote
			// path may substitute a stale nncs observation into the response port
			// (unreachable), and a client's own public IP is often unprobeable through
			// its router (no hairpin) — both fail the resolve. The sinkhole answers
			// the anchor probes with the client's own NAT'd port, which is exactly
			// the consistency check the resolve needs. A co-located host gets
			// loopback instead (no hairpin AND no internet needed).
			if req.Method == nex.MethodRegister || req.Method == nex.MethodRegisterEx {
				resp = rewriteRegisterResponse(c, resp)
			}
			return resp
		})
	}

	secureEndpoint.Register(nex.ProtocolMatchmakeExtension, mm.ExtensionHandler())
	// lm3 use protocol 0x15
	mmHandler := mm.MatchMakingHandler()
	secureEndpoint.Register(nex.ProtocolMatchMaking, func(c *nex.Connection, req *nex.RMCMessage) *nex.RMCMessage {
		switch req.Method {
		case 1, 3:
			return nex.NewRMCSuccess(c.Settings, 0x15, req.Method, req.CallID, nil)
		default:
			return mmHandler(c, req)
		}
	})
	secureEndpoint.Register(nex.ProtocolMatchMakingExt, mm.MatchMakingExtHandler())
	secureEndpoint.Register(nex.ProtocolNATTraversal, nex.NATTraversalHandler())
	secureEndpoint.Register(nex.ProtocolRanking, nex.RankingHandler())
	secureEndpoint.Register(nex.ProtocolUtility, nex.UtilityHandler())
	// lm3 uses 0x79 protocol during matchmaking, Method 14 to InitializeStation, Method 13 to UpdateState, and Method 5 to UpdateApplicationBuffer.
	secureEndpoint.Register(0x79, func(c *nex.Connection, req *nex.RMCMessage) *nex.RMCMessage {
		fmt.Printf("[LM3 Station] %s call=%d bodyLen=%d body=%x\n",
			rmcName(0x79, req.Method), req.CallID, len(req.Body), req.Body)
		switch req.Method {
		case 5:
			return nex.NewRMCSuccess(c.Settings, 0x79, req.Method, req.CallID, nil)
		case 13, 14:
			// Pia 5.17 parses the 0x79 station-list response with an explicit
			// little-endian parser (0x7100EC1F40/0x7100EC1440/0x7100EC15D0):
			//   u32 LE count
			//   per record: u8 state, u32 LE recordLen, u64 LE stationId,
			//                u32 LE mapCount, {u8 key, u16 LE len, value}*N
			// The stationId u64 packs a result code in its high 32 bits; the
			// client (0x7100EBF9C0) only accepts records where
			// (stationId >> 32)/1000 == 128 (keep station) or 111 (drop).
			// The record map: key 1 = station id (4 bytes LE), key 2 = station URL.
			// Only InitializeStation's response handler (method 14) is live on
			// the client (method 13's is a no-op), but the format is shared.
			resp := buildStationRecords(c.PID, mm, secureEndpoint)
			fmt.Printf("[LM3 Station] %s: %d records resp=%x\n",
				rmcName(0x79, req.Method), recordCount(resp), resp)
			return nex.NewRMCSuccess(c.Settings, 0x79, req.Method, req.CallID, resp)
		case 15:
			// GetStationLocation request: u32 count + u64 stationId * count
			// (+ trailing blob the client does not use). Answer per id:
			// known stations get code 128000 records, unknown get 111000 so
			// the client drops them from its station set.
			var ids []uint64
			if len(req.Body) >= 4 {
				in := nex.NewStreamIn(req.Body, c.Settings)
				cnt := in.U32()
				for i := 0; i < int(cnt) && in.Remaining() >= 8; i++ {
					ids = append(ids, in.U64())
				}
			}
			resp := buildStationRecordsFor(c.PID, mm, secureEndpoint, ids)
			fmt.Printf("[LM3 Station] %s: asked=%d ids=%v resp=%x\n",
				rmcName(0x79, req.Method), len(ids), ids, resp)
			return nex.NewRMCSuccess(c.Settings, 0x79, req.Method, req.CallID, resp)
		default:
			return nex.NewRMCSuccess(c.Settings, 0x79, req.Method, req.CallID, nil)
		}
	})

	logSecure := logRMC("Secure")
	secureEndpoint.OnRMC = func(c *nex.Connection, req *nex.RMCMessage) {
		logSecure(c, req)
		noteRMC(c, req)
		mm.TraceCall(c.PID, req.Protocol, req.Method, req.CallID, req.Body)
	}
	secureEndpoint.OnConnect = func(c *nex.Connection) {
		fmt.Printf("[LM3 Secure] connected pid=%d id=%d addr=%s\n", c.PID, c.ID, c.RemoteAddr)
	}
	secureEndpoint.OnDisconnect = func(c *nex.Connection) {
		mm.RemovePlayer(c.PID)
	}
	secureServer := nex.NewServer(secureEndpoint)

	secureEndpoint.StartReaper()
	go startDashboard(secureEndpoint, mm)
	go startPresenceReporter(secureEndpoint)
	go startPresenceReaper()

	go serveNNCS(nncsUDPPort1)
	go serveNNCS(nncsUDPPort2)
	go nncsRelay(nncsSinkhole1, secureEndpoint)
	go nncsSinkhole(nncsSinkhole2)
	fmt.Printf("[NNCS] NAT-check ports: %d, %d; sinkholes: %d, %d\n",
		nncsUDPPort1, nncsUDPPort2, nncsSinkhole1, nncsSinkhole2)
	fmt.Printf("[NNCS] NAT bridge file: %s\n", nncsNatFile)
	fmt.Printf("[NNCS] NAT type file: %s\n", nncsTypeFile)

	proxyProto := os.Getenv("NEXTENDO_PROXY_PROTOCOL") == "1"
	go func() {
		fmt.Printf("[LM3 Auth] listening WSS :%d (proxyProto=%v, secure URL -> %s)\n", authPort, proxyProto, secureURL.String())
		fmt.Printf("[LM3 Auth] title=%s accessKey=%s… piaMode=%s gameServerID=0x%08X\n", lm3AppID, effectiveAccessKey[:min(4, len(effectiveAccessKey))], piaMode, gameServerID)
		var err error
		if proxyProto {
			err = authServer.ListenSecureProxy(authPort, certFile, keyFile)
		} else {
			err = authServer.ListenSecure(authPort, certFile, keyFile)
		}
		if err != nil {
			fmt.Printf("[LM3 Auth] stopped: %v\n", err)
		}
	}()

	fmt.Printf("[LM3 Secure] listening WSS :%d\n", securePort)
	if err := secureServer.ListenSecure(securePort, certFile, keyFile); err != nil {
		fmt.Printf("[LM3 Secure] stopped: %v\n", err)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func resolveUser(username string, extraData []byte) (uint64, []byte, bool) {
	sk := sha256.Sum256([]byte("nextendo-src:" + username))
	sourceKey := sk[:]

	// 1. Signed nx2 token presented directly as the username.
	if pid, ok := nextendoPIDFromToken(username); ok {
		if allow, reason := nextendoOnlineCheck(pid, "ryujinx"); !allow {
			fmt.Printf("[Auth] pid=%d online refused (%s)\n", pid, reason)
			return 0, nil, false
		}
		return pid, sourceKey, true
	}

	// 2. Bare numeric PID. Emulator PIDs are SEQUENTIAL from 1800000000, so a bare PID
	// carries no proof: a custom build could send another member's PID and play as them
	// (and via the one-place-online gate, evict the real owner). We close that by reading
	// the signed nx2 token the emulator (>= 1.7.1) rides in the id_token's "nnex" claim
	// INSIDE the login extraData, and requiring it to prove EXACTLY the announced PID.
	// The enforce only targets the emulator range; a real CFW Switch (NSA >= 1810000000)
	// sends no nx2 and stays on resolveNSAtoPID, so legitimate consoles are never gated.
	if n, err := strconv.ParseUint(username, 10, 64); err == nil && n >= 1800000000 {
		provenPID, proven := uint64(0), false
		if tok, ok := nex.NexTokenFromLoginExtraData(extraData); ok {
			provenPID, proven = nextendoPIDFromToken(tok)
		}
		if n < 1810000000 {
			switch {
			case proven && provenPID == n:
				fmt.Printf("[Auth][bind] pid=%d OK: nx2 proves the PID\n", n)
			case proven && provenPID != n:
				fmt.Printf("[Auth][bind] pid=%d IMPERSONATION: nx2 proves %d, not %d\n", n, provenPID, n)
			default:
				fmt.Printf("[Auth][bind] pid=%d NO PROOF: no nx2 in extraData (build < 1.7.1?)\n", n)
			}
			if requireSignedToken() && !(proven && provenPID == n) {
				fmt.Printf("[Auth] pid=%d refused: identity not proven (signed nx2 token required)\n", n)
				return 0, nil, false
			}
		}
		pid, kind := n, "ryujinx"
		if n >= 1810000000 {
			kind = "switch"
			rp, st := resolveNSAtoPID(n)
			switch st {
			case nsaOK:
				pid = rp
				fmt.Printf("[Auth] NSA %d -> account pid=%d\n", n, pid)
			case nsaUnknown, nsaUnreachable:
				fmt.Printf("[Auth] NSA %d refused (%v)\n", n, st)
				return 0, nil, false
			}
		}
		if allow, reason := nextendoOnlineCheck(pid, kind); !allow {
			fmt.Printf("[Auth] pid=%d online refused (%s)\n", pid, reason)
			return 0, nil, false
		}
		return pid, sourceKey, true
	}

	if requireAccount {
		fmt.Printf("[Auth] anonymous refused: %q\n", username)
		return 0, nil, false
	}
	return anonymousPID(username), sourceKey, true
}

// revokedNexPayloads lists leaked nex_token payloads ("pid.username.expiry") that must be
// rejected even though their HMAC is valid. The 1.6.5 Windows release was packaged from a
// folder holding a live session (portable/nextendo_account.txt), so that exact token leaked
// to every downloader. The denylist kills it everywhere without rotating the shared secret
// (which would disconnect everyone). Keep in sync with nextendo-account and the sibling servers.
var revokedNexPayloads = map[string]bool{
	"1800000006.Kazuu.1787343209": true, // leaked in the 1.6.5-win release (Kazuu / PID 1800000006)
}

func nextendoPIDFromToken(s string) (uint64, bool) {
	if len(nextendoSecret) == 0 || !strings.HasPrefix(s, "nx2.") {
		return 0, false
	}
	parts := strings.Split(s[len("nx2."):], ".")
	if len(parts) != 2 {
		return 0, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return 0, false
	}
	mac := hmac.New(sha256.New, nextendoSecret)
	mac.Write([]byte("nex:" + string(raw)))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(parts[1])) {
		return 0, false
	}
	if revokedNexPayloads[string(raw)] { // leaked token (1.6.5-win) — rejected despite a valid signature
		return 0, false
	}
	f := strings.SplitN(string(raw), ".", 3)
	if len(f) != 3 {
		return 0, false
	}
	pid, err := strconv.ParseUint(f[0], 10, 64)
	if err != nil {
		return 0, false
	}
	if exp, err := strconv.ParseInt(f[2], 10, 64); err != nil || time.Now().Unix() > exp {
		return 0, false
	}
	return pid, true
}

func loadNextendoSecret() []byte {
	if v := os.Getenv("NEXTENDO_SECRET"); v != "" {
		return []byte(v)
	}
	path := envOr("NEXTENDO_SECRET_FILE", "nextendo_secret.key")
	if b, err := os.ReadFile(path); err == nil {
		if dec, derr := hex.DecodeString(strings.TrimSpace(string(b))); derr == nil && len(dec) >= 16 {
			return dec
		}
	}
	return nil
}

func anonymousPID(username string) uint64 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(username))
	return 1800000000 + uint64(h.Sum32()%100000000)
}

func logRMC(tag string) func(*nex.Connection, *nex.RMCMessage) {
	return func(c *nex.Connection, req *nex.RMCMessage) {
		fmt.Printf("[LM3 %s] pid=%d %s call=%d\n", tag, c.PID, rmcName(req.Protocol, req.Method), req.CallID)
	}
}

// rewriteRegisterResponse repoints the Register/RegisterEx response's public station
// url at the anchor (server public IP + sinkhole port, or loopback for a co-located
// host) so the client's resolve job can always probe it. Response layout: u32 result,
// u32 connection id, StationURL string.
func rewriteRegisterResponse(c *nex.Connection, resp *nex.RMCMessage) *nex.RMCMessage {
	if resp == nil || len(resp.Body) < 8 {
		return resp
	}
	addr := nextendoHost
	if host, _, err := net.SplitHostPort(c.RemoteAddr); err == nil {
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			addr = "127.0.0.1"
		}
	}
	in := nex.NewStreamIn(resp.Body, c.Settings)
	result := in.U32()
	cid := in.U32()
	url := in.String()
	if url == "" {
		return resp
	}
	newURL := stationAddrRe.ReplaceAllString(url, "address="+addr+";")
	newURL = stationPortRe.ReplaceAllString(newURL, "port="+strconv.Itoa(nncsSinkhole1)+";")
	if newURL == url {
		return resp
	}
	out := nex.NewStreamOut(c.Settings)
	out.U32(result)
	out.U32(cid)
	out.String(newURL)
	resp.Body = out.Bytes()
	return resp
}

var (
	stationAddrRe = regexp.MustCompile(`address=[^;]*;`)
	stationPortRe = regexp.MustCompile(`port=[^;]*;`)
)

// stationURLOfPID returns the public prudp station URL string registered by the
// given pid, or "" if none. Clients publish their station via SecureConnection
// Register; the library stores the URLs on the connection.
func stationURLOfPID(ep *nex.Endpoint, pid uint64) string {
	conn := ep.FindConnectionByPID(pid)
	if conn == nil {
		return ""
	}
	// Relay mode: the 0x79 mesh records must point at the server's relay socket —
	// the player's real endpoint is unreachable from the other NAT, and the port
	// matching below would otherwise pick the LAN station, which no peer can reach.
	if rHost, rPort, rOn := nex.StationRelay(); rOn {
		for _, u := range conn.Stations() {
			if u != nil && u.Get("address") == rHost && u.GetInt("port") == rPort {
				return u.String()
			}
		}
	}
	// The station on the NNCS-confirmed UDP port wins: that is the endpoint peers must
	// reach for the direct mesh connection. The public station Register synthesised from
	// the WSS source port (50529-style) is NOT the mesh listener; the host's ReplaceURL
	// station (reported after the NAT handshake) carries the real port.
	natPort := 0
	if host, _, err := net.SplitHostPort(conn.RemoteAddr); err == nil {
		if p, ok := nex.NatPortForIP(host); ok {
			natPort = p
		}
	}
	var fallback string
	for _, u := range conn.Stations() {
		if u == nil || u.Get("address") == "" {
			continue
		}
		if natPort > 0 && u.GetInt("port") == natPort {
			return u.String()
		}
		if fallback == "" {
			fallback = u.String()
		}
		if u.GetInt("type")&2 != 0 {
			fallback = u.String()
		}
	}
	return fallback
}

type stationRecord struct {
	stationID uint64 // client-side "station id" = server connection ID (RVCID), NOT PID
	url       string
}

// buildStationRecords builds the little-endian 0x79 station-record response the
// Pia 5.17 client parses. Records carry the participants' station ids and URLs.
func buildStationRecords(selfPID uint64, mm *nex.Matchmaking, ep *nex.Endpoint) []byte {
	return buildStationRecordsFor(selfPID, mm, ep, nil)
}

// buildStationRecordsFor builds the 0x79 record response. When ids is non-empty
// (GetStationLocation, method 15), only those station ids are answered: known
// ones get a 128000-code record, unknown ones a 111000-code record so the
// client drops them. When ids is nil (InitializeStation/UpdateState) every
// session member gets a record. The stationId u64 packs (code << 32) | id and
// the client (0x7100EBF9C0) accepts code 128000 (keep) / 111000 (drop).
//
// The station ids here are the SERVER CONNECTION IDs (RVCIDs), not PIDs. The
// client's Pia mesh uses RVCIDs everywhere: its own station id comes from the
// SecureConnection RegisterEx response (secureconnection.go:189 out.U32(conn.ID)),
// the participation notifications carry RVCID lists (0x%016x:... strings), and
// WaitHostStationId (0x7100F57440) only passes once the station table fed by
// these records contains the RVCID of the host it queried. PID-keyed records
// never match, so the joiner stalls at the mesh join forever.
const (
	stationCodeOK     = 128000
	stationCodeAbsent = 111000
)

func buildStationRecordsFor(selfPID uint64, mm *nex.Matchmaking, ep *nex.Endpoint, ids []uint64) []byte {
	if len(ids) == 0 {
		// The caller's own session members PLUS the stations of the caller's
		// FRIENDS who currently have a room open (in a gathering). The LM3
		// With-Friends screen is fed by these station records: the client
		// renders a friend's room only when this response carries that
		// friend's station, and the Pia mesh join (WaitHostStationId) needs
		// the host's RVCID in the station table. Friends with no room are
		// omitted so the screen keeps showing only friends with open rooms.
		pids := mm.SessionByPID(selfPID)
		if len(pids) == 0 {
			pids = []uint64{selfPID}
		}
		seen := map[uint64]bool{}
		recs := make([]stationRecord, 0, len(pids)+1)
		add := func(pid uint64) {
			if seen[pid] {
				return
			}
			seen[pid] = true
			conn := ep.FindConnectionByPID(pid)
			if conn == nil {
				return
			}
			if url := stationURLOfPID(ep, pid); url != "" {
				recs = append(recs, stationRecord{stationID: uint64(conn.ID), url: url})
			}
		}
		for _, pid := range pids {
			add(pid)
		}
		if mm.FriendPIDs != nil {
			for _, friend := range mm.FriendPIDs(selfPID) {
				if len(mm.SessionByPID(friend)) > 0 {
					add(friend)
				}
			}
		}
		add(selfPID)
		return encodeStationRecords(recs, stationCodeOK)
	}

	recs := make([]stationRecord, 0, len(ids))
	missing := make([]stationRecord, 0, len(ids))
	for _, id := range ids {
		sid := uint32(id)
		conn := ep.FindConnectionByID(sid)
		if conn == nil {
			// The m13 friend events (class 128000) carry the friend's PID
			// (not its RVCID) in the pid field; the client echoes that value
			// as the stationId of GetStationLocation. Fall back to a PID
			// lookup so the friend's own station record comes back.
			conn = ep.FindConnectionByPID(id)
		}
		if conn == nil {
			missing = append(missing, stationRecord{stationID: id})
			continue
		}
		if url := stationURLOfPID(ep, conn.PID); url != "" {
			recs = append(recs, stationRecord{stationID: id, url: url})
		} else {
			missing = append(missing, stationRecord{stationID: id})
		}
	}
	out := encodeStationRecords(recs, stationCodeOK)
	out = append(out, encodeStationRecords(missing, stationCodeAbsent)...)
	return out
}

// encodeStationRecords serializes records. Each record:
// u8 state(1), u32 recordLen, u64 (code<<32)|stationId,
// u32 mapCount, key1 (u8 1, u16 4, stationId u32), key2 (u8 2, u16 len, url).
func encodeStationRecords(recs []stationRecord, code uint32) []byte {
	put16 := func(b *[]byte, v uint16) {
		*b = append(*b, byte(v), byte(v>>8))
	}
	put32 := func(b *[]byte, v uint32) {
		*b = append(*b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
	}
	var body []byte
	put32(&body, uint32(len(recs)))
	for _, r := range recs {
		url := []byte(r.url)
		mapLen := 3 + 4 + 3 + len(url) // key1 (1+2+4) + key2 (1+2+len)
		recLen := 8 + 4 + mapLen
		body = append(body, 1) // station state
		put32(&body, uint32(recLen))
		stationID := (uint64(code) << 32) | (r.stationID & 0xFFFFFFFF)
		for i := 0; i < 8; i++ {
			body = append(body, byte(stationID>>(8*i)))
		}
		put32(&body, 2)        // map entries
		body = append(body, 1) // key 1: station id (4 bytes LE)
		put16(&body, 4)
		for i := 0; i < 4; i++ {
			body = append(body, byte(r.stationID>>(8*i)))
		}
		body = append(body, 2) // key 2: station URL
		put16(&body, uint16(len(url)))
		body = append(body, url...)
	}
	return body
}

func recordCount(b []byte) int {
	if len(b) < 4 {
		return 0
	}
	return int(b[0]) | int(b[1])<<8 | int(b[2])<<16 | int(b[3])<<24
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envOrInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func requireSignedToken() bool {
	v := os.Getenv("NEXTENDO_REQUIRE_SIGNED_TOKEN")
	return v == "1" || v == "true"
}
