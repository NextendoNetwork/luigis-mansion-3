package main


import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	nex "github.com/NextendoNetwork/nextendo-nex"
)

var (
	dashStart = time.Now()

	metaMu        sync.Mutex
	playerMeta    = map[uint64]*playerInfo{}
	sessionsSeen  int64
	peakConnected int

	rmcTotal int64

	eventsMu    sync.Mutex
	events      []rmcEvent 
	methodCount = map[string]int64{}
)

type playerInfo struct {
	PID        uint64
	FirstSeen  time.Time
	LastSeen   time.Time
	IP         string
	Calls      int64
	LastProto  uint16
	LastMethod uint32
}

type rmcEvent struct {
	T      time.Time
	PID    uint64
	Proto  uint16
	Method uint32
}


func noteRMC(c *nex.Connection, req *nex.RMCMessage) {
	pid := c.PID
	if pid == 0 {
		return
	}
	atomic.AddInt64(&rmcTotal, 1)

	metaMu.Lock()
	pi := playerMeta[pid]
	if pi == nil {
		pi = &playerInfo{PID: pid, FirstSeen: time.Now()}
		playerMeta[pid] = pi
		sessionsSeen++
	}
	pi.LastSeen = time.Now()
	pi.Calls++
	pi.LastProto = req.Protocol
	pi.LastMethod = req.Method
	if c.RemoteAddr != "" {
		pi.IP = c.RemoteAddr
	}
	metaMu.Unlock()

	eventsMu.Lock()
	events = append(events, rmcEvent{T: time.Now(), PID: pid, Proto: req.Protocol, Method: req.Method})
	if len(events) > 100 {
		events = events[len(events)-100:]
	}
	methodCount[rmcName(req.Protocol, req.Method)]++
	eventsMu.Unlock()
}


func gameModeName(mode uint32) string {
	switch mode {
	case 1:
		return "Course"
	case 2:
		return "Course (Ã©quipe)"
	case 3:
		return "Bataille"
	case 4:
		return "Bataille (Ã©quipe)"
	default:
		return fmt.Sprintf("Mode %d", mode)
	}
}

func rmcName(proto uint16, method uint32) string {
	pn := map[uint16]string{
		0x0A: "TicketGranting", 0x0B: "SecureConnection", 0x6E: "Utility",
		0x70: "Ranking", 0x6D: "MatchmakeExt", 0x15: "MatchMaking",
		0x32: "MatchMakingExt", 0x03: "NATTraversal", 0x0E: "Notifications",
	}[proto]
	if pn == "" {
		pn = fmt.Sprintf("Proto-0x%X", proto)
	}
	mn := ""
	switch proto {
	case 0x0A:
		mn = map[uint32]string{1: "Login", 2: "LoginEx", 3: "RequestTicket"}[method]
	case 0x0B:
		mn = map[uint32]string{1: "Register", 4: "RegisterEx", 7: "ReplaceURL"}[method]
	case 0x6E:
		mn = map[uint32]string{1: "AcquireNexUniqueID", 7: "GetIntegerSettings", 8: "GetStringSettings"}[method]
	case 0x70:
		mn = map[uint32]string{1: "UploadScore", 4: "UploadCommonData", 6: "GetCommonData"}[method]
	case 0x6D:
		mn = map[uint32]string{
			0x26: "CreateMatchmakeSessionWithParam", 0x27: "JoinMatchmakeSessionWithParam",
			0x28: "AutoMatchmakeWithParamPostpone", 0x22: "UpdateProgressScore",
			0x31: "FindMatchmakeSessionBySingleID", 0x3C: "GetSimplePlayingSession",
			0x44: "PrivateRoomCreate", 0x45: "ResolveCode",
		}[method]
	case 0x15:
		mn = map[uint32]string{0x02: "UnregisterGathering", 0x29: "GetSessionURLs", 0x15: "FindBySingleID"}[method]
	case 0x32:
		mn = map[uint32]string{0x01: "EndParticipation"}[method]
	case 0x03:
		mn = map[uint32]string{2: "InitiateProbe", 3: "RequestProbeInitiationExt", 5: "ReportNATProperties"}[method]
	case 0x79:
		mn = map[uint32]string{5: "UpdateApplicationBuffer", 13: "UpdateState", 14: "InitializeStation"}[method]
	}
	if mn == "" {
		mn = fmt.Sprintf("m%d", method)
	}
	return pn + "::" + mn
}



type apiPlayer struct {
	PID        uint64 `json:"pid"`
	Name       string `json:"name"`
	IP         string `json:"ip"`
	State      string `json:"state"`
	Gathering  uint32 `json:"gathering"`
	OnlineSecs int    `json:"onlineSeconds"`
	Calls      int64  `json:"calls"`
	LastAction string `json:"lastAction"`
	IdleSecs   int    `json:"idleSeconds"`
	VR         uint32 `json:"vr"`
	Mode       string `json:"mode"`
	IsHost     bool   `json:"isHost"`
}

type apiLobbyP struct {
	PID  uint64 `json:"pid"`
	Name string `json:"name"`
	VR   uint32 `json:"vr"`
	Host bool   `json:"host"`
}

type apiGathering struct {
	ID       uint32      `json:"id"`
	HostPID  uint64      `json:"hostPid"`
	HostName string      `json:"hostName"`
	Type     string      `json:"type"`
	Mode     uint32      `json:"mode"`
	VR       uint32      `json:"vr"`
	Players  []apiLobbyP `json:"players"`
	Count    int         `json:"count"`
	Max      uint16      `json:"max"`
	State    string      `json:"state"`
	Code     string      `json:"code,omitempty"`
}

type apiEvent struct {
	Ago    int    `json:"agoSeconds"`
	PID    uint64 `json:"pid"`
	Action string `json:"action"`
}

type apiMethod struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

type apiServer struct {
	AccessKey  string `json:"accessKey"`
	NexVersion string `json:"nexVersion"`
	AuthPort   string `json:"authPort"`
	SecurePort int    `json:"securePort"`
	SNIHost    string `json:"sniHost"`
	SessionKey int    `json:"sessionKeyLen"`
	Stack      string `json:"stack"`
}

type apiStats struct {
	ServerTime     string         `json:"serverTime"`
	UptimeSeconds  int            `json:"uptimeSeconds"`
	Connected      int            `json:"connected"`
	InLobby        int            `json:"inLobby"`
	ActiveLobbies  int            `json:"activeLobbies"`
	TotalSessions  int64          `json:"totalSessions"`
	TotalRMC       int64          `json:"totalRmc"`
	GatheringsMade int64          `json:"gatheringsMade"`
	PeakConnected  int            `json:"peakConnected"`
	Server         apiServer      `json:"server"`
	Players        []apiPlayer    `json:"players"`
	Gatherings     []apiGathering `json:"gatherings"`
	Events         []apiEvent     `json:"events"`
	Methods        []apiMethod    `json:"methods"`
}

func dispName(pid uint64) string { return fmt.Sprintf("Joueur-%d", pid%100000) }

func buildStats(endpoint *nex.Endpoint, mm *nex.Matchmaking) apiStats {
	conns := endpoint.SnapshotConnections()
	gaths := mm.Snapshot()

	
	type metaSnap struct {
		calls       int64
		first, last time.Time
		proto       uint16
		meth        uint32
		ip          string
	}
	metaMu.Lock()
	snap := make(map[uint64]metaSnap, len(playerMeta))
	for pid, pi := range playerMeta {
		snap[pid] = metaSnap{calls: pi.Calls, first: pi.FirstSeen, last: pi.LastSeen, proto: pi.LastProto, meth: pi.LastMethod, ip: pi.IP}
	}
	metaMu.Unlock()

	
	pidGathering := map[uint64]uint32{}
	pidMode := map[uint64]uint32{}
	pidVR := map[uint64]uint32{}
	pidIsHost := map[uint64]bool{}
	gs := make([]apiGathering, 0, len(gaths))
	for _, g := range gaths {
		if len(g.Participants) == 0 {
			continue
		}
		max := g.MaxPart
		if max == 0 {
			max = 12
		}
		state := "en recherche"
		if len(g.Participants) >= 2 {
			state = "appariÃ©"
		}
		lps := make([]apiLobbyP, 0, len(g.Participants))
		for _, p := range g.Participants {
			pidGathering[p] = g.ID
			pidMode[p] = g.GameMode
			pidVR[p] = g.VR
			host := p == g.HostPID
			if host {
				pidIsHost[p] = true
			}
			lps = append(lps, apiLobbyP{PID: p, Name: dispName(p), VR: g.VR, Host: host})
		}
		gs = append(gs, apiGathering{
			ID: g.ID, HostPID: g.HostPID, HostName: dispName(g.HostPID),
			Type: gameModeName(g.GameMode), Mode: g.GameMode, VR: g.VR,
			Players: lps, Count: len(g.Participants), Max: max, State: state, Code: g.Code,
		})
	}
	sort.Slice(gs, func(i, j int) bool { return gs[i].ID < gs[j].ID })

	
	players := make([]apiPlayer, 0, len(conns))
	inLobby := 0
	seen := map[uint64]bool{}
	for _, c := range conns {
		pid := c.PID
		if pid == 0 || seen[pid] {
			continue
		}
		seen[pid] = true
		s := snap[pid]
		online, idle, last := 0, 0, ""
		if !s.first.IsZero() {
			online = int(time.Since(s.first).Seconds())
			idle = int(time.Since(s.last).Seconds())
			last = rmcName(s.proto, s.meth)
		}
		ip := c.Addr
		if ip == "" {
			ip = s.ip
		}
		gid := pidGathering[pid]
		state := "en ligne"
		if gid != 0 {
			inLobby++
			state = "dans un lobby"
		}
		modeLabel := ""
		if m := pidMode[pid]; m != 0 {
			modeLabel = gameModeName(m)
		}
		players = append(players, apiPlayer{
			PID: pid, Name: dispName(pid), IP: ip, State: state, Gathering: gid,
			OnlineSecs: online, Calls: s.calls, LastAction: last, IdleSecs: idle,
			VR: pidVR[pid], Mode: modeLabel, IsHost: pidIsHost[pid],
		})
	}
	sort.Slice(players, func(i, j int) bool { return players[i].PID < players[j].PID })

	if len(players) > peakConnected {
		peakConnected = len(players)
	}

	
	eventsMu.Lock()
	ev := make([]apiEvent, 0, len(events))
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		ev = append(ev, apiEvent{Ago: int(time.Since(e.T).Seconds()), PID: e.PID, Action: rmcName(e.Proto, e.Method)})
	}
	ms := make([]apiMethod, 0, len(methodCount))
	for n, c := range methodCount {
		ms = append(ms, apiMethod{Name: n, Count: c})
	}
	eventsMu.Unlock()
	sort.Slice(ms, func(i, j int) bool { return ms[i].Count > ms[j].Count })

	return apiStats{
		ServerTime:     time.Now().Format("15:04:05"),
		UptimeSeconds:  int(time.Since(dashStart).Seconds()),
		Connected:      len(players),
		InLobby:        inLobby,
		ActiveLobbies:  len(gs),
		TotalSessions:  atomic.LoadInt64(&sessionsSeen),
		TotalRMC:       atomic.LoadInt64(&rmcTotal),
		GatheringsMade: int64(len(gs)),
		PeakConnected:  peakConnected,
		Server: apiServer{
			AccessKey: accessKey, NexVersion: "4.0.0", AuthPort: fmt.Sprintf("%d", authPort),
			SecurePort: securePort, SNIHost: envOr("NEXTENDO_SNI_HOST", ""), SessionKey: sessionKeyLen,
			Stack: "nextendo-nex",
		},
		Players:    players,
		Gatherings: gs,
		Events:     ev,
		Methods:    ms,
	}
}


func startDashboard(endpoint *nex.Endpoint, mm *nex.Matchmaking) {
	port := envOr("DASH_PORT", "8082")
	token := envOr("DASH_TOKEN", "")

	
	authed := func(w http.ResponseWriter, r *http.Request) bool {
		if token != "" && subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("key")), []byte(token)) == 1 {
			return true
		}
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		if !authed(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(buildStats(endpoint, mm))
	})

	mux.HandleFunc("/api/kick", func(w http.ResponseWriter, r *http.Request) {
		if !authed(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if pid, err := strconv.ParseUint(r.URL.Query().Get("pid"), 10, 64); err == nil && pid != 0 {
			_ = json.NewEncoder(w).Encode(map[string]any{"pid": pid, "kicked": endpoint.KickPID(pid)})
			return
		}
		if rv, err := strconv.ParseUint(r.URL.Query().Get("rvcid"), 10, 32); err == nil && rv != 0 {
			_ = json.NewEncoder(w).Encode(map[string]any{"rvcid": rv, "kicked": endpoint.KickConnection(uint32(rv))})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"reaped": endpoint.ReapIdle(nex.ReapIdleTimeout())})
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "ok") })


	registerAccountEndpoints(mux)

	fmt.Printf("[LM3 Dashboard] stats API on :%s (token=%v)\n", port, token != "")
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		fmt.Printf("[LM3 Dashboard] HTTP error: %v\n", err)
	}
}
