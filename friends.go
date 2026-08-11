package main


import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	nex "github.com/NextendoNetwork/nextendo-nex"
)




var friendsFilePath = os.Getenv("LM3_FRIENDS_FILE")



type presenceEntry struct {
	Status int 
	AppID  string
	At     time.Time
}

var (
	presenceMu    sync.RWMutex
	presenceByPID = map[uint64]presenceEntry{}
)


const presenceTTL = 90 * time.Second

func setPresence(pid uint64, status int, appID string) {
	presenceMu.Lock()
	presenceByPID[pid] = presenceEntry{Status: status, AppID: appID, At: time.Now()}
	presenceMu.Unlock()
}

func getPresence(pid uint64) (presenceEntry, bool) {
	presenceMu.RLock()
	e, ok := presenceByPID[pid]
	presenceMu.RUnlock()
	if !ok || time.Since(e.At) > presenceTTL {
		return presenceEntry{}, false
	}
	return e, true
}


type fileFriendCache struct {
	mtime  time.Time
	size   int64
	byPID  map[uint64][]uint64
	loaded bool
}

var (
	fileCacheMu sync.Mutex
	fileCache   fileFriendCache
)


func friendFilePIDs(pid uint64) ([]uint64, bool) {
	fileCacheMu.Lock()
	defer fileCacheMu.Unlock()

	st, err := os.Stat(friendsFilePath)
	if err != nil {
		if !fileCache.loaded {
			friendsWarn("LM3_FRIENDS_FILE %q: %v", friendsFilePath, err)
			fileCache.loaded = true
		}
		return nil, false
	}
	if !fileCache.loaded || !st.ModTime().Equal(fileCache.mtime) || st.Size() != fileCache.size {
		b, err := os.ReadFile(friendsFilePath)
		if err != nil {
			friendsWarn("LM3_FRIENDS_FILE %q: %v", friendsFilePath, err)
			fileCache = fileFriendCache{loaded: true}
			return nil, false
		}
		m := map[string][]uint64{}
		if err := json.Unmarshal(b, &m); err != nil {
			friendsWarn("LM3_FRIENDS_FILE %q: bad JSON: %v", friendsFilePath, err)
			fileCache = fileFriendCache{loaded: true}
			return nil, false
		}
		byPID := make(map[uint64][]uint64, len(m))
		for k, v := range m {
			if p, perr := strconv.ParseUint(k, 10, 64); perr == nil {
				byPID[p] = v
			}
		}
		fileCache = fileFriendCache{mtime: st.ModTime(), size: st.Size(), byPID: byPID, loaded: true}
		fmt.Printf("[Friends] loaded %d friend lists from %s\n", len(byPID), friendsFilePath)
	}
	pids, ok := fileCache.byPID[pid]
	return pids, ok
}


var stubFriendPIDs = map[uint64][]uint64{ // hardcoded friend pids
	1800002682: {1800000119}, 
	1800000119: {1800002682}, 
}

var (
	friendsCacheMu sync.Mutex
	friendsCache   = map[uint64]friendCacheEntry{}
	friendsWarned  = false
	stubNoticeOnce = false
)

const friendCacheTTL = 30 * time.Second

type friendCacheEntry struct {
	pids []uint64
	at   time.Time
}


func accountFriendPIDs(pid uint64) []uint64 {
	if os.Getenv("NEXTENDO_ACCOUNT_URL") == "" && friendsFilePath == "" {
		if !stubNoticeOnce {
			stubNoticeOnce = true
			fmt.Println("[Friends] built-in test friends active (Chop<->Mars): set NEXTENDO_ACCOUNT_URL to use a real account service")
		}
		pids, ok := stubFriendPIDs[pid]
		if !ok {
			return nil
		}
		return pids
	}
	if accountBaseURL == "" {
		return nil
	}
	friendsCacheMu.Lock()
	if e, ok := friendsCache[pid]; ok && time.Since(e.at) < friendCacheTTL {
		friendsCacheMu.Unlock()
		return e.pids
	}
	friendsCacheMu.Unlock()

	pids := accountFriendPIDsFetch(pid)

	friendsCacheMu.Lock()
	friendsCache[pid] = friendCacheEntry{pids: pids, at: time.Now()}
	friendsCacheMu.Unlock()
	return pids
}


func accountFriendPIDsFetch(pid uint64) []uint64 {
	req, err := http.NewRequest("GET", accountBaseURL+"/internal/npln-friends?pid="+strconv.FormatUint(pid, 10), nil)
	if err != nil {
		return nil
	}
	if internalKey != "" {
		req.Header.Set("X-Internal-Key", internalKey)
	}
	resp, err := gateClient.Do(req)
	if err != nil {
		friendsWarn("friends fetch pid=%d: %v", pid, err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		friendsWarn("friends fetch pid=%d: HTTP %d", pid, resp.StatusCode)
		return nil
	}
	var out struct {
		Friends []struct {
			PID uint64 `json:"pid"`
		} `json:"friends"`
	}
	if json.NewDecoder(resp.Body).Decode(&out) != nil {
		friendsWarn("friends fetch pid=%d: bad JSON", pid)
		return nil
	}
	if len(out.Friends) > 0 {
		fmt.Printf("[Friends] pid=%d has %d friends\n", pid, len(out.Friends))
	}
	pids := make([]uint64, 0, len(out.Friends))
	for _, f := range out.Friends {
		if f.PID != 0 {
			pids = append(pids, f.PID)
		}
	}
	return pids
}


func friendsWarn(format string, args ...any) {
	friendsCacheMu.Lock()
	first := !friendsWarned
	friendsWarned = true
	friendsCacheMu.Unlock()
	if first {
		fmt.Printf("[Friends] bridge warning: %s\n", format)
	}
}




func registerAccountEndpoints(mux *http.ServeMux) {
	mux.HandleFunc("/internal/npln-friends", accountNplnFriends)
	mux.HandleFunc("/internal/presence-batch", accountPresenceBatch)
	mux.HandleFunc("/internal/online-check", accountOnlineCheck)
	if friendsFilePath != "" {
		fmt.Printf("[Friends] embedded account endpoints active (friend file: %s)\n", friendsFilePath)
	}
}


func accountGuard(w http.ResponseWriter, r *http.Request) bool {
	if internalKey != "" {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Internal-Key")), []byte(internalKey)) != 1 {
			http.Error(w, "forbidden", http.StatusForbidden)
			return false
		}
	}
	return true
}


func accountNplnFriends(w http.ResponseWriter, r *http.Request) {
	if !accountGuard(w, r) {
		return
	}
	pid, err := strconv.ParseUint(r.URL.Query().Get("pid"), 10, 64)
	if err != nil || pid == 0 {
		http.Error(w, "bad pid", http.StatusBadRequest)
		return
	}
	pids, ok := friendFilePIDs(pid)
	if !ok {
		http.NotFound(w, r)
		return
	}
	friends := make([]map[string]any, 0, len(pids))
	for _, fpid := range pids {
		f := map[string]any{"pid": fpid, "name": dispName(fpid)}
		if p, ok := getPresence(fpid); ok {
			f["presence"] = map[string]any{"status": p.Status, "app_id": p.AppID}
		}
		friends = append(friends, f)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"pid":      pid,
		"verified": true,
		"friends":  friends,
	})
}


func accountPresenceBatch(w http.ResponseWriter, r *http.Request) {
	if !accountGuard(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST expected", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var in struct {
		Status int      `json:"status"`
		AppId  string   `json:"appId"`
		Pids   []uint64 `json:"pids"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		http.Error(w, "bad JSON", http.StatusBadRequest)
		return
	}
	if in.Status == 0 {
		in.Status = 2
	}
	const maxPresenceBatch = 5000
	if len(in.Pids) > maxPresenceBatch {
		in.Pids = in.Pids[:maxPresenceBatch]
	}
	for _, p := range in.Pids {
		setPresence(p, in.Status, in.AppId)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "n": len(in.Pids)})
}


func accountOnlineCheck(w http.ResponseWriter, r *http.Request) {
	if !accountGuard(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST expected", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var in struct {
		PID uint64 `json:"pid"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.PID == 0 {
		http.Error(w, "bad pid", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"allow": true})
}


func publishFriendSession(mm *nex.Matchmaking, pid uint64, gid uint32) {
	types := friendEventTypes()
	mode := os.Getenv("LM3_FRIEND_EVENT_MODE")
	for _, typ := range types {
		ev := &nex.NotificationEvent{PIDSource: pid, Type: typ, Param1: uint64(gid), Param2: 1}
		switch mode {
		case "param2":
			ev.Param1, ev.Param2 = 0, uint64(gid)
		case "str":
			ev.Param1, ev.Param2, ev.StrParam = 0, 1, fmt.Sprintf("%d", gid)
		}
		mm.PublishNotification(pid, typ, ev)
	}
	fmt.Printf("[Friends] auto-published pid=%d gid=%d types=%v mode=%q\n", pid, gid, types, mode)
}



func friendEventTypes() []uint32 {
	raw := os.Getenv("LM3_FRIEND_EVENT_TYPE")
	if raw == "" {
		return []uint32{111000, 128000}
	}
	var out []uint32
	for _, p := range strings.Split(raw, ",") {
		if v, err := strconv.ParseUint(strings.TrimSpace(p), 10, 32); err == nil {
			out = append(out, uint32(v))
		}
	}
	if len(out) == 0 {
		out = []uint32{101}
	}
	return out
}


func startPresenceReporter(endpoint *nex.Endpoint) {
	if accountBaseURL == "" || (os.Getenv("NEXTENDO_ACCOUNT_URL") == "" && friendsFilePath == "") {
		
		return
	}
	fmt.Printf("[Friends] presence reporter -> %s (key=%v)\n", accountBaseURL, internalKey != "")
	for {
		time.Sleep(30 * time.Second)
		conns := endpoint.SnapshotConnections()
		pids := make([]uint64, 0, len(conns))
		seen := map[uint64]bool{}
		for _, c := range conns {
			if c.PID != 0 && !seen[c.PID] {
				seen[c.PID] = true
				pids = append(pids, c.PID)
			}
		}
		if len(pids) == 0 {
			continue
		}
		body, _ := json.Marshal(map[string]any{"status": 2, "appId": lm3AppID, "pids": pids})
		req, err := http.NewRequest("POST", accountBaseURL+"/internal/presence-batch", bytes.NewReader(body))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		if internalKey != "" {
			req.Header.Set("X-Internal-Key", internalKey)
		}
		resp, err := gateClient.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
	}
}
