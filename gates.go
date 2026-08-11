package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

var (
	accountBaseURL = envOr("NEXTENDO_ACCOUNT_URL", "http://nextendo-account:8080")
	internalKey    = os.Getenv("NEXTENDO_INTERNAL_KEY")
	gateClient     = &http.Client{Timeout: 3 * time.Second}
)

func nextendoOnlineCheck(pid uint64, kind string) (bool, string) {
	body, _ := json.Marshal(map[string]any{"pid": pid, "kind": kind})
	req, err := http.NewRequest("POST", accountBaseURL+"/internal/online-check", bytes.NewReader(body))
	if err != nil {
		return true, ""
	}
	req.Header.Set("Content-Type", "application/json")
	if internalKey != "" {
		req.Header.Set("X-Internal-Key", internalKey)
	}
	resp, err := gateClient.Do(req)
	if err != nil {
		return true, "" // fail-open
	}
	defer resp.Body.Close()
	var out struct {
		Allow  bool   `json:"allow"`
		Reason string `json:"reason"`
	}
	if json.NewDecoder(resp.Body).Decode(&out) != nil {
		return true, ""
	}
	return out.Allow, out.Reason
}

type nsaStatus int

const (
	nsaOK nsaStatus = iota
	nsaUnknown
	nsaUnreachable
)

var (
	nsaCacheMu sync.Mutex
	nsaCache   = map[uint64]uint64{}
)

func resolveNSAtoPID(nsa uint64) (uint64, nsaStatus) {
	nsaCacheMu.Lock()
	if pid, ok := nsaCache[nsa]; ok {
		nsaCacheMu.Unlock()
		return pid, nsaOK
	}
	nsaCacheMu.Unlock()

	resp, err := gateClient.Get(fmt.Sprintf("%s/api/nsa?id=%d", accountBaseURL, nsa))
	if err != nil {
		return 0, nsaUnreachable
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return 0, nsaUnknown
	}
	if resp.StatusCode != http.StatusOK {
		return 0, nsaUnreachable
	}
	var out struct {
		PID uint64 `json:"pid"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.PID == 0 {
		return 0, nsaUnreachable
	}
	nsaCacheMu.Lock()
	nsaCache[nsa] = out.PID
	nsaCacheMu.Unlock()
	return out.PID, nsaOK
}
