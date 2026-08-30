package scanner

import (
	"encoding/json"
	"strings"
	"sync"
)

var (
	ouiMu   sync.RWMutex
	ouiRaw  []byte
	ouiMap  map[string]string
	ouiRead bool
)

// SetOUIData installs the OUI database used by VendorFromMac. The payload is the
// JSON object from assets/oui.json, keyed by the first six hex digits of a MAC.
// It is parsed on first lookup.
func SetOUIData(data []byte) {
	ouiMu.Lock()
	defer ouiMu.Unlock()
	ouiRaw = data
	ouiMap = nil
	ouiRead = false
}

func ouiTable() map[string]string {
	ouiMu.RLock()
	if ouiRead {
		defer ouiMu.RUnlock()
		return ouiMap
	}
	ouiMu.RUnlock()

	ouiMu.Lock()
	defer ouiMu.Unlock()
	if !ouiRead {
		ouiRead = true
		ouiMap = map[string]string{}
		if len(ouiRaw) > 0 {
			if err := json.Unmarshal(ouiRaw, &ouiMap); err != nil {
				ouiMap = map[string]string{}
			}
		}
	}
	return ouiMap
}

// VendorFromMac resolves a hardware vendor from the OUI part of a MAC address.
func VendorFromMac(mac string) string {
	if mac == "" {
		return ""
	}
	key := strings.ToUpper(strings.NewReplacer(":", "", "-", "", ".", "").Replace(mac))
	if len(key) < 6 {
		return ""
	}
	return ouiTable()[key[:6]]
}
