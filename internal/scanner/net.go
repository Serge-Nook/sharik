package scanner

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

// COMMON_PORTS is the default port set probed when no custom list is given.
var COMMON_PORTS = []int{21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 587, 993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 8080, 8443}

// PingResult reports whether a host answered ICMP and its round trip time.
type PingResult struct {
	Alive bool
	// Time is the round trip time in milliseconds, negative when unknown.
	Time float64
}

var pingTimeRe = regexp.MustCompile(`(?i)time[=<]\s*([\d.,]+)\s*ms`)

// PingHost probes a host with the system ping utility.
func PingHost(ctx context.Context, ip string, timeout time.Duration) PingResult {
	ms := int(timeout / time.Millisecond)
	var args []string
	switch runtime.GOOS {
	case "windows":
		args = []string{"-n", "1", "-w", strconv.Itoa(ms), ip}
	case "darwin":
		args = []string{"-c", "1", "-W", strconv.Itoa(ms), ip}
	default:
		// linux: -W takes whole seconds
		secs := (ms + 999) / 1000
		if secs < 1 {
			secs = 1
		}
		args = []string{"-c", "1", "-W", strconv.Itoa(secs), ip}
	}

	cmdCtx, cancel := context.WithTimeout(ctx, timeout+1500*time.Millisecond)
	defer cancel()

	out, err := exec.CommandContext(cmdCtx, "ping", args...).Output()
	if err != nil {
		return PingResult{Time: -1}
	}
	res := PingResult{Alive: true, Time: -1}
	if m := pingTimeRe.FindSubmatch(out); m != nil {
		if v, err := strconv.ParseFloat(strings.Replace(string(m[1]), ",", ".", 1), 64); err == nil {
			res.Time = v
		}
	}
	return res
}

// CheckPort reports whether a TCP port accepts connections.
func CheckPort(ctx context.Context, ip string, port int, timeout time.Duration) bool {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// ScanPorts probes the given ports on a host and returns the open ones, sorted.
func ScanPorts(ctx context.Context, ip string, ports []int, timeout time.Duration) []int {
	type result struct {
		port int
		open bool
	}
	ch := make(chan result, len(ports))
	for _, p := range ports {
		go func(p int) {
			ch <- result{p, CheckPort(ctx, ip, p, timeout)}
		}(p)
	}
	var open []int
	for range ports {
		if r := <-ch; r.open {
			open = append(open, r.port)
		}
	}
	sort.Ints(open)
	return open
}

// ResolveName performs a reverse DNS lookup, returning an empty string on failure.
func ResolveName(ctx context.Context, ip string) string {
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

var (
	macRe = regexp.MustCompile(`(?i)([0-9a-f]{2}[:-]){5}[0-9a-f]{2}`)
	ipRe  = regexp.MustCompile(`(\d{1,3}\.){3}\d{1,3}`)
)

func normalizeMac(mac string) string {
	return strings.ToUpper(strings.ReplaceAll(mac, "-", ":"))
}

// ArpTable returns the current IP to MAC mapping known to the operating system.
func ArpTable() map[string]string {
	table := map[string]string{}
	if runtime.GOOS == "linux" {
		if f, err := os.Open("/proc/net/arp"); err == nil {
			defer f.Close()
			sc := bufio.NewScanner(f)
			sc.Scan() // header
			for sc.Scan() {
				cols := strings.Fields(sc.Text())
				if len(cols) >= 4 && cols[3] != "00:00:00:00:00:00" {
					table[cols[0]] = normalizeMac(cols[3])
				}
			}
			return table
		}
	}

	out, err := exec.Command("arp", "-a").Output()
	if err != nil {
		return table
	}
	for _, line := range strings.Split(string(out), "\n") {
		ipM := ipRe.FindString(line)
		macM := macRe.FindString(line)
		if ipM != "" && macM != "" {
			table[ipM] = normalizeMac(macM)
		}
	}
	return table
}

// LocalRange describes an IPv4 address of a local network interface.
type LocalRange struct {
	Iface   string
	Address string
	CIDR    string
	Mac     string
}

// LocalRanges lists the non-loopback IPv4 addresses of local interfaces
// together with the hardware address of the owning interface.
func LocalRanges() []LocalRange {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var ranges []LocalRange
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.To4() == nil || ipNet.IP.IsLoopback() {
				continue
			}
			ones, _ := ipNet.Mask.Size()
			if ones == 0 {
				ones = 24
			}
			ranges = append(ranges, LocalRange{
				Iface:   iface.Name,
				Address: ipNet.IP.String(),
				CIDR:    fmt.Sprintf("%s/%d", ipNet.IP.String(), ones),
				Mac:     normalizeMac(iface.HardwareAddr.String()),
			})
		}
	}
	return ranges
}

// LocalMacs maps every local IPv4 address to the MAC of its interface. The
// operating system does not list its own addresses in the ARP table, so this is
// the only way to report MAC and vendor for the machine running the scan.
func LocalMacs() map[string]string {
	macs := map[string]string{}
	for _, r := range LocalRanges() {
		if r.Mac != "" {
			macs[r.Address] = r.Mac
		}
	}
	return macs
}
