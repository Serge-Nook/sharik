package scanner

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Device is a host discovered during a scan.
type Device struct {
	IP       string
	Status   string
	Hostname string
	Mac      string
	Vendor   string
	// Time is the ping round trip in milliseconds, negative when unknown.
	Time  float64
	Ports []int
}

// PortsString renders open ports as a space separated list.
func (d Device) PortsString() string {
	parts := make([]string, len(d.Ports))
	for i, p := range d.Ports {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, " ")
}

// Options configures a scan.
type Options struct {
	Range        string
	Concurrency  int
	PingTimeout  time.Duration
	PortTimeout  time.Duration
	ScanPorts    bool
	Ports        []int
	ResolveNames bool
}

// Progress reports how far a scan has advanced.
type Progress struct {
	Completed int
	Total     int
	Alive     int
}

// Result summarises a finished scan.
type Result struct {
	Total     int
	Alive     int
	Cancelled bool
	Devices   []Device
}

// Callbacks receive scan events. They are invoked from worker goroutines, so a
// GUI must marshal them onto its own thread.
type Callbacks struct {
	OnDevice   func(Device)
	OnProgress func(Progress)
}

func (o Options) normalized() Options {
	o.Concurrency = clampInt(o.Concurrency, 1, 512)
	o.PingTimeout = clampDuration(o.PingTimeout, 200*time.Millisecond, 10*time.Second)
	o.PortTimeout = clampDuration(o.PortTimeout, 100*time.Millisecond, 5*time.Second)
	if len(o.Ports) == 0 {
		o.Ports = COMMON_PORTS
	}
	return o
}

// Scan probes every address of the requested range and reports discovered hosts
// through the callbacks. Cancelling ctx stops the scan.
func Scan(ctx context.Context, opts Options, cb Callbacks) (Result, error) {
	targets, err := ParseTargets(opts.Range)
	if err != nil {
		return Result{}, err
	}
	opts = opts.normalized()

	localMacs := LocalMacs()
	var (
		mu        sync.Mutex
		devices   []Device
		completed int
		alive     int

		arpMu       sync.Mutex
		arp         = ArpTable()
		arpRefresh  time.Time
		arpInterval = time.Second
	)

	// macFor prefers the interface MAC when the address belongs to this machine,
	// because a host never appears in its own ARP table.
	macFor := func(ip string) string {
		if mac := localMacs[ip]; mac != "" {
			return mac
		}
		arpMu.Lock()
		defer arpMu.Unlock()
		if mac := arp[ip]; mac != "" {
			return mac
		}
		// pings should have populated the cache by now
		if time.Since(arpRefresh) > arpInterval {
			arpRefresh = time.Now()
			for k, v := range ArpTable() {
				arp[k] = v
			}
		}
		return arp[ip]
	}

	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup
	for _, ip := range targets {
		if ctx.Err() != nil {
			break // already started probes finish on their own
		}

		sem <- struct{}{}
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()

			if ctx.Err() != nil {
				return
			}

			ping := PingHost(ctx, ip, opts.PingTimeout)
			isAlive := ping.Alive
			var openPorts []int
			if opts.ScanPorts {
				openPorts = ScanPorts(ctx, ip, opts.Ports, opts.PortTimeout)
				if !isAlive && len(openPorts) > 0 {
					isAlive = true // host is up even when ICMP is blocked
				}
			}

			var device *Device
			if isAlive && ctx.Err() == nil {
				hostname := ""
				if opts.ResolveNames {
					hostname = ResolveName(ctx, ip)
				}
				mac := macFor(ip)
				device = &Device{
					IP:       ip,
					Status:   "up",
					Hostname: hostname,
					Mac:      mac,
					Vendor:   VendorFromMac(mac),
					Time:     ping.Time,
					Ports:    openPorts,
				}
			}

			mu.Lock()
			completed++
			if device != nil {
				alive++
				devices = append(devices, *device)
			}
			progress := Progress{Completed: completed, Total: len(targets), Alive: alive}
			mu.Unlock()

			if device != nil && cb.OnDevice != nil {
				cb.OnDevice(*device)
			}
			if cb.OnProgress != nil {
				cb.OnProgress(progress)
			}
		}(ip)
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	sort.Slice(devices, func(i, j int) bool {
		a, _ := IPToInt(devices[i].IP)
		b, _ := IPToInt(devices[j].IP)
		return a < b
	})
	return Result{
		Total:     len(targets),
		Alive:     len(devices),
		Cancelled: ctx.Err() != nil,
		Devices:   devices,
	}, nil
}

func clampInt(v, min, max int) int {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func clampDuration(v, min, max time.Duration) time.Duration {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}
