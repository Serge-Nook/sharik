package scanner

import (
	"fmt"
	"strconv"
	"strings"
)

// MaxTargets is the upper bound of addresses a single scan may cover.
const MaxTargets = 65536

// IPToInt converts a dotted-quad IPv4 address into its numeric form.
func IPToInt(ip string) (uint32, error) {
	parts := strings.Split(strings.TrimSpace(ip), ".")
	if len(parts) != 4 {
		return 0, fmt.Errorf("Некорректный IP: %s", ip)
	}
	var n uint32
	for _, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 || v > 255 {
			return 0, fmt.Errorf("Некорректный IP: %s", ip)
		}
		n = n<<8 | uint32(v)
	}
	return n, nil
}

// IntToIP converts a numeric IPv4 address into its dotted-quad form.
func IntToIP(n uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", n>>24&255, n>>16&255, n>>8&255, n&255)
}

// ParseTargets expands user input into a list of IPv4 addresses.
// Supported forms: single address, CIDR (a.b.c.d/n), range (a.b.c.d-a.b.c.d or
// a.b.c.d-<last octet>) and any combination of those separated by spaces,
// commas or semicolons.
func ParseTargets(input string) ([]string, error) {
	if strings.TrimSpace(input) == "" {
		return nil, fmt.Errorf("Пустой диапазон")
	}

	var out []string
	seen := make(map[string]bool)
	push := func(n uint32) error {
		ip := IntToIP(n)
		if !seen[ip] {
			if len(out) >= MaxTargets {
				return fmt.Errorf("Слишком большой диапазон (>%d адресов)", MaxTargets)
			}
			seen[ip] = true
			out = append(out, ip)
		}
		return nil
	}
	pushRange := func(start, end uint32) error {
		for n := start; ; n++ {
			if err := push(n); err != nil {
				return err
			}
			if n == end {
				return nil
			}
		}
	}

	for _, token := range strings.FieldsFunc(input, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == ',' || r == ';'
	}) {
		switch {
		case strings.Contains(token, "/"):
			base, bitsStr, _ := strings.Cut(token, "/")
			bits, err := strconv.Atoi(bitsStr)
			if err != nil || bits < 0 || bits > 32 {
				return nil, fmt.Errorf("Некорректная маска: %s", token)
			}
			baseInt, err := IPToInt(base)
			if err != nil {
				return nil, err
			}
			var mask uint32
			if bits > 0 {
				mask = ^uint32(0) << (32 - bits)
			}
			network := baseInt & mask
			broadcast := network | ^mask
			start, end := network, broadcast
			if bits <= 30 {
				// exclude network and broadcast addresses
				start, end = network+1, broadcast-1
			}
			if err := pushRange(start, end); err != nil {
				return nil, err
			}
		case strings.Contains(token, "-"):
			a, b, _ := strings.Cut(token, "-")
			startInt, err := IPToInt(a)
			if err != nil {
				return nil, err
			}
			var endInt uint32
			if strings.Contains(b, ".") {
				endInt, err = IPToInt(b)
				if err != nil {
					return nil, err
				}
			} else {
				last, err := strconv.Atoi(strings.TrimSpace(b))
				if err != nil || last < 0 || last > 255 {
					return nil, fmt.Errorf("Некорректный диапазон: %s", token)
				}
				endInt = startInt&0xffffff00 | uint32(last)
			}
			if endInt < startInt {
				return nil, fmt.Errorf("Конец диапазона меньше начала: %s", token)
			}
			if err := pushRange(startInt, endInt); err != nil {
				return nil, err
			}
		default:
			n, err := IPToInt(token)
			if err != nil {
				return nil, err
			}
			if err := push(n); err != nil {
				return nil, err
			}
		}
	}

	return out, nil
}

// ParsePorts reads a user supplied port list; an empty input yields nil.
func ParsePorts(input string) []int {
	var ports []int
	for _, tok := range strings.FieldsFunc(input, func(r rune) bool {
		return r == ' ' || r == '\t' || r == ',' || r == ';'
	}) {
		p, err := strconv.Atoi(tok)
		if err != nil || p <= 0 || p >= 65536 {
			continue
		}
		ports = append(ports, p)
	}
	return ports
}
