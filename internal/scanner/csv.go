package scanner

import (
	"bytes"
	"encoding/csv"
	"strconv"
)

// CSVHeader lists the exported columns.
var CSVHeader = []string{"IP", "Статус", "Имя хоста", "MAC", "Производитель", "Отклик (мс)", "Открытые порты"}

// DevicesToCSV renders devices as UTF-8 CSV with a byte order mark and CRLF
// line endings so that Excel opens it correctly.
func DevicesToCSV(devices []Device) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("\ufeff")
	w := csv.NewWriter(&buf)
	w.UseCRLF = true
	rows := [][]string{CSVHeader}
	for _, d := range devices {
		t := ""
		if d.Time >= 0 {
			t = strconv.FormatFloat(d.Time, 'f', -1, 64)
		}
		rows = append(rows, []string{d.IP, d.Status, d.Hostname, d.Mac, d.Vendor, t, d.PortsString()})
	}
	if err := w.WriteAll(rows); err != nil {
		return nil, err
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
