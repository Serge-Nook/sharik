package main

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/Serge-Nook/sharik/internal/scanner"
)

type column struct {
	title string
	key   string
	width float32
}

var columns = []column{
	{title: "IP-адрес", key: "ip", width: 150},
	{title: "Имя хоста", key: "hostname", width: 260},
	{title: "MAC-адрес", key: "mac", width: 170},
	{title: "Производитель", key: "vendor", width: 240},
	{title: "Отклик", key: "time", width: 100},
	{title: "Открытые порты", key: "ports", width: 220},
}

type ui struct {
	app fyne.App
	win fyne.Window

	rangeEntry   *widget.Entry
	concurrency  *widget.Entry
	pingTimeout  *widget.Entry
	portTimeout  *widget.Entry
	portsEntry   *widget.Entry
	filterEntry  *widget.Entry
	resolveNames *widget.Check
	scanPorts    *widget.Check
	portsRow     *fyne.Container
	portTimeCell *fyne.Container

	scanBtn   *widget.Button
	cancelBtn *widget.Button
	clearBtn  *widget.Button
	exportBtn *widget.Button

	progress *widget.ProgressBar
	status   *widget.Label
	count    *widget.Label
	table    *widget.Table

	mu       sync.Mutex
	devices  []scanner.Device
	visible  []scanner.Device
	progVal  scanner.Progress
	dirty    bool
	scanning bool
	cancel   context.CancelFunc

	sortKey string
	sortDir int
}

func newUI(a fyne.App) *ui {
	u := &ui{
		app:     a,
		win:     a.NewWindow(appTitle),
		sortKey: "ip",
		sortDir: 1,
	}
	u.build()
	u.win.Resize(fyne.NewSize(1180, 760))
	u.win.SetMaster()
	return u
}

func (u *ui) build() {
	u.rangeEntry = widget.NewEntry()
	u.rangeEntry.SetPlaceHolder("напр. 192.168.1.0/24 или 192.168.1.1-254")
	u.rangeEntry.OnSubmitted = func(string) { u.startScan() }

	u.concurrency = numberEntry("128")
	u.pingTimeout = numberEntry("1000")
	u.portTimeout = numberEntry("600")

	u.portsEntry = widget.NewEntry()
	u.portsEntry.SetPlaceHolder("напр. 22,80,443,3389 (пусто = типовые)")

	u.resolveNames = widget.NewCheck("Имена хостов (DNS)", nil)
	u.resolveNames.SetChecked(true)

	u.filterEntry = widget.NewEntry()
	u.filterEntry.SetPlaceHolder("Фильтр по IP / имени / MAC / производителю…")
	u.filterEntry.OnChanged = func(string) { u.refreshTable() }

	u.progress = widget.NewProgressBar()
	u.progress.Min, u.progress.Max = 0, 1
	u.status = widget.NewLabel("Готов к сканированию")
	u.count = widget.NewLabel("0 устройств")

	u.scanBtn = widget.NewButtonWithIcon("Сканировать", theme.MediaPlayIcon(), u.startScan)
	u.scanBtn.Importance = widget.HighImportance
	u.cancelBtn = widget.NewButtonWithIcon("Остановить", theme.MediaStopIcon(), u.cancelScan)
	u.cancelBtn.Importance = widget.DangerImportance
	u.cancelBtn.Disable()
	u.clearBtn = widget.NewButtonWithIcon("Очистить", theme.DeleteIcon(), u.clear)
	u.exportBtn = widget.NewButtonWithIcon("Экспорт CSV", theme.DownloadIcon(), u.exportCSV)
	u.exportBtn.Disable()
	localBtn := widget.NewButtonWithIcon("Моя сеть", theme.ComputerIcon(), u.fillLocalRange)
	aboutBtn := widget.NewButtonWithIcon("О программе", theme.InfoIcon(), u.showAbout)

	u.portTimeCell = container.NewVBox(widget.NewLabel("Таймаут порта (мс)"), u.portTimeout)
	u.portTimeCell.Hide()
	u.portsRow = container.NewBorder(nil, nil, widget.NewLabel("Порты"), nil, u.portsEntry)
	u.portsRow.Hide()
	u.scanPorts = widget.NewCheck("Сканировать порты", func(on bool) {
		if on {
			u.portsRow.Show()
			u.portTimeCell.Show()
		} else {
			u.portsRow.Hide()
			u.portTimeCell.Hide()
		}
	})

	u.buildTable()

	header := container.NewHBox(
		widget.NewRichTextFromMarkdown("## Шарик"),
		widget.NewLabel("Продвинутый сканер IP-адресов"),
	)

	rangeRow := container.NewBorder(nil, nil, widget.NewLabel("Диапазон IPv4"), localBtn, u.rangeEntry)

	options := container.NewHBox(
		container.NewVBox(widget.NewLabel("Потоки"), sizedEntry(u.concurrency, 90)),
		container.NewVBox(widget.NewLabel("Таймаут ping (мс)"), sizedEntry(u.pingTimeout, 110)),
		container.NewVBox(widget.NewLabel(""), u.resolveNames),
		container.NewVBox(widget.NewLabel(""), u.scanPorts),
		u.portTimeCell,
	)

	actions := container.NewHBox(u.scanBtn, u.cancelBtn, u.exportBtn, u.clearBtn, aboutBtn)

	top := container.NewVBox(
		header,
		rangeRow,
		options,
		u.portsRow,
		actions,
		u.progress,
		u.status,
		widget.NewSeparator(),
		container.NewBorder(nil, nil, nil, u.count, u.filterEntry),
	)

	footer := container.NewHBox(
		widget.NewLabel(fmt.Sprintf("%s v%s", appName, appVersion)),
		widget.NewLabel("·"),
		widget.NewLabel("Автор: "+appAuthor),
	)

	u.win.SetContent(container.NewBorder(top, footer, nil, nil, u.table))
}

func numberEntry(value string) *widget.Entry {
	e := widget.NewEntry()
	e.SetText(value)
	return e
}

func sizedEntry(e *widget.Entry, width float32) fyne.CanvasObject {
	wrap := container.NewGridWrap(fyne.NewSize(width, e.MinSize().Height), e)
	return wrap
}

// ---------- table ----------

func (u *ui) buildTable() {
	u.table = widget.NewTable(
		func() (int, int) {
			u.mu.Lock()
			defer u.mu.Unlock()
			return len(u.visible), len(columns)
		},
		func() fyne.CanvasObject {
			return newTableCell(u.showRowMenu)
		},
		func(id widget.TableCellID, o fyne.CanvasObject) {
			cell, ok := o.(*tableCell)
			if !ok {
				return
			}
			cell.row = id.Row
			u.mu.Lock()
			var text string
			if id.Row >= 0 && id.Row < len(u.visible) {
				text = cellText(u.visible[id.Row], id.Col)
			}
			u.mu.Unlock()
			cell.setText(text)
		},
	)
	u.table.ShowHeaderRow = true
	u.table.CreateHeader = func() fyne.CanvasObject {
		return widget.NewButton("", nil)
	}
	u.table.UpdateHeader = func(id widget.TableCellID, o fyne.CanvasObject) {
		btn, ok := o.(*widget.Button)
		if !ok || id.Col < 0 || id.Col >= len(columns) {
			return
		}
		col := columns[id.Col]
		title := col.title
		if u.sortKey == col.key {
			if u.sortDir > 0 {
				title += " ▲"
			} else {
				title += " ▼"
			}
		}
		btn.SetText(title)
		btn.Importance = widget.LowImportance
		btn.OnTapped = func() { u.sortBy(col.key) }
	}
	for i, c := range columns {
		u.table.SetColumnWidth(i, c.width)
	}
}

func cellText(d scanner.Device, col int) string {
	switch columns[col].key {
	case "ip":
		return d.IP
	case "hostname":
		return orDash(d.Hostname)
	case "mac":
		return orDash(d.Mac)
	case "vendor":
		return orDash(d.Vendor)
	case "time":
		if d.Time < 0 {
			return "—"
		}
		return strconv.FormatFloat(d.Time, 'f', -1, 64) + " мс"
	case "ports":
		return orDash(d.PortsString())
	}
	return ""
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func (u *ui) sortBy(key string) {
	u.mu.Lock()
	if u.sortKey == key {
		u.sortDir *= -1
	} else {
		u.sortKey, u.sortDir = key, 1
	}
	u.mu.Unlock()
	u.refreshTable()
}

// refreshTable recomputes the filtered and sorted rows. It must run on the Fyne
// thread.
func (u *ui) refreshTable() {
	query := strings.ToLower(strings.TrimSpace(u.filterEntry.Text))

	u.mu.Lock()
	list := make([]scanner.Device, 0, len(u.devices))
	for _, d := range u.devices {
		if query == "" || matchesFilter(d, query) {
			list = append(list, d)
		}
	}
	key, dir := u.sortKey, u.sortDir
	sort.SliceStable(list, func(i, j int) bool {
		return less(list[i], list[j], key) == (dir > 0)
	})
	u.visible = list
	total := len(u.devices)
	scanning := u.scanning
	u.mu.Unlock()

	u.count.SetText(fmt.Sprintf("%d устройств", total))
	if total == 0 || scanning {
		u.exportBtn.Disable()
	} else {
		u.exportBtn.Enable()
	}
	u.table.Refresh()
}

func matchesFilter(d scanner.Device, query string) bool {
	for _, v := range []string{d.IP, d.Hostname, d.Mac, d.Vendor, d.PortsString()} {
		if v != "" && strings.Contains(strings.ToLower(v), query) {
			return true
		}
	}
	return false
}

func less(a, b scanner.Device, key string) bool {
	switch key {
	case "ip":
		ai, _ := scanner.IPToInt(a.IP)
		bi, _ := scanner.IPToInt(b.IP)
		return ai < bi
	case "time":
		at, bt := a.Time, b.Time
		if at < 0 {
			at = 1 << 30 // unknown response times sort last
		}
		if bt < 0 {
			bt = 1 << 30
		}
		return at < bt
	case "ports":
		return len(a.Ports) < len(b.Ports)
	case "hostname":
		return strings.ToLower(a.Hostname) < strings.ToLower(b.Hostname)
	case "mac":
		return strings.ToLower(a.Mac) < strings.ToLower(b.Mac)
	case "vendor":
		return strings.ToLower(a.Vendor) < strings.ToLower(b.Vendor)
	}
	return false
}

// ---------- context menu ----------

func (u *ui) showRowMenu(row int, pos fyne.Position) {
	u.mu.Lock()
	if row < 0 || row >= len(u.visible) {
		u.mu.Unlock()
		return
	}
	d := u.visible[row]
	u.mu.Unlock()

	u.table.Select(widget.TableCellID{Row: row, Col: 0})

	copyItem := func(label, value string) *fyne.MenuItem {
		item := fyne.NewMenuItem(label, func() {
			u.app.Clipboard().SetContent(value)
			u.status.SetText(fmt.Sprintf("Скопировано: %s", value))
		})
		item.Disabled = value == ""
		return item
	}

	menu := fyne.NewMenu("",
		copyItem("Скопировать IP", d.IP),
		copyItem("Скопировать MAC", d.Mac),
		copyItem("Скопировать порты", d.PortsString()),
	)
	widget.ShowPopUpMenuAtPosition(menu, u.win.Canvas(), pos)
}

// ---------- actions ----------

func (u *ui) startScan() {
	u.mu.Lock()
	running := u.scanning
	u.mu.Unlock()
	if running {
		return
	}

	rangeText := strings.TrimSpace(u.rangeEntry.Text)
	if rangeText == "" {
		u.status.SetText("Укажите диапазон IP-адресов.")
		return
	}

	opts := scanner.Options{
		Range:        rangeText,
		Concurrency:  atoiOr(u.concurrency.Text, 128),
		PingTimeout:  time.Duration(atoiOr(u.pingTimeout.Text, 1000)) * time.Millisecond,
		PortTimeout:  time.Duration(atoiOr(u.portTimeout.Text, 600)) * time.Millisecond,
		ScanPorts:    u.scanPorts.Checked,
		Ports:        scanner.ParsePorts(u.portsEntry.Text),
		ResolveNames: u.resolveNames.Checked,
	}

	ctx, cancel := context.WithCancel(context.Background())

	u.mu.Lock()
	u.devices = nil
	u.visible = nil
	u.scanning = true
	u.cancel = cancel
	u.progVal = scanner.Progress{}
	u.mu.Unlock()

	u.setScanning(true)
	u.progress.SetValue(0)
	u.status.SetText("Подготовка…")
	u.refreshTable()

	stopTicker := u.startUpdateLoop()

	go func() {
		res, err := scanner.Scan(ctx, opts, scanner.Callbacks{
			OnDevice: func(d scanner.Device) {
				u.mu.Lock()
				u.devices = append(u.devices, d)
				u.dirty = true
				u.mu.Unlock()
			},
			OnProgress: func(p scanner.Progress) {
				u.mu.Lock()
				u.progVal = p
				u.dirty = true
				u.mu.Unlock()
			},
		})
		cancel()
		stopTicker()

		fyne.Do(func() {
			u.mu.Lock()
			u.scanning = false
			u.cancel = nil
			u.mu.Unlock()

			u.setScanning(false)
			if err != nil {
				u.progress.SetValue(0)
				u.status.SetText("Ошибка: " + err.Error())
			} else {
				verb := "Завершено"
				if res.Cancelled {
					verb = "Остановлено"
				}
				u.progress.SetValue(1)
				u.status.SetText(fmt.Sprintf("%s: проверено %d адресов, найдено %d устройств.",
					verb, res.Total, res.Alive))
			}
			u.refreshTable()
		})
	}()
}

// startUpdateLoop repaints progress and results a few times per second while a
// scan is running, so that thousands of events do not flood the GUI thread.
func (u *ui) startUpdateLoop() func() {
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				u.mu.Lock()
				dirty := u.dirty
				p := u.progVal
				u.dirty = false
				u.mu.Unlock()
				if !dirty {
					continue
				}
				fyne.Do(func() {
					if p.Total > 0 {
						u.progress.SetValue(float64(p.Completed) / float64(p.Total))
						pct := p.Completed * 100 / p.Total
						u.status.SetText(fmt.Sprintf("Сканирование… %d / %d (%d%%) · найдено %d",
							p.Completed, p.Total, pct, p.Alive))
					}
					u.refreshTable()
				})
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(done) }) }
}

func (u *ui) setScanning(on bool) {
	if on {
		u.scanBtn.Disable()
		u.clearBtn.Disable()
		u.exportBtn.Disable()
		u.cancelBtn.Enable()
		return
	}
	u.scanBtn.Enable()
	u.clearBtn.Enable()
	u.cancelBtn.Disable()
}

func (u *ui) cancelScan() {
	u.mu.Lock()
	cancel := u.cancel
	u.mu.Unlock()
	if cancel != nil {
		cancel()
		u.status.SetText("Останавливаю…")
	}
}

func (u *ui) clear() {
	u.mu.Lock()
	u.devices = nil
	u.visible = nil
	u.progVal = scanner.Progress{}
	u.mu.Unlock()
	u.progress.SetValue(0)
	u.status.SetText("Готов к сканированию")
	u.refreshTable()
}

func (u *ui) fillLocalRange() {
	ranges := scanner.LocalRanges()
	if len(ranges) == 0 {
		u.status.SetText("Локальная сеть не обнаружена.")
		return
	}
	u.rangeEntry.SetText(ranges[0].CIDR)
	u.status.SetText(fmt.Sprintf("Локальная сеть: %s (%s)", ranges[0].Iface, ranges[0].Address))
}

func (u *ui) exportCSV() {
	u.mu.Lock()
	devices := append([]scanner.Device(nil), u.visible...)
	u.mu.Unlock()
	if len(devices) == 0 {
		u.status.SetText("Нет данных для экспорта.")
		return
	}

	data, err := scanner.DevicesToCSV(devices)
	if err != nil {
		dialog.ShowError(err, u.win)
		return
	}

	save := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
		if err != nil {
			dialog.ShowError(err, u.win)
			return
		}
		if writer == nil {
			return
		}
		defer writer.Close()
		if _, err := writer.Write(data); err != nil {
			dialog.ShowError(err, u.win)
			return
		}
		u.status.SetText("Сохранено: " + writer.URI().Path())
	}, u.win)
	save.SetFileName("sharik-scan.csv")
	save.SetFilter(storageFilter())
	save.Show()
}

func (u *ui) showAbout() {
	site, _ := url.Parse(appSite)
	content := container.NewVBox(
		widget.NewLabelWithStyle(appName, fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		widget.NewLabel("Продвинутый сканер IP-адресов"),
		widget.NewLabel("Версия: "+appVersion),
		widget.NewLabel("Автор: "+appAuthor),
		widget.NewHyperlink(appSite, site),
		widget.NewLabel(""),
		widget.NewLabel("Сканирует диапазон IPv4-адресов и показывает найденные\n"+
			"устройства и информацию о них: IP, имя хоста, MAC,\n"+
			"производитель, время отклика и открытые порты."),
	)
	dialog.NewCustom("О программе", "OK", content, u.win).Show()
}

func atoiOr(s string, fallback int) int {
	v, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return fallback
	}
	return v
}
