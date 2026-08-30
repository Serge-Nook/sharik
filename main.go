package main

import (
	_ "embed"

	"fyne.io/fyne/v2/app"

	"github.com/Serge-Nook/sharik/internal/scanner"
)

// The OUI vendor database ships inside the binary.
//
//go:embed assets/oui.json
var ouiJSON []byte

const (
	appTitle   = "Шарик — сканер IP-адресов"
	appName    = "Шарик"
	appVersion = "2.0.0"
	appAuthor  = "Горшков Сергей Владимирович"
	appSite    = "https://nookbat.ru/"
)

func main() {
	scanner.SetOUIData(ouiJSON)

	a := app.NewWithID("ru.gorshkov.sharik")
	a.Settings().SetTheme(darkTheme{})

	u := newUI(a)
	u.win.ShowAndRun()
}
