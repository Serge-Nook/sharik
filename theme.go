package main

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// darkTheme reproduces the dark palette of the previous interface.
type darkTheme struct{}

var _ fyne.Theme = darkTheme{}

func (darkTheme) Color(name fyne.ThemeColorName, _ fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground:
		return color.NRGBA{R: 0x0f, G: 0x14, B: 0x20, A: 0xff}
	case theme.ColorNameOverlayBackground, theme.ColorNameMenuBackground:
		return color.NRGBA{R: 0x16, G: 0x1d, B: 0x2e, A: 0xff}
	case theme.ColorNameInputBackground:
		return color.NRGBA{R: 0x1a, G: 0x22, B: 0x35, A: 0xff}
	case theme.ColorNameButton:
		return color.NRGBA{R: 0x1e, G: 0x27, B: 0x3d, A: 0xff}
	case theme.ColorNameHover, theme.ColorNameSelection:
		return color.NRGBA{R: 0x27, G: 0x33, B: 0x4d, A: 0xff}
	case theme.ColorNameForeground:
		return color.NRGBA{R: 0xe6, G: 0xec, B: 0xf7, A: 0xff}
	case theme.ColorNamePlaceHolder, theme.ColorNameDisabled:
		return color.NRGBA{R: 0x7e, G: 0x8a, B: 0xa3, A: 0xff}
	case theme.ColorNamePrimary:
		return color.NRGBA{R: 0x3d, G: 0x8b, B: 0xfd, A: 0xff}
	case theme.ColorNameSuccess:
		return color.NRGBA{R: 0x3d, G: 0xd6, B: 0x8c, A: 0xff}
	case theme.ColorNameError:
		return color.NRGBA{R: 0xef, G: 0x5f, B: 0x6b, A: 0xff}
	case theme.ColorNameSeparator, theme.ColorNameInputBorder:
		return color.NRGBA{R: 0x2a, G: 0x35, B: 0x4d, A: 0xff}
	case theme.ColorNameShadow:
		return color.NRGBA{A: 0x99}
	}
	return theme.DefaultTheme().Color(name, theme.VariantDark)
}

func (darkTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

func (darkTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

func (darkTheme) Size(name fyne.ThemeSizeName) float32 {
	return theme.DefaultTheme().Size(name)
}
