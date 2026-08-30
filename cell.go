package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"
)

// tableCell is a table cell that reports right clicks together with its row, so
// that the results table can offer a context menu.
type tableCell struct {
	widget.BaseWidget

	label       *widget.Label
	row         int
	onSecondary func(row int, pos fyne.Position)
}

var _ fyne.SecondaryTappable = (*tableCell)(nil)

func newTableCell(onSecondary func(row int, pos fyne.Position)) *tableCell {
	c := &tableCell{
		label:       widget.NewLabel("000.000.000.000"),
		row:         -1,
		onSecondary: onSecondary,
	}
	c.label.Truncation = fyne.TextTruncateEllipsis
	c.ExtendBaseWidget(c)
	return c
}

func (c *tableCell) setText(text string) {
	if c.label.Text == text {
		return
	}
	c.label.SetText(text)
}

func (c *tableCell) CreateRenderer() fyne.WidgetRenderer {
	return widget.NewSimpleRenderer(c.label)
}

func (c *tableCell) TappedSecondary(e *fyne.PointEvent) {
	if c.onSecondary != nil {
		c.onSecondary(c.row, e.AbsolutePosition)
	}
}

func storageFilter() storage.FileFilter {
	return storage.NewExtensionFileFilter([]string{".csv"})
}
