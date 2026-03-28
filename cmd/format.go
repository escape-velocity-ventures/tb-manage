package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// printKV prints a key-value pair with fixed-width alignment.
func printKV(key, value string) {
	fmt.Printf("  %-12s %s\n", key, value)
}

// printTable prints a fixed-width table with headers and rows.
func printTable(headers []string, rows [][]string) {
	if len(rows) == 0 {
		return
	}

	// Calculate column widths from headers and data
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	// Print header
	var hdr strings.Builder
	for i, h := range headers {
		if i > 0 {
			hdr.WriteString("  ")
		}
		hdr.WriteString(fmt.Sprintf("%-*s", widths[i], h))
	}
	fmt.Printf("\n  %s\n", hdr.String())

	// Print rows
	for _, row := range rows {
		var line strings.Builder
		for i, cell := range row {
			if i > 0 {
				line.WriteString("  ")
			}
			w := 0
			if i < len(widths) {
				w = widths[i]
			}
			line.WriteString(fmt.Sprintf("%-*s", w, cell))
		}
		fmt.Printf("  %s\n", line.String())
	}
}

// outputJSON writes v as indented JSON to stdout.
func outputJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
