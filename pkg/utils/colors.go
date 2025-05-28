package utils

import (
	"fmt"
	"strconv"
)

func HexToRGB(hex string) (r, g, b int, err error) {
	if len(hex) > 0 && hex[0] == '#' {
		hex = hex[1:]
	}

	if len(hex) != 6 {
		return 0, 0, 0, fmt.Errorf("invalid hex provided")
	}

	r64, err := strconv.ParseInt(hex[0:2], 16, 64)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid hex provided")
	}

	g64, err := strconv.ParseInt(hex[2:4], 16, 64)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid hex provided")
	}

	b64, err := strconv.ParseInt(hex[4:6], 16, 64)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid hex provided")
	}

	return int(r64), int(g64), int(b64), nil
}
