package utils

import (
	"os"
	"strconv"
	"strings"
)

func ParsePortRange(portRange string) []int {
	var ports []int
	ranges := strings.Split(portRange, ",")

	for _, r := range ranges {
		r = strings.TrimSpace(r)
		if strings.Contains(r, "-") {
			bounds := strings.Split(r, "-")
			if len(bounds) != 2 {
				continue
			}

			start, err := strconv.Atoi(bounds[0])
			if err != nil {
				continue
			}
			end, err := strconv.Atoi(bounds[1])
			if err != nil {
				continue
			}

			for i := start; i <= end; i++ {
				ports = append(ports, i)
			}
		} else {
			p, err := strconv.Atoi(r)
			if err == nil {
				ports = append(ports, p)
			}
		}
	}

	return ports
}

func IsRoot() bool {
	uid := os.Geteuid()
	return uid == 0
}
