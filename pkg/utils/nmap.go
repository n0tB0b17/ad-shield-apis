package utils

import (
	"fmt"
	"strings"
)

func ParseNMAPOutput(output string, port int) (string, string, error) {
	serviceName := ""
	serviceVersion := ""
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, fmt.Sprintf("%d/tcp", port)) {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				serviceName = fields[2]

				if len(fields) >= 4 {
					serviceVersion = strings.Join(fields[3:], " ")
				}
			}

			break
		}
	}
	return serviceName, serviceVersion, nil
}
