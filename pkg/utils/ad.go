package utils

import (
	"fmt"
	"strings"
)

func ConvertDomainToDN(v string) string {
	parts := strings.Split(strings.TrimSpace(v), ".")
	dnParts := make([]string, 0, len(parts))

	for _, part := range parts {
		if part != "" {
			dnParts = append(dnParts, fmt.Sprintf("DC=%s", part))
		}
	}

	return strings.Join(dnParts, ",")
}
