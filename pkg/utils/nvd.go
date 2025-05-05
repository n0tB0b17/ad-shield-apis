package utils

import (
	"regexp"
	"strings"
)

func RemoveBracket(i string) string {
	re := regexp.MustCompile(`\([^)]*\)`)
	resp := re.ReplaceAllString(i, "")
	resp = strings.TrimSpace(resp)

	space := regexp.MustCompile(`\s+`)
	resp = space.ReplaceAllString(resp, " ")

	return resp
}
