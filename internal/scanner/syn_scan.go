package scanner

import (
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// need to revise
func synScan(addr string, port int) (bool, error) {
	if runtime.GOOS != "linux" {
		return false, fmt.Errorf("other operating system besides linux is not accepted")
	}

	cmd := exec.Command("nmap", "-sS", "-p", strconv.Itoa(port), addr)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("failed SYN scanning :> %v \n", err)
		return false, err
	}

	if strings.Contains(string(output), "open") {
		return true, nil
	}

	fmt.Println(string(output), "xxxxx")
	return false, fmt.Errorf("unable to identify if port is open or closed")
}
