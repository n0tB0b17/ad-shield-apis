package searchsploit

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type ReqBody struct {
	Query string `json:"query"`
}

func Query(service, version string) ([]Resp, error) {
	body := ReqBody{
		Query: fmt.Sprintf("%s %s", service, version),
	}

	return makeRequest(body)
}

func makeRequest(body ReqBody) ([]Resp, error) {
	cmd := exec.Command("searchsploit", "--disable-colour", "-t", fmt.Sprintf("%s", body.Query))
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("error while combining output: %v \n", err)
		return nil, err
	}

	outStr := string(out)
	resp := parseCommandResponse(outStr)

	return resp, nil
}

func parseCommandResponse(output string) []Resp {
	var resp []Resp

	isExploitTitle := false
	isShellTitle := false
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		ln := strings.TrimSpace(line)
		if ln == "" {
			continue
		}

		if strings.Contains(ln, "Exploit Title") {
			isExploitTitle = true
			isShellTitle = false
			continue
		}

		if strings.Contains(ln, "Shellcode Title") {
			isExploitTitle = false
			isShellTitle = true
			continue
		}

		if strings.Contains(ln, "-------------") {
			continue
		}

		if isExploitTitle && strings.Contains(ln, "|") {
			exploitResp := getResponseFromSearchsploit(ln, "Exploit")
			resp = append(resp, *exploitResp)
		}

		if isShellTitle && strings.Contains(ln, "|") {
			shellResp := getResponseFromSearchsploit(ln, "Shell")
			resp = append(resp, *shellResp)
		}
	}

	return resp
}

func getResponseFromSearchsploit(line string, t string) *Resp {
	parts := strings.SplitN(line, "|", 2)
	if len(parts) == 2 {
		name := strings.TrimSpace(parts[0])
		path := strings.TrimSpace(parts[1])

		if name != "" && path != "" {
			resp := &Resp{
				Title: t,
				Name:  name,
				Path:  path,
			}

			exploitPath := generatePath(resp.Path, resp.Title)
			fileContent, err := readExploitContent(exploitPath)
			if err != nil {
				resp.ExploitContent = ""
				return resp
			}

			resp.ExploitContent = fileContent
			return resp
		} else {
			return nil
		}
	}

	return nil
}

func generatePath(path, t string) string {
	basePath := os.Getenv("EXPLOIT_DB_BASE_PATH")
	filePath := ""
	if t == "Exploit" {
		filePath = fmt.Sprintf("%s/exploits/%s", basePath, path)
	}
	if t == "Shell" {
		filePath = fmt.Sprintf("%s/shellcodes/%s", basePath, path)
	}

	return filePath
}

func readExploitContent(path string) (string, error) {
	cleanPath := filepath.Clean(path)
	fileInfo, err := os.Stat(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("file does not exist")
		}

		if os.IsPermission(err) {
			return "", fmt.Errorf("permission denied, not allowed to access file")
		}

		return "", fmt.Errorf("failed to access file: %v", err)
	}

	if !fileInfo.Mode().IsRegular() {
		return "", fmt.Errorf("irregular file type detected...")
	}

	const maxFileSize = 10 * 1024 * 1024
	if fileInfo.Size() > int64(maxFileSize) {
		return "", fmt.Errorf("file size is greater than expected")
	}

	file, err := os.Open(cleanPath)
	if err != nil {
		return "", fmt.Errorf("error while opening file: %w", err)
	}
	defer file.Close()

	content, err := ioutil.ReadAll(file)
	if err != nil {
		return "", fmt.Errorf("error while reading file content: %w", err)
	}

	return string(content), nil

}
