package searchsploit

type Resp struct {
	Title          string `json:"title"`
	Name           string `json:"name"`
	Path           string `json:"path"`
	ExploitContent string `json:"exploit_content,omitempty"`
}
