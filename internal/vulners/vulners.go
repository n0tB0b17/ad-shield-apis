package vulners

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

type VulnersBase struct {
	URL string
	Key string

	Retries int
	Timeout time.Duration
}

type ReqBody struct {
	Query string `json:"query"`
	Key   string `json:"apiKey"`
}

func GetVulners(retries int) *VulnersBase {
	url := os.Getenv("VULNERS_BASE_URL")
	key := os.Getenv("VULNERS_KEY")
	return &VulnersBase{
		URL:     url,
		Key:     key,
		Retries: retries,
		Timeout: 5 * time.Second,
	}
}

func (v *VulnersBase) HealthCheck() (bool, error) {
	client := &http.Client{
		Timeout: v.Timeout,
	}

	var lastError error
	for i := 1; i <= v.Retries; i++ {
		req, err := http.NewRequest("GET", v.URL, nil)
		if err != nil {
			lastError = err
			time.Sleep(time.Duration(i) * time.Second)
			continue
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("accept", "application/json")

		apiResp, err := client.Do(req)
		if err != nil {
			lastError = err
			time.Sleep(time.Duration(i) * time.Second)
			continue
		}

		if apiResp.StatusCode != http.StatusOK {
			lastError = fmt.Errorf("invalid status code got")
			time.Sleep(time.Duration(i) * time.Second)
			continue
		}

		return true, nil
	}

	return false, lastError
}

func (v *VulnersBase) Query(service, version string) (*Resp, error) {
	body := ReqBody{
		Query: fmt.Sprintf("%s %s", service, version),
		Key:   v.Key,
	}

	resp, err := v.makeRequest(body)
	if err != nil {
		fmt.Println("error while making request to vulners API: ", err.Error())
		return nil, err
	}

	return resp, err
}

func (v *VulnersBase) makeRequest(body ReqBody) (*Resp, error) {
	client := &http.Client{
		Timeout: v.Timeout,
	}

	docs, err := json.Marshal(body)
	if err != nil {
		fmt.Printf("error marshing ReqBody to json: %v \n", err)
		return nil, err
	}

	var docsResp Resp
	var lastErr error

	for i := 1; i <= v.Retries; i++ {
		req, err := http.NewRequest("POST", v.URL, bytes.NewBuffer(docs))
		if err != nil {
			fmt.Printf("[Attempt: %d] Creating request failed: %v \n", i, err)
			lastErr = err
			time.Sleep(time.Duration(i) * time.Second)
			continue
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("[Attempt: %d] Unable to make new request: %v \n", i, err)
			lastErr = err
			time.Sleep(time.Duration(i) * time.Second)
			continue
		}

		defer resp.Body.Close()
		respBody, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("unexpected status code: %d: %s", resp.StatusCode, string(respBody))

			if resp.StatusCode >= 500 {
				time.Sleep(time.Duration(i) * time.Second)
				continue
			}
			return nil, lastErr
		}

		err = json.Unmarshal(respBody, &docsResp)
		if err != nil {
			fmt.Printf("[Attempt: %d] Error while decoding response body: %v \n", i, err)
			lastErr = fmt.Errorf("error while decoding response body: %w", err)
			return nil, lastErr
		}

		return &docsResp, nil
	}

	return nil, lastErr
}
