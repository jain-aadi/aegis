package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
)

type Engine struct {
	SocketPath string
	httpClient *http.Client
}

type createReq struct {
	Img        string     `json:"Image"`
	Cmd        []string   `json:"Cmd"`
	Env        []string   `json:"Env,omitempty"`
	WorkingDir string     `json:"WorkingDir,omitempty"`
	HostConfig hostConfig `json:"HostConfig"`
}

type hostConfig struct {
	Binds       []string `json:"Binds,omitempty"`
	AutoRemove  bool     `json:"AutoRemove,omitempty"`
	NetworkMode string   `json:"NetworkMode,omitempty"`
	CapDrop     []string `json:"CapDrop,omitempty"`
}

type createResp struct {
	ID string `json:"Id"`
}

func NewEngine() (*Engine, error) {
	xdg := os.Getenv("XDG_RUNTIME_DIR")
	if xdg == "" {
		xdg = fmt.Sprintf("/run/user/%d", os.Getuid())
	}

	sock := filepath.Join(xdg, "podman", "podman.sock")
	if _, err := os.Stat(sock); err != nil {
		return nil, fmt.Errorf("podman socket not found at %s (run: systemctl --user start podman.socket)", sock)
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", sock)
			},
		},
	}

	return &Engine{
		SocketPath: sock,
		httpClient: client,
	}, nil
}

func (e *Engine) RunAgent(ctx context.Context, workspaceDir, yamlFile, prompt, apiKey string, out io.Writer) error {
	absWorkspace, err := filepath.Abs(workspaceDir)
	if err != nil {
		return err
	}

	payload := createReq{
		Img:        "localhost/aegis-sandbox:latest",
		Cmd:        []string{"run", filepath.Join("/workspace", yamlFile), prompt},
		Env:        []string{"GOOGLE_API_KEY=" + apiKey},
		WorkingDir: "/workspace",
		HostConfig: hostConfig{
			// Read-only mount (:ro) with SELinux relabel (:Z) so the agent cannot tamper with its own YAML
			Binds:       []string{fmt.Sprintf("%s:/workspace:ro,Z", absWorkspace)},
			AutoRemove:  false,                                  // Keep briefly so we can stream logs cleanly, then force-remove
			NetworkMode: "slirp4netns:allow_host_loopback=true", // Needed in Phase 2 to hit Host MCP Gatekeeper
			CapDrop:     []string{"ALL"},                        // Drop all Linux capabilities for maximum security
		},
	}

	body, _ := json.Marshal(payload)
	req, _ := http.NewRequestWithContext(ctx, "POST", "http://d/v4.0.0/containers/create", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to create container: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("container create failed (%d): %s", resp.StatusCode, string(b))
	}

	var created createResp
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return err
	}
	containerID := created.ID

	// destroying the ephemeral container on exit
	defer func() {
		delReq, _ := http.NewRequestWithContext(ctx, "DELETE", fmt.Sprintf("http://d/v4.0.0/containers/%s?force=true", containerID), nil)
		e.httpClient.Do(delReq)
	}()

	// 2. Start the container
	startReq, _ := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("http://d/v4.0.0/containers/%s/start", containerID), nil)
	startResp, err := e.httpClient.Do(startReq)
	if err != nil {
		return fmt.Errorf("start failed: %w", err)
	}
	startResp.Body.Close()

	// 3. Stream stdout/stderr in real time
	logURL := fmt.Sprintf("http://d/v4.0.0/containers/%s/logs?follow=true&stdout=true&stderr=true", containerID)
	logReq, _ := http.NewRequestWithContext(ctx, "GET", logURL, nil)
	logResp, err := e.httpClient.Do(logReq)
	if err != nil {
		return fmt.Errorf("log stream failed: %w", err)
	}
	defer logResp.Body.Close()

	_, err = io.Copy(out, logResp.Body)
	return err
}
