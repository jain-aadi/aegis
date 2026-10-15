package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jain-aadi/aegis/internal/sandbox"
)

func main() {
	apiKey := os.Getenv("GOOGLE_API_KEY")
	if apiKey == "" {
		log.Fatal("Please export GOOGLE_API_KEY before running.")
	}

	engine, err := sandbox.NewEngine()
	if err != nil {
		log.Fatalf("Failed to initialize Podman engine: %v", err)
	}
	fmt.Printf("[Aegis] Connected to Rootless Podman socket: %s\n", engine.SocketPath)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	fmt.Println("[Aegis] Launching ephemeral sandbox for test-agent.yaml...")
	err = engine.RunAgent(
		ctx,
		"./workspace",
		"test-agent.yaml",
		"Report your current status.",
		apiKey,
		os.Stdout,
	)
	if err != nil {
		log.Fatalf("[Aegis] Execution failed: %v", err)
	}
	fmt.Println("\n[Aegis] Sandbox execution complete and container destroyed.")
}
