package main

import (
	"context"
	"fmt"
	"os"

	"github.com/robalb/deviceid/internal/server"
)

// The entry point for the webserver.
// This is just a wrapper around the
// actual business logic, a practice
// that simplifies writing e2e tests.
func main() {
	ctx := context.Background()
	if err := server.Run(ctx, os.Stdout, os.Stderr, os.Args, os.Getenv); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
