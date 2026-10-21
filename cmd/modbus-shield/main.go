// Command modbus-shield is the single static binary for the Modbus TCP
// retrofit proxy. Milestone 0 scaffold: subcommand wiring arrives with
// the gateway core (see AGENTS.md roadmap).
package main

import "fmt"

// version is overridden for releases via ldflags.
var version = "0.1.0"

func main() {
	fmt.Println("modbus-shield", version)
}
