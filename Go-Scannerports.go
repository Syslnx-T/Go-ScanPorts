package main

import (
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

func main() {
	// Define flags
	target := flag.String("t", "", "Target IP/Domain (e.g., 192.168.1.1)")
	portRange := flag.String("p", "1-1024", "Port range to scan (e.g., 1-1000)")
	openOnly := flag.Bool("open", false, "Only list open ports")
	flag.Parse()

	// Validate the target
	if *target == "" {
		fmt.Println("Error: Target IP/Domain is required.")
		fmt.Println("Usage: go run scanner.go -t <target> [-p <port_range>] [--open]")
		return
	}

	// Convert the port range to a list of integers
	ports := parsePortRange(*portRange)

	// Scan the ports
	openPorts := scanPorts(*target, ports)

	// Display results
	if *openOnly {
		// Only show open ports
		fmt.Printf("\n--- Open Ports on %s ---\n", *target)
		for _, port := range openPorts {
			service := getServiceName(port)
			fmt.Printf("%d/tcp   open  %s\n", port, service)
		}
	} else {
		// Show full summary
		fmt.Printf("\n--- Scan Summary ---\n")
		fmt.Printf("Host: %s\n", *target)
		fmt.Printf("Not shown: %d closed ports\n", len(ports)-len(openPorts))
		fmt.Printf("\nPORT     STATE SERVICE\n")

		for _, port := range openPorts {
			service := getServiceName(port)
			fmt.Printf("%d/tcp   open  %s\n", port, service)
		}
	}
}

func parsePortRange(portRange string) []int {
	var ports []int

	if strings.Contains(portRange, "-") {
		// Port range (e.g., 1-1000)
		rangeParts := strings.Split(portRange, "-")
		start, _ := strconv.Atoi(rangeParts[0])
		end, _ := strconv.Atoi(rangeParts[1])

		for port := start; port <= end; port++ {
			ports = append(ports, port)
		}
	} else if strings.Contains(portRange, ",") {
		// Comma-separated port list (e.g., 22,80,443)
		portList := strings.Split(portRange, ",")
		for _, portStr := range portList {
			port, _ := strconv.Atoi(portStr)
			ports = append(ports, port)
		}
	} else {
		// Single port (e.g., 80)
		port, _ := strconv.Atoi(portRange)
		ports = append(ports, port)
	}

	return ports
}

func scanPorts(target string, ports []int) []int {
	var openPorts []int

	for _, port := range ports {
		address := fmt.Sprintf("%s:%d", target, port)
		conn, err := net.DialTimeout("tcp", address, 1*time.Second)
		if err == nil {
			openPorts = append(openPorts, port)
			conn.Close()
		}
	}

	return openPorts
}

func getServiceName(port int) string {
	// Map common ports to services
	commonServices := map[int]string{
		22:   "ssh",
		80:   "http",
		443:  "https",
		3306: "mysql",
		21:   "ftp",
		25:   "smtp",
		53:   "dns",
		8080: "http-alt",
	}

	// Return the service name if found, otherwise return "unknown"
	if service, exists := commonServices[port]; exists {
		return service
	}
	return "unknown"
}