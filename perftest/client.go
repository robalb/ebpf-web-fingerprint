package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	iface            = "veth-host"
	local_ip         = "10.200.1.1" // IP on "veth-host" interface
	health_sign      = "Tcp"        // Text that must be present in the response body
	destination_ip   = "10.200.1.2"
	destination_port = 8080

	clients  = 50    // unique clients by TCP fingerprint
	requests = 10000 // total requests performed
)

type TestResult struct {
	Index    int
	Error    error
	Body     string
	Duration time.Duration
}

func main() {
	fmt.Printf("[i] Parallel test for %d unique clients, %d cuncurrent requests\n", clients, requests)
	fmt.Println("[i] Gathering window size maps.")

	// map of requestWindowSize : responseWindowSize
	windows := gatherWindowMaps(clients)
	fmt.Printf("[i] unique maps found: %d \n", len(windows))

	fmt.Print("Consider clearing the BPF_MAPs now for better test results")
	fmt.Print("Press Enter to continue...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')

	fmt.Println("[i] starting parallel tests.")

	results := runParallelTests(requests, windows)
	var (
		okCount       int
		failCount     int
		totalDuration time.Duration
		failString1   int
	)
	for _, res := range results {
		if res.Error != nil {
			failCount++
			fmt.Printf("Test %d failed: %v (%.2f ms)\n", res.Index, res.Error, res.Duration.Seconds()*1000)
			fmt.Printf("`-- Body: %s\n", res.Body)
		} else {
			okCount++
			totalDuration += res.Duration
			fmt.Printf("Test %d passed (%.2f ms)\n", res.Index, res.Duration.Seconds()*1000)
		}
		if strings.Contains(res.Body, "LOOKUP_ERROR") {
			failString1++
		}
	}
	// Calculate average response time only for successful requests
	var avgDurationMs float64
	if okCount > 0 {
		avgDurationMs = totalDuration.Seconds() * 1000 / float64(okCount)
	}
	fmt.Printf("\nSummary:\n")
	fmt.Printf("Passed: %d\n", okCount)
	fmt.Printf("Failed: %d\n", failCount)
	fmt.Printf("Average Duration (ms): %.2f\n", avgDurationMs)
	fmt.Printf("Responses containing 'LOOKUP_ERROR': %d\n", failString1)
}

func runParallelTests(n int, windows map[int]int) []TestResult {
	var wg sync.WaitGroup
	results := make([]TestResult, n)

	// Extract keys for random selection
	keys := make([]int, 0, len(windows))
	for k := range windows {
		keys = append(keys, k)
	}

	wg.Add(n)

	for i := 0; i < n; i++ {
		go func(index int) {
			defer wg.Done()

			// Randomly select reqSize and expectedSize
			randomKey := keys[rand.Intn(len(keys))]
			reqSize := randomKey
			expectedSize := windows[randomKey]

			start := time.Now()
			err, body := serverTest(reqSize, expectedSize)
			duration := time.Since(start)

			results[index] = TestResult{
				Index:    index,
				Error:    err,
				Body:     body,
				Duration: duration,
			}
		}(i)
	}

	wg.Wait()
	return results
}

func serverTest(reqSize int, expectedSize int) (err error, body string) {
	err, _, retSize, body := ServerRequest(reqSize)
	if err != nil {
		return
	}
	if retSize != expectedSize {
		err = fmt.Errorf("got %d window size, expected: %d", retSize, expectedSize)
	}
	return
}

func gatherWindowMaps(mapSize int) map[int]int {
	windows := map[int]int{}

	stepSize := 1000
	initialSize := 1000
	maxSize := 65535

	for i := 0; len(windows) < mapSize; i++ {
		// bound checks
		if i*stepSize+initialSize >= maxSize {
			break
		}

		reqSize := initialSize + i*stepSize
		fmt.Printf("%d ", reqSize)
		err, _, retSize, _ := ServerRequest(reqSize)
		if err != nil {
			fmt.Printf("- error: %v\n", err)
			continue
		}
		//check for duplicates
		duplicate_val := false
		for _, v := range windows {
			if v == retSize {
				duplicate_val = true
				break
			}
		}
		if duplicate_val {
			fmt.Printf("- duplicate retSize\n")
			continue
		}

		windows[reqSize] = retSize
		fmt.Printf("-> %d\n", retSize)
	}
	return windows
}

// Perform an HTTP request to the target webserver, with a customized TCP receive buffer size.
// then parse the response body, extracting the tcp MSS and TCP window that the server should have
// returned. the format that this function expects is:
// ---- HTTP Body ----
// {"Tcp":"65495_1026_20_2-4-8-1-3_7","Sock":"rtt: 93, rttvar: 32","Proto":"HTTP/1.1","Headers":"..."}
// -------------------
//
// Note that the windowSize that is set as param for this function will not correspond with the
// actual windowSize in the TCP SYN sent by the request. The actual value is set by the kernel,
// with some influence based on the value set here.
func ServerRequest(windowSize int) (err error, retMSS int, retWindowSize int, retBody string) {
	retWindowSize = 0
	retBody = ""

	localAddr := &net.TCPAddr{
		IP:   net.ParseIP(local_ip),
		Port: 0, // ephemeral port
	}

	dialer := &net.Dialer{
		LocalAddr: localAddr,
		Control: func(network, address string, c syscall.RawConn) error {
			var controlErr error
			err := c.Control(func(fd uintptr) {
				// Set SO_SNDBUF to simulate different TCP window sizes
				controlErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, windowSize)
			})
			if err != nil {
				return err
			}
			return controlErr
		},
	}

	transport := &http.Transport{
		DialContext: dialer.DialContext,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}

	resp, err := client.Get(fmt.Sprintf("http://%s:%d/test/id", destination_ip, destination_port))
	if err != nil {
		err = fmt.Errorf("Request failed: %w", err)
		return
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		err = fmt.Errorf("Failed to read response: %w", err)
		return
	}

	//sanity check
	if !strings.Contains(string(bodyBytes), health_sign) {
		err = errors.New("Invalid server response: sanity string not in body")
		return
	}

	retBody = strings.TrimSpace(string(bodyBytes))
	retMSS, retWindowSize = parseHttpResponse(retBody)
	// if retWindowSize == 0 {
	// 	err = errors.New("Invalid server response: no window size")
	// 	return
	// }

	return
}

func parseHttpResponse(body string) (mss int, window int) {
	re := regexp.MustCompile(`"Tcp":"(\d+)_(\d+)_`)
	// Regex to capture the Tcp string: "Tcp":"65495_1026_20_2-4-8-1-3_7"
	matches := re.FindStringSubmatch(body)
	if len(matches) >= 3 {
		// matches[1] is the window, matches[2] is the mss
		window, _ = strconv.Atoi(matches[1])
		mss, _ = strconv.Atoi(matches[2])
	}
	return
}
