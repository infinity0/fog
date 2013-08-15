package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"time"
)

import "git.torproject.org/flashproxy.git/websocket-transport/src/pt"

const ptMethodName = "obfs3_flash"

var logFile = os.Stderr

var ptInfo pt.ServerInfo

var procs []*os.Process

func usage() {
	fmt.Printf("Usage: %s [OPTIONS]\n", os.Args[0])
	fmt.Printf("Chains websocket-server and obfsproxy transports. websocket-server and\n")
	fmt.Printf("obfsproxy must be in PATH.\n")
	fmt.Printf("\n")
	fmt.Printf("  -h, --help   show this help.\n")
	fmt.Printf("  --log FILE   log messages to FILE (default stderr).\n")
}

var logMutex sync.Mutex

func log(format string, v ...interface{}) {
	dateStr := time.Now().Format("2006-01-02 15:04:05")
	logMutex.Lock()
	defer logMutex.Unlock()
	msg := fmt.Sprintf(format, v...)
	fmt.Fprintf(logFile, "%s %s\n", dateStr, msg)
}

func findBindAddr(r io.Reader, methodName string) (*net.TCPAddr, error) {
	br := bufio.NewReader(r)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		log("Received from sub-transport: %q.", line)
		fields := strings.Fields(strings.TrimRight(line, "\n"))
		if len(fields) < 1 {
			continue
		}
		keyword := fields[0]
		args := fields[1:]
		if keyword == "SMETHOD" && len(args) >= 2 && args[0] == methodName {
			bindAddr, err := net.ResolveTCPAddr("tcp", args[1])
			if err != nil {
				return nil, err
			}
			return bindAddr, nil
		} else if keyword == "SMETHODS" && len(args) == 1 && args[0] == "DONE" {
			break
		}
	}
	return nil, errors.New(fmt.Sprintf("no SMETHOD %s found before SMETHODS DONE", methodName))
}

func startChain(bindAddr *net.TCPAddr) (*net.TCPAddr, error) {
	var midBindAddr, extBindAddr *net.TCPAddr
	var tmpProcs []*os.Process

	defer func() {
		// Something went wrong; kill the processes we started.
		for _, proc := range tmpProcs {
			log("Killing process with pid %d.", proc.Pid)
			proc.Kill()
			proc.Wait()
		}
	}()

	// obfsproxy talks directly to the real ORPort and listens on
	// midBindAddr.
	cmd := exec.Command("obfsproxy", "managed")
	cmd.Env = []string{
		"TOR_PT_MANAGED_TRANSPORT_VER=1",
		"TOR_PT_STATE_LOCATION=" + os.Getenv("TOR_PT_STATE_LOCATION"),
		"TOR_PT_EXTENDED_SERVER_PORT=",
		"TOR_PT_ORPORT=" + os.Getenv("TOR_PT_ORPORT"),
		"TOR_PT_SERVER_TRANSPORTS=obfs3",
		"TOR_PT_SERVER_BINDADDR=obfs3-127.0.0.1:0",
	}
	log("obfsproxy environment %q", cmd.Env)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log("Failed to open obfsproxy stdout pipe: %s.", err)
		return nil, err
	}
	err = cmd.Start()
	if err != nil {
		log("Failed to start obfsproxy: %s.", err)
		return nil, err
	}
	log("Exec %s with args %q pid %d.", cmd.Path, cmd.Args, cmd.Process.Pid)
	tmpProcs = append(tmpProcs, cmd.Process)

	midBindAddr, err = findBindAddr(stdout, "obfs3")
	if err != nil {
		log("Failed to find obfsproxy bindaddr: %s.", err)
		return nil, err
	}
	log("obfsproxy bindaddr is %s.", midBindAddr)

	// websocket-server talks to midBindAddr and listens on bindAddr.
	cmd = exec.Command("websocket-server")
	cmd.Env = []string{
		"TOR_PT_MANAGED_TRANSPORT_VER=1",
		"TOR_PT_STATE_LOCATION=" + os.Getenv("TOR_PT_STATE_LOCATION"),
		"TOR_PT_ORPORT=" + midBindAddr.String(),
		"TOR_PT_SERVER_TRANSPORTS=websocket",
		"TOR_PT_SERVER_BINDADDR=websocket-" + bindAddr.String(),
	}
	log("websocket-server environment %q", cmd.Env)
	stdout, err = cmd.StdoutPipe()
	if err != nil {
		log("Failed to open websocket-server stdout pipe: %s.", err)
		return nil, err
	}
	err = cmd.Start()
	if err != nil {
		log("Failed to start websocket-server: %s.", err)
		return nil, err
	}
	log("Exec %s with args %q pid %d.", cmd.Path, cmd.Args, cmd.Process.Pid)
	tmpProcs = append(tmpProcs, cmd.Process)

	extBindAddr, err = findBindAddr(stdout, "websocket")
	if err != nil {
		log("Failed to find websocket-server bindaddr: %s.", err)
		return nil, err
	}
	log("websocket-server bindaddr is %s.", extBindAddr)

	// Add new processes to the global list of processes and cause them not
	// to be killed when this function returns.
	procs = append(procs, tmpProcs...)
	tmpProcs = []*os.Process{}

	return extBindAddr, err
}

func main() {
	var logFilename string

	flag.Usage = usage
	flag.StringVar(&logFilename, "log", "", "log file to write to")
	flag.Parse()

	if logFilename != "" {
		f, err := os.OpenFile(logFilename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Can't open log file %q: %s.\n", logFilename, err.Error())
			os.Exit(1)
		}
		logFile = f
	}

	log("Starting.")
	ptInfo = pt.ServerSetup([]string{ptMethodName})

	for _, bindAddr := range ptInfo.BindAddrs {
		addr, err := startChain(bindAddr.Addr)
		if err != nil {
			pt.SmethodError(bindAddr.MethodName, err.Error())
			continue
		}
		pt.Smethod(bindAddr.MethodName, addr)
	}
	pt.SmethodsDone()

	sigintChan := make(chan os.Signal, 1)
	signal.Notify(sigintChan, os.Interrupt)

	<-sigintChan

	log("SIGINT 1.")
	for _, proc := range procs {
		log("Sending SIGINT to process with pid %d.", proc.Pid)
		proc.Signal(os.Interrupt)
	}

	<-sigintChan

	log("SIGINT 2.")
	for _, proc := range procs {
		log("Sending SIGINT to process with pid %d.", proc.Pid)
		proc.Signal(os.Interrupt)
	}
}
