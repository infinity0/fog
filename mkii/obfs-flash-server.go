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
	"syscall"
	"time"
)

import "git.torproject.org/flashproxy.git/websocket-transport/src/pt"

const ptMethodName = "obfs3_flash"
const subprocessWaitTimeout = 30 * time.Second

var logFile = os.Stderr

var ptInfo pt.ServerInfo

var procs []*os.Process

// When a connection handler starts, +1 is written to this channel; when it
// ends, -1 is written.
var handlerChan = make(chan int)

func usage() {
	fmt.Printf("Usage: %s [OPTIONS]\n", os.Args[0])
	fmt.Printf("Chains websocket-server and obfsproxy transports. websocket-server and\n")
	fmt.Printf("obfsproxy must be in PATH.\n")
	fmt.Printf("\n")
	fmt.Printf("  -h, --help   show this help.\n")
	fmt.Printf("  --log FILE   log messages to FILE (default stderr).\n")
	fmt.Printf("  --port PORT  listen on PORT (overrides Tor's requested port).\n")
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

func startChain(connectBackAddr net.Addr) (*net.TCPAddr, error) {
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

	// obfsproxy talks to connectBackAddr and listens on midBindAddr.
	cmd := exec.Command("obfsproxy", "managed")
	cmd.Env = []string{
		"TOR_PT_MANAGED_TRANSPORT_VER=1",
		"TOR_PT_STATE_LOCATION=" + os.Getenv("TOR_PT_STATE_LOCATION"),
		"TOR_PT_EXTENDED_SERVER_PORT=",
		"TOR_PT_ORPORT=" + connectBackAddr.String(),
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

	// websocket-server talks to midBindAddr and listens on extBindAddr.
	cmd = exec.Command("websocket-server")
	cmd.Env = []string{
		"TOR_PT_MANAGED_TRANSPORT_VER=1",
		"TOR_PT_STATE_LOCATION=" + os.Getenv("TOR_PT_STATE_LOCATION"),
		"TOR_PT_ORPORT=" + midBindAddr.String(),
		"TOR_PT_SERVER_TRANSPORTS=websocket",
		"TOR_PT_SERVER_BINDADDR=websocket-127.0.0.1:0",
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

func acceptLoop(name string, ln *net.TCPListener, ch chan *net.TCPConn) {
	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			log("%s accept: %s.", name, err)
			break
		}
		log("%s connection from %s.", name, conn.RemoteAddr().String())
		ch <- conn
	}
	close(ch)
}

func copyLoop(a, b *net.TCPConn) error {
	var wg sync.WaitGroup

	wg.Add(2)

	go func() {
		n, err := io.Copy(b, a)
		if err != nil {
			log("after %d bytes from %s to %s: %s.", n, a.RemoteAddr().String(), b.RemoteAddr().String(), err)
		}
		a.CloseRead()
		b.CloseWrite()
		wg.Done()
	}()

	go func() {
		n, err := io.Copy(a, b)
		if err != nil {
			log("after %d bytes from %s to %s: %s.", n, b.RemoteAddr().String(), a.RemoteAddr().String(), err)
		}
		b.CloseRead()
		a.CloseWrite()
		wg.Done()
	}()

	wg.Wait()

	return nil
}

func handleExternalConnection(conn *net.TCPConn, connChan chan *net.TCPConn, chainAddr *net.TCPAddr) error {
	handlerChan <- 1
	defer func() {
		handlerChan <- -1
	}()

	connChan <- conn
	log("handleExternalConnection: now %d conns buffered.", len(connChan))
	chain, err := net.DialTCP("tcp", nil, chainAddr)
	if err != nil {
		log("error dialing proxy chain: %s.", err)
		return err
	}
	err = copyLoop(conn, chain)
	if err != nil {
		log("error copying between ext and proxy chain: %s.", err)
		return err
	}
	return nil
}

func handleInternalConnection(conn *net.TCPConn, connChan chan *net.TCPConn) error {
	handlerChan <- 1
	defer func() {
		handlerChan <- -1
	}()

	extConn := <-connChan
	log("connecting to ORPort using remote addr %s.", extConn.RemoteAddr())
	log("handleInternalConnection: now %d conns buffered.", len(connChan))
	or, err := pt.ConnectOr(&ptInfo, extConn, ptMethodName)
	if err != nil {
		log("error connecting to ORPort: %s.", err)
		return err
	}
	err = copyLoop(or, conn)
	if err != nil {
		log("error copying between int and ORPort: %s.", err)
		return err
	}
	return nil
}

func listenerLoop(extLn, intLn *net.TCPListener, chainAddr *net.TCPAddr) {
	defer extLn.Close()
	defer intLn.Close()
	// XXX defer kill procs.

	extChan := make(chan *net.TCPConn)
	intChan := make(chan *net.TCPConn)
	go acceptLoop("external", extLn, extChan)
	go acceptLoop("internal", intLn, intChan)

	// This channel acts as a queue to forward externally connecting IP
	// addresses to the extended ORPort.
	connChan := make(chan *net.TCPConn, 10)

loop:
	for {
		select {
		case conn, ok := <-extChan:
			if !ok {
				break loop
			}
			go handleExternalConnection(conn, connChan, chainAddr)
		case conn, ok := <-intChan:
			if !ok {
				break loop
			}
			go handleInternalConnection(conn, connChan)
		}
	}
}

func startListeners(bindAddr *net.TCPAddr) (*net.TCPListener, error) {
	// Start internal listener (the proxy chain connects back to this).
	intLn, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		log("error opening internal listener: %s.", err)
		return nil, err
	}
	log("internal listener on %s.", intLn.Addr())

	// Start proxy chain.
	chainAddr, err := startChain(intLn.Addr())
	if err != nil {
		log("error starting proxy chain: %s.", err)
		intLn.Close()
		return nil, err
	}
	log("proxy chain on %s.", chainAddr)

	// Start external Internet listener (listens on bindAddr and connects to
	// proxy chain).
	extLn, err := net.ListenTCP("tcp", bindAddr)
	if err != nil {
		log("error opening external listener: %s.", err)
		intLn.Close()
		// XXX kill procs
		return nil, err
	}
	log("external listener on %s.", extLn.Addr())

	go listenerLoop(extLn, intLn, chainAddr)

	return extLn, nil
}

// Returns true if all processes terminated, or false if timeout was reached.
func awaitSubProcessTermination(timeout time.Duration) bool {
	c := make(chan bool, 1)
	go func() {
		time.Sleep(timeout)
		c <- false
	}()
	go func() {
		for _, proc := range procs {
			proc.Wait()
		}
		c <- true
	}()
	return <-c
}

func main() {
	var logFilename string
	var port int

	flag.Usage = usage
	flag.StringVar(&logFilename, "log", "", "log file to write to")
	flag.IntVar(&port, "port", 0, "port to listen on if unspecified by Tor")
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

	listeners := make([]*net.TCPListener, 0)
	for _, bindAddr := range ptInfo.BindAddrs {
		// Override tor's requested port (which is 0 if this transport
		// has not been run before) with the one requested by the --port
		// option.
		if port != 0 {
			bindAddr.Addr.Port = port
		}

		ln, err := startListeners(bindAddr.Addr)
		if err != nil {
			pt.SmethodError(bindAddr.MethodName, err.Error())
			continue
		}
		pt.Smethod(bindAddr.MethodName, ln.Addr())
		listeners = append(listeners, ln)
	}
	pt.SmethodsDone()

	var numHandlers int = 0
	var sig os.Signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	sig = nil
	for sig == nil {
		select {
		case n := <-handlerChan:
			numHandlers += n
		case sig = <-sigChan:
		}
	}
	log("Got first signal %q with %d running handlers.", sig, numHandlers)
	for _, ln := range listeners {
		ln.Close()
	}
	for _, proc := range procs {
		log("Sending signal %q to process with pid %d.", sig, proc.Pid)
		proc.Signal(sig)
	}

	if sig == syscall.SIGTERM {
		log("Caught signal %q, exiting.", sig)
		return
	}

	sig = nil
	for sig == nil && numHandlers != 0 {
		select {
		case n := <-handlerChan:
			numHandlers += n
			log("%d remaining handlers.", numHandlers)
		case sig = <-sigChan:
		}
	}
	if sig != nil {
		log("Got second signal %q with %d running handlers.", sig, numHandlers)
		for _, proc := range procs {
			log("Sending signal %q to process with pid %d.", sig, proc.Pid)
			proc.Signal(sig)
		}
	}

	log("Waiting up to %g seconds for subprocesses to terminate.", subprocessWaitTimeout.Seconds())
	timedout := !awaitSubProcessTermination(subprocessWaitTimeout)
	if timedout {
		log("Timed out.")
	}

	log("Exiting.")
}
