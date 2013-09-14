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
const connStackSize = 10
const subprocessWaitTimeout = 30 * time.Second

var logFile = os.Stderr

var ptInfo pt.ServerInfo

var procs ProcList

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

type ProcList []*os.Process

func (procs ProcList) Kill() {
	for _, p := range procs {
		log("Killing process with pid %d.", p.Pid)
		err := p.Kill()
		if err != nil {
			log("Error killing process with pid %d: %s.", p.Pid, err)
			continue
		}
		state, err := p.Wait()
		if err != nil {
			log("Error waiting on process with pid %d: %s.", state.Pid(), err)
			continue
		}
		if !state.Exited() {
			log("Process with pid %d didn't exit.", state.Pid())
			continue
		}
	}
}

type Chain struct {
	ExtLn, IntLn *net.TCPListener
	ProcsAddr    *net.TCPAddr
	Procs        ProcList
	// This stack forwards external IP addresses to the extended ORPort.
	Conns *Stack
}

func (chain *Chain) CloseListeners() {
	if chain.ExtLn != nil {
		err := chain.ExtLn.Close()
		if err != nil {
			log("Error closing external listener: %s.", err)
		}
	}
	if chain.IntLn != nil {
		err := chain.IntLn.Close()
		if err != nil {
			log("Error closing internal listener: %s.", err)
		}
	}
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

func startProcesses(connectBackAddr net.Addr) (extBindAddr *net.TCPAddr, procs ProcList, err error) {
	var midBindAddr *net.TCPAddr
	var stdout io.ReadCloser

	defer func() {
		if err != nil {
			// Kill subprocesses before returning error.
			procs.Kill()
			procs = procs[:0]
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
	stdout, err = cmd.StdoutPipe()
	if err != nil {
		log("Failed to open obfsproxy stdout pipe: %s.", err)
		return
	}
	err = cmd.Start()
	if err != nil {
		log("Failed to start obfsproxy: %s.", err)
		return
	}
	log("Exec %s with args %q pid %d.", cmd.Path, cmd.Args, cmd.Process.Pid)
	procs = append(procs, cmd.Process)

	midBindAddr, err = findBindAddr(stdout, "obfs3")
	if err != nil {
		log("Failed to find obfsproxy bindaddr: %s.", err)
		return
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
		return
	}
	err = cmd.Start()
	if err != nil {
		log("Failed to start websocket-server: %s.", err)
		return
	}
	log("Exec %s with args %q pid %d.", cmd.Path, cmd.Args, cmd.Process.Pid)
	procs = append(procs, cmd.Process)

	extBindAddr, err = findBindAddr(stdout, "websocket")
	if err != nil {
		log("Failed to find websocket-server bindaddr: %s.", err)
		return
	}
	log("websocket-server bindaddr is %s.", extBindAddr)

	return extBindAddr, procs, err
}

func acceptLoop(name string, ln *net.TCPListener, ch chan *net.TCPConn) {
	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			log("%s accept: %s.", name, err)
			break
		}
		log("%s connection from %s.", name, conn.RemoteAddr())
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
			log("After %d bytes from %s to %s: %s.", n, a.RemoteAddr(), b.RemoteAddr(), err)
		}
		a.CloseRead()
		b.CloseWrite()
		wg.Done()
	}()

	go func() {
		n, err := io.Copy(a, b)
		if err != nil {
			log("After %d bytes from %s to %s: %s.", n, b.RemoteAddr(), a.RemoteAddr(), err)
		}
		b.CloseRead()
		a.CloseWrite()
		wg.Done()
	}()

	wg.Wait()

	return nil
}

func handleExternalConnection(conn *net.TCPConn, chain *Chain) error {
	handlerChan <- 1
	defer func() {
		handlerChan <- -1
	}()

	chain.Conns.Push(conn)
	log("handleExternalConnection: now %d conns buffered.", chain.Conns.Length())
	procsConn, err := net.DialTCP("tcp", nil, chain.ProcsAddr)
	if err != nil {
		log("error dialing proxy chain: %s.", err)
		return err
	}
	err = copyLoop(conn, procsConn)
	if err != nil {
		log("error copying between ext and proxy chain: %s.", err)
		return err
	}
	return nil
}

func handleInternalConnection(conn *net.TCPConn, chain *Chain) error {
	handlerChan <- 1
	defer func() {
		handlerChan <- -1
	}()

	elem, ok := chain.Conns.Pop()
	if !ok {
		log("Underflow of connection stack, closing connection.")
		err := conn.Close()
		if err != nil {
			log("Error in close: %s.", err)
		}
		return errors.New("connection stack underflow")
	}
	extConn := elem.(*net.TCPConn)
	log("Connecting to ORPort using remote addr %s.", extConn.RemoteAddr())
	log("handleInternalConnection: now %d conns buffered.", chain.Conns.Length())
	or, err := pt.ConnectOr(&ptInfo, extConn, ptMethodName)
	if err != nil {
		log("Error connecting to ORPort: %s.", err)
		return err
	}
	err = copyLoop(or, conn)
	if err != nil {
		log("Error copying between int and ORPort: %s.", err)
		return err
	}
	return nil
}

func listenerLoop(chain *Chain) {
	defer chain.CloseListeners()
	// XXX defer kill procs.

	extChan := make(chan *net.TCPConn)
	intChan := make(chan *net.TCPConn)
	go acceptLoop("external", chain.ExtLn, extChan)
	go acceptLoop("internal", chain.IntLn, intChan)

loop:
	for {
		select {
		case conn, ok := <-extChan:
			if !ok {
				break loop
			}
			go handleExternalConnection(conn, chain)
		case conn, ok := <-intChan:
			if !ok {
				break loop
			}
			go handleInternalConnection(conn, chain)
		}
	}
}

func startChain(bindAddr *net.TCPAddr) (*Chain, error) {
	chain := &Chain{}
	var err error

	chain.Conns = NewStack(connStackSize)

	// Start internal listener (the proxy chain connects back to this).
	chain.IntLn, err = net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		log("Error opening internal listener: %s.", err)
		return nil, err
	}
	log("Internal listener on %s.", chain.IntLn.Addr())

	// Start subprocesses.
	chain.ProcsAddr, chain.Procs, err = startProcesses(chain.IntLn.Addr())
	if err != nil {
		log("Error starting proxy chain: %s.", err)
		chain.CloseListeners()
		return nil, err
	}
	procs = append(procs, chain.Procs...)
	log("Proxy chain on %s.", chain.ProcsAddr)

	// Start external Internet listener (listens on bindAddr and connects to
	// proxy chain).
	chain.ExtLn, err = net.ListenTCP("tcp", bindAddr)
	if err != nil {
		log("Error opening external listener: %s.", err)
		chain.CloseListeners()
		// XXX kill procs
		return nil, err
	}
	log("External listener on %s.", chain.ExtLn.Addr())

	go listenerLoop(chain)

	return chain, nil
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

	chains := make([]*Chain, 0)
	for _, bindAddr := range ptInfo.BindAddrs {
		// Override tor's requested port (which is 0 if this transport
		// has not been run before) with the one requested by the --port
		// option.
		if port != 0 {
			bindAddr.Addr.Port = port
		}

		chain, err := startChain(bindAddr.Addr)
		if err != nil {
			pt.SmethodError(bindAddr.MethodName, err.Error())
			continue
		}
		pt.Smethod(bindAddr.MethodName, chain.ExtLn.Addr())
		chains = append(chains, chain)
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
	for _, chain := range chains {
		chain.CloseListeners()
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
