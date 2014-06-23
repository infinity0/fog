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
	"path"
	"strings"
	"sync"
	"syscall"
	"sort"
	"time"
)

import "git.torproject.org/pluggable-transports/goptlib.git"

const connStackSize = 1000
const subprocessWaitTimeout = 30 * time.Second

var logFile = os.Stderr

var ptInfo pt.ServerInfo

// When a connection handler starts, +1 is written to this channel; when it
// ends, -1 is written.
var handlerChan = make(chan int)

func usage() {
	fmt.Printf("Usage: %s [OPTIONS]\n", os.Args[0])
	fmt.Printf("Chains websocket and obfsproxy server transports. pt-websocket-server and\n")
	fmt.Printf("obfsproxy must be in PATH.\n")
	fmt.Printf("\n")
	fmt.Printf("  -h, --help   show this help.\n")
	fmt.Printf("  --log FILE   log messages to FILE (default stderr).\n")
	fmt.Printf("  --port PORT  listen on PORT (overrides Tor's requested port).\n")
	fmt.Printf("  -f, --file FILE   Loads and runs configuration FILE.\n")
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

func (procs ProcList) Signal(sig os.Signal) {
	for _, p := range procs {
		log("Sending signal %q to process with pid %d.", sig, p.Pid)
		err := p.Signal(sig)
		if err != nil {
			log("Error sending signal %q to process with pid %d: %s.", sig, p.Pid, err)
		}
	}
}

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
	MethodName   string
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

func (chain *Chain) Shutdown() {
	chain.CloseListeners()
	chain.Procs.Kill()
	for {
		elem, ok := chain.Conns.Pop()
		if !ok {
			break
		}
		conn := elem.(*net.TCPConn)
		log("Closing stale connection from %s.", conn.RemoteAddr())
		err := conn.Close()
		if err != nil {
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
			bindaddr, err := net.ResolveTCPAddr("tcp", args[1])
			if err != nil {
				return nil, err
			}
			return bindaddr, nil
		} else if keyword == "SMETHODS" && len(args) == 1 && args[0] == "DONE" {
			break
		}
	}
	return nil, errors.New(fmt.Sprintf("no SMETHOD %s found before SMETHODS DONE", methodName))
}

// Escape a string for a ServerTransportOptions serialization.
func escape(s string) string {
	repl := strings.NewReplacer(":", "\\:", ";", "\\;", "=", "\\=", "\\", "\\\\")
	return repl.Replace(s)
}

func encodeServerTransportOptions(methodName string, opts pt.Args) string {
	if opts == nil {
		return ""
	}
	keys := make([]string, 0, len(opts))
	for key, _ := range opts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		for _, value := range opts[key] {
			parts = append(parts, escape(methodName) + ":" + escape(key) + "=" + escape(value))
		}
	}
	return strings.Join(parts, ";")
}

func startProcesses(connectBackAddr net.Addr, plugins []ServerTransportPlugin) (bindAddr *net.TCPAddr, procs ProcList, err error) {
	var stdout io.ReadCloser

	defer func() {
		if err != nil {
			// Kill subprocesses before returning error.
			procs.Kill()
			procs = procs[:0]
		}
	}()

	bindAddr = connectBackAddr.(*net.TCPAddr)
	for _, plugin := range plugins {
		// This plugin has its TOR_PT_ORPORT set to the previous
		// bindAddr.
		cmd := exec.Command(plugin.Command[0], plugin.Command[1:]...)
		cmd.Env = []string{
			"TOR_PT_MANAGED_TRANSPORT_VER=1",
			"TOR_PT_STATE_LOCATION=" + path.Join(os.Getenv("TOR_PT_STATE_LOCATION"), "fog"),
			"TOR_PT_EXTENDED_SERVER_PORT=",
			"TOR_PT_ORPORT=" + bindAddr.String(),
			"TOR_PT_SERVER_TRANSPORTS=" + plugin.MethodName,
			"TOR_PT_SERVER_BINDADDR=" + plugin.MethodName + "-127.0.0.1:0",
		}
		serverTransportOptions := encodeServerTransportOptions(plugin.MethodName, plugin.Options)
		if serverTransportOptions != "" {
			cmd.Env = append(cmd.Env, "TOR_PT_SERVER_TRANSPORT_OPTIONS=" + serverTransportOptions)
		}
		log("%s environment %q", cmd.Args[0], cmd.Env)
		stdout, err = cmd.StdoutPipe()
		if err != nil {
			log("Failed to open %s stdout pipe: %s.", cmd.Args[0], err)
			return
		}
		err = cmd.Start()
		if err != nil {
			log("Failed to start %s: %s.", cmd.Args[0], err)
			return
		}
		log("Exec %s with args %q pid %d.", cmd.Path, cmd.Args, cmd.Process.Pid)
		procs = append(procs, cmd.Process)

		bindAddr, err = findBindAddr(stdout, plugin.MethodName)
		if err != nil {
			log("Failed to find %s bindaddr: %s.", cmd.Args[0], err)
			return
		}
		log("%s bindaddr is %s.", cmd.Args[0], bindAddr)
	}

	return bindAddr, procs, err
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
	or, err := pt.DialOr(&ptInfo, extConn.RemoteAddr().String(), chain.MethodName)
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

func startChain(methodName string, bindaddr *net.TCPAddr, plugins []ServerTransportPlugin) (*Chain, error) {
	chain := &Chain{}
	var err error

	chain.MethodName = methodName
	chain.Conns = NewStack(connStackSize)

	// Start internal listener (the proxy chain connects back to this).
	chain.IntLn, err = net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		log("Error opening internal listener: %s.", err)
		chain.Shutdown()
		return nil, err
	}
	log("Internal listener on %s.", chain.IntLn.Addr())

	// Start subprocesses.
	chain.ProcsAddr, chain.Procs, err = startProcesses(chain.IntLn.Addr(), plugins)
	if err != nil {
		log("Error starting proxy chain: %s.", err)
		chain.Shutdown()
		return nil, err
	}
	log("Proxy chain on %s.", chain.ProcsAddr)

	// Start external Internet listener (listens on bindaddr and connects to
	// proxy chain).
	chain.ExtLn, err = net.ListenTCP("tcp", bindaddr)
	if err != nil {
		log("Error opening external listener: %s.", err)
		chain.Shutdown()
		return nil, err
	}
	log("External listener on %s.", chain.ExtLn.Addr())

	go listenerLoop(chain)

	return chain, nil
}

func main() {
	var logFilename string
	var port int
	var configFilename string
	var conf *Configuration

	flag.Usage = usage
	flag.StringVar(&logFilename, "log", "", "log file to write to")
	flag.IntVar(&port, "port", 0, "port to listen on if unspecified by Tor")
	flag.StringVar(&configFilename, "file", "fogrc", "The fog file to read the configuration from.")
	flag.StringVar(&configFilename, "f", "fogrc", "The fog file to read the configuration from.")
	flag.Parse()

	if logFilename != "" {
		f, err := os.OpenFile(logFilename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Can't open log file %q: %s.\n", logFilename, err.Error())
			os.Exit(1)
		}
		logFile = f
	}
	var err error

	conf, err = ReadConfigFile(configFilename)
	if err != nil {
		log("Error in reading configuration file: %s", err)
		os.Exit(1)
	}
	log("Starting.")

	ptInfo, err = pt.ServerSetup(conf.MethodNames())
	if err != nil {
		log("Error in ServerSetup: %s", err)
		os.Exit(1)
	}

	chains := make([]*Chain, 0)
	for _, bindaddr := range ptInfo.Bindaddrs {
		// Override tor's requested port (which is 0 if this transport
		// has not been run before) with the one requested by the --port
		// option.
		if port != 0 {
			bindaddr.Addr.Port = port
		}

		plugins, err := conf.PluginList(bindaddr.MethodName)
		if err != nil {
			pt.SmethodError(bindaddr.MethodName, err.Error())
			continue
		}

		chain, err := startChain(bindaddr.MethodName, bindaddr.Addr, plugins)
		if err != nil {
			pt.SmethodError(bindaddr.MethodName, err.Error())
			continue
		}
		pt.Smethod(bindaddr.MethodName, chain.ExtLn.Addr())
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
		chain.Procs.Signal(sig)
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
		for _, chain := range chains {
			chain.Procs.Signal(sig)
		}
	}

	log("Exiting.")
}
