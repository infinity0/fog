package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
)

import "git.torproject.org/pluggable-transports/goptlib.git"
import "github.com/mattn/go-shellwords"

// Represents a server transport plugin configuration like:
// 	ServerTransportPlugin MethodName exec Command
type ServerTransportPlugin struct {
	MethodName string
	Command    []string
	Options    pt.Args
}

type Configuration struct {
	// Map from method names to command strings.
	Transports map[string][]string
	// Map from method names to ServerTransportOptions.
	Options map[string]pt.Args
	// Map from tor-friendly names like "obfs3_websocket" to systematic
	// names like "obfs3|websocket".
	Aliases map[string]string
}

func (conf *Configuration) MethodNames() []string {
	result := make([]string, 0)
	// We understand all the single transports
	for k, _ := range conf.Transports {
		result = append(result, k)
	}
	// and aliases.
	for k, _ := range conf.Aliases {
		result = append(result, k)
	}
	return result
}

// Parse a (possibly composed) method name into a slice of single method names.
func (conf *Configuration) ParseMethodName(methodName string) []string {
	if name, ok := conf.Aliases[methodName]; ok {
		methodName = name
	}
	return strings.Split(methodName, "|")
}

func (conf *Configuration) PluginList(methodName string) ([]ServerTransportPlugin, error) {
	names := conf.ParseMethodName(methodName)
	stp := make([]ServerTransportPlugin, 0)
	for _, name := range names {
		command, ok := conf.Transports[name]
		if !ok {
			return nil, errors.New(fmt.Sprintf("no transport named %q", name))
		}
		options := conf.Options[name]
		stp = append(stp, ServerTransportPlugin{name, command, options})
	}
	return stp, nil
}

// Initialize a configuration object
func getConfiguration() (conf *Configuration) {
	conf = new(Configuration)
	conf.Transports = make(map[string][]string)
	conf.Aliases = make(map[string]string)
	conf.Options = make(map[string]pt.Args)
	return conf
}

// Reads a configuration file and returns the contents
func ReadConfigFile(fileName string) (*Configuration, error) {
	var contents []byte
	contents, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error reading configuration file %s contents.", fileName))
	}
	return ParseConfiguration(string(contents), getConfiguration())
}

// Parses a configuration string and fills the config object's fields with the requested Aliases and ServerTransportPlugins
func ParseConfiguration(configString string, config *Configuration) (*Configuration, error) {
	lines := strings.Split(configString, "\n")
	for lineCounter, line := range lines {
		if len(line) > 0 && line[0] != '#' { // Check for empty lines and comment tags on the first
			line = strings.TrimSpace(line)
			delimitedTokens, err := shellwords.Parse(line)
			if err != nil {
				return nil, errors.New(fmt.Sprintf("Line %v: \"%v\" was split incorrectly by shellwords. Error: %v", lineCounter, line, err))
			}
			if len(delimitedTokens) > 1 {
				configLineType := delimitedTokens[0] // This can be either Alias or ServerTransportPlugin
				if configLineType == "ServerTransportPlugin" {
					err = parseTransportLine(config, delimitedTokens, lineCounter)
					if err != nil {
						return nil, err
					}
				} else if configLineType == "Alias" {
					err = parseAliasLine(config, delimitedTokens, lineCounter)
					if err != nil {
						return nil, err
					}
				} else {
					log("Configuration file has unknown line %s: %s", lineCounter, line)
				}
			}
		}
	}
	return config, nil
}

// Parses a ServerTransportPlugin line.
// Ex: ServerTransportPlugin dummy obfsproxy --client T managed
func parseTransportLine(config *Configuration, tokens []string, lineCounter int) error {
	transportName := tokens[1]
	transportCmdLine := tokens[2:]
	if _, ok := config.Transports[transportName]; ok {
		return errors.New(fmt.Sprintf("Configuration file has duplicate ServerTransportPlugin lines. Duplicate line is at line number %s", lineCounter))
	}
	config.Transports[transportName] = transportCmdLine
	return nil
}

// Parses an alias line
// Ex: Alias b64_b64 b64|b64
func parseAliasLine(config *Configuration, tokens []string, lineCounter int) error {
	var aliasName string
	var aliasPath []string
	aliasName = tokens[1]
	aliasPath = strings.Split(tokens[2], "|")
	if _, hashed := config.Aliases[aliasName]; hashed {
		return errors.New(fmt.Sprintf("Configuration file has duplicate Alias lines. Duplicate line is at line number %s", lineCounter))
	}
	for _, ptName := range aliasPath {
		if _, hashed := config.Transports[ptName]; !hashed {
			log("Transport map is missing pluggable transport %s needed for chain %s. Check your configuration file for a ServerTransportPlugin line can launch %s", ptName, aliasName, ptName)
		}
	}
	config.Aliases[aliasName] = tokens[2]
	return nil
}