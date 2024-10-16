package command

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/1set/starlet"
	hbot "github.com/whyrusleeping/hellabot"
)

// This trigger will op people in the given list who ask by saying "-opme"
var oplist = []string{"whyrusleeping", "tlane", "ltorvalds"}
var opPeople = hbot.Trigger{
	Condition: func(bot *hbot.Bot, m *hbot.Message) bool {
		if m.Content == "-opme" {
			for _, s := range oplist {
				if m.From == s {
					return true
				}
			}
		}
		return false
	},
	Action: func(irc *hbot.Bot, m *hbot.Message) bool {
		irc.ChMode(m.To, m.From, "+o")
		return false
	},
}

// This trigger will say the contents of the file "info" when prompted
var sayInfoMessage = hbot.Trigger{
	Condition: func(bot *hbot.Bot, m *hbot.Message) bool {
		return m.Command == "PRIVMSG" && m.Content == "-info"
	},
	Action: func(irc *hbot.Bot, m *hbot.Message) bool {
		fi, err := os.Open("info")
		if err != nil {
			return false
		}
		info, _ := ioutil.ReadAll(fi)

		irc.Send("PRIVMSG " + m.From + " : " + string(info))
		return false
	},
}

// Run a Lua script
func (core Core) RunLua(m *hbot.Message, args []string) {
	// Define your machine with global variables and modules
	globals := starlet.StringAnyMap{
		"greet": func(name string) string {
			return fmt.Sprintf("Hello, %s!", name)
		},
		"allArgs": func() string {
			return strings.Join(args, " ")
		},
		"arg": func(index int) string {
			return args[index]
		},
	}
	/*
		atom 	godoc 	Atomic operations for integers, floats, and strings
		base64 	godoc 	Base64 encoding & decoding functions
		csv 	godoc 	Parses and writes comma-separated values (csv) contents
		file 	godoc 	Functions to interact with the file system
		goidiomatic 	godoc 	Go idiomatic functions and values for Starlark
		hashlib 	godoc 	Hash primitives for Starlark
		http 	godoc 	HTTP client and server handler implementation for Starlark
		json 	godoc 	Utilities for converting Starlark values to/from JSON strings
		log 	godoc 	Functionality for logging messages at various severity levels
		path 	godoc 	Functions to manipulate directories and file paths
		random 	godoc 	Functions to generate random values for various distributions
		re 	godoc 	Regular expression functions for Starlark
		runtime 	godoc 	Provides Go and app runtime information
		string 	godoc 	Constants and functions to manipulate strings
	*/

	mac := starlet.NewWithNames(globals, []string{"random", "atom", "base64", "csv", "file", "hashlib", "http", "json", "log", "path", "random", "re", "runtime", "string"}, nil)

	// Run a Starlark script in the machine
	script := args[0]

	res, err := mac.RunScript([]byte(script), nil)

	// Check for errors and results
	if err != nil {
		core.Bot.Reply(m, fmt.Sprintf("Exited with errors: %s", err))
		return
	}

	core.Bot.Reply(m, fmt.Sprintf("%v", res))
}

// Run a script
func (core Core) RunScript(m *hbot.Message, args []string) {
	var a = []string{}

	if len(args) > 1 {
		a = args[1:]
	}

	output, err := run_script(args[0], a)
	core.Bot.Reply(m, output)

	if err != nil {
		core.Bot.Reply(m, fmt.Sprintf("Exited with errors: %s", err))
		return
	}
}

func run_script(script string, args []string) (string, error) {
	cmd := exec.Command(script, args...)
	stdout, err := cmd.Output()

	return string(stdout), err
}

// Kudos sends a kudos to the target nick
func (core Core) Kudos(m *hbot.Message, args []string) {
	if len(args) < 1 {
		core.Bot.Reply(m, "Please tell me who to thank!")
		return
	}
	teammate := args[0]
	core.Bot.Reply(m, fmt.Sprintf("Hey %s, thanks for being awesome!", teammate))
}

type cveResponse struct {
	Data struct {
		Modified     string      `json:"Modified"`
		Published    string      `json:"Published"`
		Cvss         interface{} `json:"cvss"`
		Cwe          string      `json:"cwe"`
		ID           string      `json:"id"`
		LastModified string      `json:"last-modified"`
		Redhat       struct {
			Advisories []struct {
				Bugzilla struct {
					ID    string `json:"id"`
					Title string `json:"title"`
				} `json:"bugzilla"`
				Rhsa struct {
					ID       string `json:"id"`
					Released string `json:"released"`
					Severity string `json:"severity"`
					Title    string `json:"title"`
				} `json:"rhsa"`
			} `json:"advisories"`
			Rpms []string `json:"rpms"`
		} `json:"redhat"`
		References []string `json:"references"`
		Refmap     struct {
			Confirm []string `json:"confirm"`
		} `json:"refmap"`
		Summary                      string        `json:"summary"`
		VulnerableConfiguration      []interface{} `json:"vulnerable_configuration"`
		VulnerableConfigurationCpe22 []interface{} `json:"vulnerable_configuration_cpe_2_2"`
	} `json:"data"`
	Status string `json:"status"`
}

// GetCVE gets info about a CVE
func (core Core) GetCVE(m *hbot.Message, args []string) {
	client := &http.Client{
		Timeout: time.Second * 10,
	}
	if len(args) < 1 {
		core.Bot.Reply(m, "Please tell me which CVE to fetch")
		return
	}
	cve := args[0]

	cve = strings.ToUpper(cve)
	matched, err := regexp.MatchString("CVE-\\d{4}-\\d{4,}", cve)
	if err != nil {
		core.Bot.Reply(m, fmt.Sprintf("regexp error: %v", err))
		return
	}
	if !matched {
		core.Bot.Reply(m, fmt.Sprintf("Err! %v is not valid CVE format. Valid format: CVE-2017-7494", cve))
		return
	}
	url := fmt.Sprintf("http://cve.circl.lu/api/cve/%s", cve)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		core.Bot.Reply(m, fmt.Sprintf("error creating new request: %v", err))
		return
	}
	req.Header.Add("Version", "1.1")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("User-Agent", "NorCERT likes you :)")
	resp, err := client.Do(req)
	if err != nil {
		core.Bot.Reply(m, fmt.Sprintf("client request error: %v", err))
		return
	}
	if resp.StatusCode == 404 {
		core.Bot.Reply(m, fmt.Sprintf("%v not found", cve))
		return
	}
	if resp.StatusCode != 200 {
		core.Bot.Reply(m, fmt.Sprintf("response status code not 200: %v", resp))
		return
	}

	var r cveResponse
	err = json.NewDecoder(resp.Body).Decode(&r)
	if err != nil {
		core.Bot.Reply(m, fmt.Sprintf("json decode error: %v", err))
		return
	}
	core.Bot.Reply(m, fmt.Sprintf("%s: %s", cve, r.Data.Summary))
	if len(r.Data.Refmap.Confirm) > 0 {
		core.Bot.Reply(m, fmt.Sprintf("%v", r.Data.Refmap.Confirm[0]))
	}
}
