package analysis

import (

	// Standard packages
	"fmt"
	"encoding/json"
	"errors"
	"io/ioutil"
	"bufio"
	"os"
	"io"

	// Third party packages
	"github.com/gookit/color"
)


/*
 *******************************************************************************
 *                              Type Definitions                               *
 *******************************************************************************
*/


// Type describing a call chain (analyzable entity)
type Chain struct {
	ID           int        // The chain identifier
	Prio         int        // The chain priority
	Path         []int      // The callbacks that consist the chain
	Period_us    int64      // The period of the chain timer (microseconds)
	Utilisation  float64    // Chain specific utilisation
	Random_seed  int        // Seed used when generating this chain
	PPE          bool       // [Test setting]: Whether the chain runs on the PPE or not
	Avg_len      int        // [Test setting]: Average chain length
	Merge_p      float64    // [Test setting]: Merge probability used
	Sync_p       float64    // [Test setting]: Sync probability used
	Variance     float64    // [Test setting]: Variance in length used
	Executors    int        // [Test setting]: Total number of executors used
}

// Type describing a slice of chains
type Chains []Chain

// Type describing a chain analysis
type Result struct {
	ID            int       // The chain identifier
	WCRT_us       int64     // The worst case response time (microseconds)
	ACRT_us       int64     // Average case response time (microseconds)
	BCRT_us       int64     // Best case response time (microseconds)
}

// Type describing a log call event
type Event struct {
	Executor      int       // The executor the event occurred on
	Chain         int       // The chain the event belonged to
	Start_us      int64     // The start timestamp (microseconds)
	Duration_us   int64     // The duration of the chain (microseconds)
}


/*
 *******************************************************************************
 *                         Public Function Definitions                         *
 *******************************************************************************
*/


// Returns a string describing a path (copied from Ops package)
func Path2String (path []int) string {
	s := "{"
	for i, n := range path {
		s += fmt.Sprintf("%d", n)
		if i < (len(path)-1) {
			s += ","
		}
	}
	return s + "}"
}

// Attempts to write chains to a file
func WriteChains (filepath string, 
	random_seed int, 
	ppe bool,
	chain_avg_len, executor_count int,
	chain_merge_p, chain_sync_p, chain_variance float64,
	chains, periods, priorities []int, 
	paths [][]int, 
	us []float64) error {
	var cs Chains = []Chain{}

	// Create the data structures
	for id, _ := range chains {
		cs = append(cs, Chain{
			ID:          id,
			Prio:        priorities[id],
			Path:        paths[id],
			Period_us:   int64(periods[id]),
			Utilisation: us[id],
			Random_seed: random_seed,
			PPE:         ppe,
			Avg_len:     chain_avg_len,
			Merge_p:     chain_merge_p,
			Sync_p:      chain_sync_p,
			Variance:    chain_variance,
			Executors:   executor_count,
		})
	}

	// Attempt to marshall the data
	data, err := json.Marshal(cs)
	if nil != err {
		return err
	}
	
	// Attempt to write the serialized data to file
	return ioutil.WriteFile(filepath, data, 0777)
}

// Attempts to unmarshall chains from a file
func ReadChains (filepath string) ([]Chain, error) {
	var chains Chains
	var data []byte
	var err error = nil

	// Open the given file
	if data, err = ioutil.ReadFile(filepath); err != nil {
		return []Chain{}, errors.New("Unable to open " + filepath + ": " +
			err.Error())
	}

	// Attempt to unmarshall the JSON
	err = json.Unmarshal(data, &chains)
	if nil != err {
		return []Chain{}, errors.New("Unable to parse JSON into chain: " +
			err.Error())
	}

	return chains, nil
}

// Attempts to read a file into a series of events
func ReadEvents (filepath string) ([]Event, error) {
	var file *os.File = nil
	var err error = nil
	var events []Event = []Event{}

	// Open the given file
	if file, err = os.Open(filepath); err != nil {
		return []Event{}, errors.New("Unable to open " + filepath + ": " + 
			err.Error())
	} else {
		defer file.Close()
	}

	// Create a buffered reader
	reader := bufio.NewReader(file)

	for n := 1; ; n++ {
		line, prefix, err := reader.ReadLine()

		// Check: Error reading line
		if nil != err {
			break
		}

		// Check: Was able to read entire line
		if prefix {
			reason := fmt.Sprintf("Line %s:%d too long for parser!", filepath, n)
			return []Event{}, errors.New(reason)
		}

		// Check: Line could be parsed
		event, err := parse_event(line)
		if nil != err {
			reason := fmt.Sprintf("Line %s:%d could not be parsed: %s", filepath, n,
				err.Error())
			return []Event{}, errors.New(reason)
		} else {
			events = append(events, event)
		}
	}

	// Return an error if EOF wasn't the cause of the line break
	if (err != nil) && (err != io.EOF) {
		return []Event{}, errors.New("Exception when parsing: " + err.Error())
	}

	return events, nil
}

// Converts (Chains, Logfile) into results
func Analyse (chains Chains, events []Event) []Result {
	var results []Result = []Result{}

	for _, chain := range chains {

		// Collect all events related to the chain
		chain_events := []Event{}
		for _, event := range events {
			if event.Chain == chain.ID {
				chain_events = append(chain_events, event)
			}
		}
		fmt.Fprintf(os.Stderr, "Analyzing chain %d (%d events)\n", chain.ID, len(chain_events))

		// Obtain all response times
		response_times := analyse_chain(chain, chain_events)

		// If there were no response times, do nothing
		if len(response_times) == 0 {
			fmt.Fprintf(os.Stderr, "No response times were computed for chain %d\n", chain.ID)
			continue
		}

		// Calculate the BCRT, WCRT, and ACRT
		bcrt, wcrt, acrt := response_times[0], response_times[0], response_times[0]
		for i := 1; i < len(response_times); i++ {
			if response_times[i] < bcrt {
				bcrt = response_times[i]
			}
			if response_times[i] > wcrt {
				wcrt = response_times[i]
			}
			acrt += response_times[i]
		}
		acrt /= int64(len(response_times))

		results = append(results, Result{
			ID:       chain.ID,
			WCRT_us:  wcrt,
			ACRT_us:  acrt,
			BCRT_us:  bcrt,
		})
	}

	return results
}

/*
 *******************************************************************************
 *                        Private Function Definitions                         *
 *******************************************************************************
*/

// Performs analysis on a single chain, given it's event stream
// Since the logs now only report end-to-end response times, all I need
// to do is extract them
func analyse_chain (chain Chain, events []Event) []int64 {
	response_times := []int64{}

	for _, event := range events {
		response_times = append(response_times, event.Duration_us)
	}
	return response_times
}

func parse_event (line []byte) (Event, error) {
	var event Event
	var split int = 0
	var sfmt string = "{executor: %d, chain: %d, start: %d, duration: %d}"

	// Discard bytes until an opening brace is hit (in line with log format)
	for i, b := range line {
		if b == '{' {
			split = i
			break
		}
	}

	// Check that line buffer not exceeded
	if split >= (len(line) - 1) {
		return event, errors.New("Opening delimiter not found!")
	}

	// Isolate the log component
	log := string(line[split:])

	// Parse the arguments
	matched, err := fmt.Sscanf(log, sfmt, &(event.Executor), &(event.Chain),
		&(event.Start_us), &(event.Duration_us))
	if nil != err || (matched != 4) {
		return event, errors.New("Unable to match event format: " + err.Error() +
		" in line:\n\"" + log + "\"\n")
	}

	return event, nil
}

func warn (s string, args ...interface{}) {
	color.Style{color.FgYellow, color.OpBold}.Printf("%s\n", fmt.Sprintf(s, args...))
}

func info (s string, args ...interface{}) {
	color.Style{color.FgGreen, color.OpBold}.Printf("%s\n", fmt.Sprintf(s, args...))
}