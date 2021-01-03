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
	Period_us    int        // The period of the chain timer (microseconds)
	Utilisation  float64    // Chain specific utilisation
	Random_seed  int        // Seed used when generating this chain
	PPE          bool       // [Test setting]: Whether the chain runs on the PPE or not
	Avg_len      int        // [Test setting]: Average chain length
	Merge_p      float64    // [Test setting]: Merge probability used
	Sync_p       float64    // [Test setting]: Sync probability used
	Variance     float64    // [Test setting]: Variance in length used
}

// Type describing a slice of chains
type Chains []Chain

// Type describing a chain analysis
type Result struct {
	ID            int       // The chain identifier
	WCRT_us       int       // The worst case response time (microseconds)
	ACRT_us       int       // Average case response time (microseconds)
	BCRT_us       int       // Best case response time (microseconds)
}

// Type describing a log call event
type Event struct {
	Executor      int       // The executor the event occurred on
	Chain         int       // The chain the event belonged to
	Callback      int       // The callback for the event
	Start_us      int       // The start timestamp (microseconds)
	Duration_us   int       // The duration (microseconds)
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
	chain_avg_len int,
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
			Period_us:   periods[id],
			Utilisation: us[id],
			Random_seed: random_seed,
			PPE:         ppe,
			Avg_len:     chain_avg_len,
			Merge_p:     chain_merge_p,
			Sync_p:      chain_sync_p,
			Variance:    chain_variance,
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
func Analyze (chains Chains, events []Event) []Result {
	var results []Result = []Result{}

	for _, chain := range chains {
		response_times := []int{}

		// Collect all events related to the chain
		chain_events := []Event{}
		for _, event := range events {
			if event.Chain == chain.ID {
				chain_events = append(chain_events, event)
			}
		}
		fmt.Fprintf(os.Stderr, "Analyzing chain %d (%d events)\n", chain.ID, len(chain_events))
		// Roll through all events cyclically. Make sure it adheres to the path
		mismatch_count := 0
		for i, path := 0, chain.Path; i < len(chain_events); i++ {
			expected_callback := path[i % len(chain.Path)]
			if expected_callback != chain_events[i].Callback {
				// warn("%d </> %d ~ MISMATCH\n", expected_callback, 
				// 	chain_events[i].Callback)
				mismatch_count++
			}

			// Case: Reached one cycle of the path
			if ((i+1) % len(chain.Path)) == 0 && i > 0 {

				start_callback_index := (i - len(chain.Path) + 1)
				end_callback_index   := i

				// Calculate response time
				response_time := ((chain_events[end_callback_index].Start_us + 
					chain_events[end_callback_index].Duration_us) - 
					chain_events[start_callback_index].Start_us)

				// Add to response times
				response_times = append(response_times, response_time)
			}
		}

		// If there were no response times, do nothing
		if len(response_times) == 0 {
			fmt.Fprintf(os.Stderr, "No response times were computed for chain %d\n", chain.ID)
			continue
		}

		// If the mismatch count is nonzero, report it
		if mismatch_count > 0 {
			fmt.Fprintf(os.Stderr, "%d/%d events did not occur as expected!\n", mismatch_count,
				len(chain_events))
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
		acrt /= len(response_times)

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

func parse_event (line []byte) (Event, error) {
	var event Event
	var split int = 0
	var sfmt string = "{executor: %d, chain: %d, callback: %d, start: %d, duration: %d}"

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
		&(event.Callback), &(event.Start_us), &(event.Duration_us))
	if nil != err || (matched != 5) {
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