// Package synth generates a deterministic synthetic AWS account: an IAM
// inventory in get-account-authorization-details format, months of
// CloudTrail activity for several workloads, and a ground-truth file that
// records what each workload actually needs and which resources it must not
// touch (decoys).
//
// Everything is fictional: account 111122223333 and the documentation IP
// ranges (RFC 5737) are reserved example values. No real AWS account or API
// is contacted.
package synth

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Account is the fictional AWS account ID used by the scenario.
const Account = "111122223333"

// homeRegion is the region of the regional services the scenario calls.
const homeRegion = "us-east-1"

// Config parameterises generation.
type Config struct {
	Seed      uint64
	Start     time.Time
	Days      int
	TrainDays int
}

// DefaultConfig is the configuration used for the committed fixtures.
func DefaultConfig() Config {
	return Config{Seed: 20260701, Start: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), Days: 90, TrainDays: 60}
}

// Need is one permission a workload genuinely requires.
type Need struct {
	Action   string `json:"action"`
	Resource string `json:"resource"`
	// Frequency is "frequent", "daily", "weekly", "monthly", "quarterly"
	// (only in the held-out window) or "never-logged".
	Frequency string `json:"frequency"`
	// Observable is false for actions CloudTrail never records.
	Observable bool `json:"observable"`
}

// Decoy is a request the workload never makes and should not be able to make.
type Decoy struct {
	Action   string `json:"action"`
	Resource string `json:"resource"`
	Why      string `json:"why"`
}

// PrincipalTruth is the ground truth for one principal.
type PrincipalTruth struct {
	ARN         string  `json:"arn"`
	Description string  `json:"description"`
	Needs       []Need  `json:"needs"`
	Decoys      []Decoy `json:"decoys"`
}

// Truth is the ground-truth file.
type Truth struct {
	Scenario   string           `json:"scenario"`
	Seed       uint64           `json:"seed"`
	Start      time.Time        `json:"start"`
	TrainEnd   time.Time        `json:"trainEnd"`
	End        time.Time        `json:"end"`
	Principals []PrincipalTruth `json:"principals"`
	Events     int              `json:"events"`
	Noise      map[string]int   `json:"noise"`
}

// Scenario is a generated dataset.
type Scenario struct {
	Authz []byte
	Truth Truth
	// Files maps relative paths (cloudtrail/<region>/<date>.json.gz) to
	// their records.
	Files map[string][]event
}

type task struct {
	actor     *actor
	need      Need
	rate      float64 // mean calls per active day
	weekdays  bool
	everyDays int // >0: exactly one call every N days
	phase     int
	hour      int // >=0: calls happen in this UTC hour
	build     func(r *rand.Rand, day int, date time.Time) call
}

// Generate builds the scenario in memory.
func Generate(cfg Config) (*Scenario, error) {
	if cfg.Days <= 0 || cfg.TrainDays <= 0 || cfg.TrainDays >= cfg.Days {
		return nil, fmt.Errorf("invalid config: need 0 < TrainDays < Days")
	}
	r := rand.New(rand.NewPCG(cfg.Seed, cfg.Seed^0x9e3779b97f4a7c15)) // #nosec G404 -- deterministic fixture generation, not security-sensitive
	tasks, noise, truths := scenario()
	authzDoc, err := json.MarshalIndent(inventory(), "", "  ")
	if err != nil {
		return nil, err
	}
	sc := &Scenario{
		Authz: append(authzDoc, '\n'),
		Files: map[string][]event{},
		Truth: Truth{
			Scenario: "acme-retail", Seed: cfg.Seed, Start: cfg.Start,
			TrainEnd: cfg.Start.AddDate(0, 0, cfg.TrainDays), End: cfg.Start.AddDate(0, 0, cfg.Days),
			Noise: map[string]int{},
		},
	}
	type timed struct {
		t time.Time
		e event
	}
	for day := 0; day < cfg.Days; day++ {
		date := cfg.Start.AddDate(0, 0, day)
		weekend := date.Weekday() == time.Saturday || date.Weekday() == time.Sunday
		byRegion := map[string][]timed{}
		emit := func(a *actor, c call, hour int) {
			sec := r.IntN(86400)
			if hour >= 0 {
				sec = hour*3600 + r.IntN(3600)
			}
			t := date.Add(time.Duration(sec) * time.Second)
			byRegion[c.region] = append(byRegion[c.region], timed{t, render(r, Account, a, c, t)})
		}
		for _, tk := range tasks {
			if !tk.need.Observable {
				continue
			}
			n := 0
			switch {
			case tk.everyDays > 0:
				if day%tk.everyDays == tk.phase {
					n = 1
				}
			case tk.weekdays && weekend:
				n = 0
			default:
				n = int(tk.rate*(0.6+0.8*r.Float64()) + 0.5)
			}
			for i := 0; i < n; i++ {
				emit(tk.actor, tk.build(r, day, date), tk.hour)
			}
		}
		for _, nz := range noise {
			if nz.everyDays > 0 && day%nz.everyDays != nz.phase {
				continue
			}
			emit(nz.actor, nz.build(r, day, date), -1)
			sc.Truth.Noise[nz.need.Frequency]++
		}
		for region, evs := range byRegion {
			sort.Slice(evs, func(i, j int) bool { return evs[i].t.Before(evs[j].t) })
			path := fmt.Sprintf("cloudtrail/%s/%s.json.gz", region, date.Format("2006-01-02"))
			for _, e := range evs {
				sc.Files[path] = append(sc.Files[path], e.e)
			}
			sc.Truth.Events += len(evs)
		}
	}
	sc.Truth.Principals = truths
	return sc, nil
}

// Write stores the scenario under dir: authz.json, truth.json and
// cloudtrail/<region>/<date>.json.gz files in CloudTrail delivery format.
func (s *Scenario) Write(dir string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "authz.json"), s.Authz, 0o600); err != nil {
		return err
	}
	tb, err := json.MarshalIndent(s.Truth, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "truth.json"), append(tb, '\n'), 0o600); err != nil {
		return err
	}
	paths := make([]string, 0, len(s.Files))
	for p := range s.Files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		data, err := EncodeLogFile(s.Files[p])
		if err != nil {
			return err
		}
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(full, data, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// EncodeLogFile renders records as a gzip-compressed CloudTrail log file
// with one record per line inside the Records array.
func EncodeLogFile(records []event) ([]byte, error) {
	var plainBuf bytes.Buffer
	plainBuf.WriteString("{\"Records\":[\n")
	for i, rec := range records {
		b, err := json.Marshal(rec)
		if err != nil {
			return nil, err
		}
		plainBuf.Write(b)
		if i < len(records)-1 {
			plainBuf.WriteByte(',')
		}
		plainBuf.WriteByte('\n')
	}
	plainBuf.WriteString("]}\n")
	var out bytes.Buffer
	gz, err := gzip.NewWriterLevel(&out, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := gz.Write(plainBuf.Bytes()); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
