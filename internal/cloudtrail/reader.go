package cloudtrail

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ErrStop can be returned by a visitor to stop reading early without error.
var ErrStop = errors.New("stop")

// Visitor receives each record; returning an error aborts reading.
type Visitor func(Record) error

// ReadPath reads a file or a directory tree of CloudTrail logs. Files ending
// in .json, .jsonl or .json.gz (and .gz in general) are read; other files are
// ignored. Directory entries are visited in lexical order so results are
// deterministic.
func ReadPath(path string, visit Visitor) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return readFileStop(path, visit)
	}
	var files []string
	err = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && isLogFile(p) {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return err
	}
	sort.Strings(files)
	for _, f := range files {
		if err := ReadFile(f, visit); err != nil {
			if errors.Is(err, ErrStop) {
				return nil
			}
			return err
		}
	}
	return nil
}

func readFileStop(path string, visit Visitor) error {
	err := ReadFile(path, visit)
	if errors.Is(err, ErrStop) {
		return nil
	}
	return err
}

func isLogFile(p string) bool {
	for _, suf := range []string{".json", ".jsonl", ".gz"} {
		if strings.HasSuffix(p, suf) {
			return true
		}
	}
	return false
}

// ReadFile reads one log file (plain or gzip-compressed).
func ReadFile(path string, visit Visitor) error {
	f, err := os.Open(path) // #nosec G304 -- the path is an explicit user input
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	var r io.Reader = bufio.NewReader(f)
	br := r.(*bufio.Reader)
	if magic, err := br.Peek(2); err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		defer func() { _ = gz.Close() }()
		r = gz
	}
	if err := Read(r, visit); err != nil {
		if errors.Is(err, ErrStop) {
			return err
		}
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// Read decodes records from r, which holds either a CloudTrail log object
// ({"Records":[...]}) or JSON Lines of records.
func Read(r io.Reader, visit Visitor) error {
	br := bufio.NewReader(r)
	first, err := peekNonSpace(br)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return err
	}
	if first != '{' {
		return fmt.Errorf("expected a JSON object, found %q", first)
	}
	dec := json.NewDecoder(br)
	// Decode the first object lazily: it is either the wrapper or a record.
	var head json.RawMessage
	if err := dec.Decode(&head); err != nil {
		return err
	}
	if records, ok, err := wrapperRecords(head); err != nil {
		return err
	} else if ok {
		for i, raw := range records {
			var rec Record
			if err := json.Unmarshal(raw, &rec); err != nil {
				return fmt.Errorf("record %d: %w", i, err)
			}
			if err := visit(rec); err != nil {
				return err
			}
		}
		return expectEOF(dec)
	}
	// JSON Lines: head is the first record.
	n := 0
	for {
		var rec Record
		if err := json.Unmarshal(head, &rec); err != nil {
			return fmt.Errorf("record %d: %w", n, err)
		}
		if err := visit(rec); err != nil {
			return err
		}
		n++
		head = nil
		if err := dec.Decode(&head); err == io.EOF {
			return nil
		} else if err != nil {
			return fmt.Errorf("record %d: %w", n, err)
		}
	}
}

// wrapperRecords recognises the CloudTrail log-file wrapper object.
func wrapperRecords(head json.RawMessage) ([]json.RawMessage, bool, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(head, &probe); err != nil {
		return nil, false, err
	}
	raw, ok := probe["Records"]
	if !ok {
		return nil, false, nil
	}
	var records []json.RawMessage
	if err := json.Unmarshal(raw, &records); err != nil {
		return nil, false, fmt.Errorf("decode Records array: %w", err)
	}
	return records, true, nil
}

func expectEOF(dec *json.Decoder) error {
	var extra json.RawMessage
	if err := dec.Decode(&extra); err == io.EOF {
		return nil
	} else if err != nil {
		return err
	}
	return errors.New("unexpected data after the Records object")
}

func peekNonSpace(br *bufio.Reader) (byte, error) {
	for {
		b, err := br.ReadByte()
		if err != nil {
			return 0, err
		}
		switch b {
		case ' ', '\t', '\r', '\n', 0xEF, 0xBB, 0xBF: // whitespace and UTF-8 BOM bytes
			continue
		}
		if err := br.UnreadByte(); err != nil {
			return 0, err
		}
		return b, nil
	}
}

// ReadAll is a convenience that collects every record under path.
func ReadAll(path string) ([]Record, error) {
	var out []Record
	err := ReadPath(path, func(r Record) error {
		out = append(out, r)
		return nil
	})
	return out, err
}
