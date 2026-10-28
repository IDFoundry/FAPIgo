package depcheck

import (
	"io"
	"testing"
	"time"
)

type reader interface{ Read([]byte) (int, error) }

type ptrReader struct{}

func (*ptrReader) Read([]byte) (int, error) { return 0, io.EOF }

type mapReader map[string]int

func (mapReader) Read([]byte) (int, error) { return 0, io.EOF }

type sliceReader []byte

func (sliceReader) Read([]byte) (int, error) { return 0, io.EOF }

type funcReader func([]byte) (int, error)

func (f funcReader) Read(p []byte) (int, error) { return f(p) }

type chanReader chan byte

func (chanReader) Read([]byte) (int, error) { return 0, io.EOF }

type valueReader struct{}

func (valueReader) Read([]byte) (int, error) { return 0, io.EOF }

type deps struct {
	First          reader
	ClientKeyStore reader
	HTTP           reader
	CIBARARPolicy  reader
	unexported     reader
	Concrete       *ptrReader
}

func TestFindTypedNil(t *testing.T) {
	for name, tc := range map[string]struct {
		deps     deps
		found    bool
		wantName string
		wantType string
	}{
		"all nil":                {deps{}, false, "", ""},
		"values set":             {deps{First: valueReader{}, HTTP: &ptrReader{}, CIBARARPolicy: mapReader{}}, false, "", ""},
		"nil pointer":            {deps{ClientKeyStore: (*ptrReader)(nil)}, true, "client_key_store", "*ptrReader"},
		"nil map":                {deps{HTTP: mapReader(nil)}, true, "http", "mapReader"},
		"nil slice":              {deps{First: sliceReader(nil)}, true, "first", "sliceReader"},
		"nil func":               {deps{First: funcReader(nil)}, true, "first", "funcReader"},
		"nil chan":               {deps{First: chanReader(nil)}, true, "first", "chanReader"},
		"override":               {deps{CIBARARPolicy: (*ptrReader)(nil)}, true, "ciba_rar_policy", "*ptrReader"},
		"first in order":         {deps{First: (*ptrReader)(nil), HTTP: mapReader(nil)}, true, "first", "*ptrReader"},
		"unexported is skipped":  {deps{unexported: (*ptrReader)(nil)}, false, "", ""},
		"concrete nil is absent": {deps{Concrete: nil}, false, "", ""},
	} {
		t.Run(name, func(t *testing.T) {
			got, found := FindTypedNil(tc.deps, map[string]string{"CIBARARPolicy": "ciba_rar_policy"})
			if found != tc.found || got.Name != tc.wantName || got.Type != tc.wantType {
				t.Fatalf("FindTypedNil = %+v, %v; want {%s %s}, %v", got, found, tc.wantName, tc.wantType, tc.found)
			}
		})
	}
}

func TestFindTypedNilQualifiesForeignTypes(t *testing.T) {
	type foreign struct{ Reader io.Reader }
	var nilPipe *io.PipeReader
	got, found := FindTypedNil(foreign{Reader: nilPipe}, nil)
	if !found || got.Name != "reader" || got.Type != "*io.PipeReader" {
		t.Fatalf("FindTypedNil = %+v, %v; want reader, *io.PipeReader", got, found)
	}
}

func TestSnakeCase(t *testing.T) {
	for in, want := range map[string]string{
		"Clients":                 "clients",
		"ClientCertificateTrust":  "client_certificate_trust",
		"HTTP":                    "http",
		"FederationHTTP":          "federation_http",
		"HTTPClient":              "http_client",
		"PairwiseSubjectResolver": "pairwise_subject_resolver",
	} {
		if got := snakeCase(in); got != want {
			t.Errorf("snakeCase(%q) = %q, want %q", in, got, want)
		}
	}
}

type systemClock struct{ declares bool }

func (c systemClock) ReadsSystemTime() bool { return c.declares }

func TestReadsSystemTime(t *testing.T) {
	if !ReadsSystemTime(systemClock{declares: true}) {
		t.Error("a clock declaring true doesn't read system time")
	}
	if ReadsSystemTime(systemClock{declares: false}) {
		t.Error("a clock declaring false reads system time")
	}
	if ReadsSystemTime(struct{}{}) {
		t.Error("an undeclared clock reads system time")
	}
}

func TestClockOffset(t *testing.T) {
	for name, tc := range map[string]struct {
		offset   time.Duration
		min, max time.Duration
	}{
		"behind": {-time.Hour, time.Hour, time.Hour + time.Minute},
		"ahead":  {time.Hour, time.Hour - time.Minute, time.Hour},
		"now":    {0, 0, time.Minute},
	} {
		got := ClockOffset(time.Now().Add(tc.offset))
		if got < tc.min || got > tc.max {
			t.Errorf("%s: ClockOffset = %v, want between %v and %v", name, got, tc.min, tc.max)
		}
	}
}
