package ldap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type fakeSRVResolver struct {
	records []*net.SRV
	err     error
	obeyCtx bool

	service string
	proto   string
	name    string
	calls   int
}

func (f *fakeSRVResolver) LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error) {
	f.service, f.proto, f.name = service, proto, name
	f.calls++
	if f.obeyCtx {
		if err := ctx.Err(); err != nil {
			return "", nil, err
		}
	}
	if f.err != nil {
		return "", nil, f.err
	}
	return "", f.records, nil
}

func srvRecords(t *testing.T) []*net.SRV {
	t.Helper()
	return []*net.SRV{
		{Priority: 20, Weight: 0, Port: 1389, Target: "second.example.com."},
		{Priority: 10, Weight: 0, Port: 389, Target: "first.example.com."},
		{Priority: 10, Weight: 30, Port: 2389, Target: "third.example.com."},
	}
}

func TestLookupSRVOrdersRecordsAndDropsUnavailableTarget(t *testing.T) {
	resolver := &fakeSRVResolver{records: append(srvRecords(t),
		&net.SRV{Priority: 0, Weight: 0, Port: 389, Target: "."},
		nil,
	)}

	records, err := LookupSRV(context.Background(), resolver, "ldap", "tcp", "example.com")
	if err != nil {
		t.Fatalf("LookupSRV returned error: %v", err)
	}

	if resolver.service != "ldap" || resolver.proto != "tcp" || resolver.name != "example.com" {
		t.Fatalf("unexpected query _%s._%s.%s", resolver.service, resolver.proto, resolver.name)
	}

	if len(records) != 3 {
		t.Fatalf("expected 3 usable records, got %d", len(records))
	}
	for i, rr := range records {
		if rr.Target == "." || rr.Target == "" {
			t.Fatalf("record %d: unusable target %q was returned", i, rr.Target)
		}
	}
	if records[0].Priority != 10 || records[1].Priority != 10 || records[2].Priority != 20 {
		t.Fatalf("records are not ordered by ascending priority: %v", records)
	}
}

func TestLookupSRVReturnsResolverError(t *testing.T) {
	boom := errors.New("dns boom")
	resolver := &fakeSRVResolver{err: boom}

	if _, err := LookupSRV(context.Background(), resolver, "ldap", "tcp", "example.com"); !errors.Is(err, boom) {
		t.Fatalf("expected resolver error, got %v", err)
	}
}

func TestLookupSRVErrorsWhenNoUsableRecords(t *testing.T) {
	for name, records := range map[string][]*net.SRV{
		"empty":        {},
		"only dot":     {{Priority: 0, Weight: 0, Port: 389, Target: "."}},
		"empty target": {{Priority: 0, Weight: 0, Port: 389, Target: ""}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LookupSRV(context.Background(), &fakeSRVResolver{records: records}, "ldap", "tcp", "example.com")
			if err == nil || !strings.Contains(err.Error(), "no SRV records") {
				t.Fatalf("expected no-records error, got %v", err)
			}
		})
	}
}

func TestLookupSRVPropagatesContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := LookupSRV(ctx, &fakeSRVResolver{obeyCtx: true}, "ldap", "tcp", "example.com")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestOrderSRVRecordsGroupsPriorities(t *testing.T) {
	records := []*net.SRV{
		{Priority: 30, Weight: 0, Port: 1, Target: "c."},
		{Priority: 10, Weight: 0, Port: 2, Target: "a."},
		{Priority: 10, Weight: 0, Port: 3, Target: "b."},
		{Priority: 20, Weight: 0, Port: 4, Target: "d."},
	}

	ordered := OrderSRVRecords(records, func(int) int { return 0 })
	got := make([]uint16, 0, len(ordered))
	for _, rr := range ordered {
		got = append(got, rr.Priority)
	}
	want := []uint16{10, 10, 20, 30}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("priority order = %v, want %v", got, want)
		}
	}
}

// TestOrderSRVRecordsWeightedSelection checks the RFC 2782 drawing rule for one
// priority group with weights 0, 5 and 50: the random number is drawn from
// [0, sum] inclusive and the first record whose running weight sum reaches it
// is selected.
func TestOrderSRVRecordsWeightedSelection(t *testing.T) {
	const (
		zeroTarget  = "zero."
		lightTarget = "light."
		heavyTarget = "heavy."
	)
	records := []*net.SRV{
		{Priority: 1, Weight: 5, Port: 2, Target: lightTarget},
		{Priority: 1, Weight: 0, Port: 1, Target: zeroTarget},
		{Priority: 1, Weight: 50, Port: 3, Target: heavyTarget},
	}

	for target := 0; target <= 55; target++ {
		draw := target
		ordered := OrderSRVRecords(records, func(n int) int {
			if draw >= n {
				return n - 1
			}
			return draw
		})
		if len(ordered) != len(records) {
			t.Fatalf("target %d: got %d records, want %d", target, len(ordered), len(records))
		}

		first := ordered[0].Target
		switch {
		case target == 0:
			if first != zeroTarget {
				t.Fatalf("target %d: picked %q, want the zero-weight record %q", target, first, zeroTarget)
			}
		case target <= 5:
			if first != lightTarget {
				t.Fatalf("target %d: picked %q, want the weight-5 record %q", target, first, lightTarget)
			}
		default:
			if first != heavyTarget {
				t.Fatalf("target %d: picked %q, want the weight-50 record %q", target, first, heavyTarget)
			}
		}
	}
}

func TestOrderSRVRecordsSelectsProportionallyToWeight(t *testing.T) {
	records := []*net.SRV{
		{Priority: 1, Weight: 10, Port: 1, Target: "a."},
		{Priority: 1, Weight: 30, Port: 2, Target: "b."},
		{Priority: 1, Weight: 60, Port: 3, Target: "c."},
	}
	const iterations = 20000
	counts := map[string]int{}
	for i := 0; i < iterations; i++ {
		counts[OrderSRVRecords(records, nil)[0].Target]++
	}

	for target, wantShare := range map[string]float64{"a.": 0.1, "b.": 0.3, "c.": 0.6} {
		got := float64(counts[target]) / iterations
		if got < wantShare-0.05 || got > wantShare+0.05 {
			t.Fatalf("target %s was picked %.3f of the time, want about %.2f", target, got, wantShare)
		}
	}
}

func TestOrderSRVRecordsSingleRecordAndEmptyInput(t *testing.T) {
	single := []*net.SRV{{Priority: 5, Weight: 7, Port: 389, Target: "only.example.com."}}
	ordered := OrderSRVRecords(single, func(int) int { return 0 })
	if len(ordered) != 1 || ordered[0] != single[0] {
		t.Fatalf("single record was not returned unchanged: %v", ordered)
	}

	if ordered := OrderSRVRecords(nil, func(int) int { return 0 }); len(ordered) != 0 {
		t.Fatalf("nil input returned %d records", len(ordered))
	}
	if ordered := OrderSRVRecords([]*net.SRV{}, func(int) int { return 0 }); len(ordered) != 0 {
		t.Fatalf("empty input returned %d records", len(ordered))
	}
}

func TestOrderSRVRecordsDoesNotModifyInput(t *testing.T) {
	records := srvRecords(t)
	original := make([]*net.SRV, len(records))
	copy(original, records)

	OrderSRVRecords(records, func(int) int { return 0 })

	for i := range records {
		if records[i] != original[i] {
			t.Fatalf("input slice was reordered: record %d is now %v, want %v", i, records[i], original[i])
		}
	}
}

func TestDialURLSRVUsesTargetsInOrder(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	unreachable := unusedTCPPort(t)
	livePort := ln.Addr().(*net.TCPAddr).Port

	resolver := &fakeSRVResolver{records: []*net.SRV{
		{Priority: 10, Weight: 0, Port: uint16(unreachable), Target: "127.0.0.1."},
		{Priority: 20, Weight: 0, Port: uint16(livePort), Target: "127.0.0.1."},
	}}

	dialerWithRecorder, attemptsOf := recordingDialer(t)
	conn, err := DialURL("ldap://srv.example.com:9999", DialWithDialer(dialerWithRecorder), DialWithSRVResolver(resolver))
	if err != nil {
		t.Fatalf("DialURL with SRV discovery failed: %v", err)
	}
	conn.SetTimeout(time.Millisecond)
	defer func() { _ = conn.Close() }()

	if resolver.calls != 1 || resolver.service != "ldap" || resolver.proto != "tcp" || resolver.name != "srv.example.com" {
		t.Fatalf("unexpected SRV query: calls=%d _%s._%s.%s", resolver.calls, resolver.service, resolver.proto, resolver.name)
	}

	got := attemptsOf()
	want := []string{
		net.JoinHostPort("127.0.0.1", fmt.Sprint(unreachable)),
		net.JoinHostPort("127.0.0.1", fmt.Sprint(livePort)),
	}
	if len(got) != len(want) {
		t.Fatalf("dial attempts = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("dial attempts = %v, want %v", got, want)
		}
	}

	select {
	case c := <-accepted:
		_ = c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("live SRV target was not connected to")
	}
}

func TestDialURLSRVReportsAllDialFailures(t *testing.T) {
	first, second := unusedTCPPort(t), unusedTCPPort(t)
	resolver := &fakeSRVResolver{records: []*net.SRV{
		{Priority: 10, Weight: 0, Port: uint16(first), Target: "127.0.0.1."},
		{Priority: 20, Weight: 0, Port: uint16(second), Target: "127.0.0.1."},
	}}

	_, err := DialURL("ldap://srv.example.com", DialWithSRVResolver(resolver))
	if err == nil {
		t.Fatal("expected an error when no SRV target is reachable")
	}
	for _, port := range []int{first, second} {
		if !strings.Contains(err.Error(), fmt.Sprint(port)) {
			t.Fatalf("error %v does not mention failed target port %d", err, port)
		}
	}
}

func TestDialURLSRVResolverErrorsPropagate(t *testing.T) {
	boom := errors.New("dns boom")
	_, err := DialURL("ldap://srv.example.com", DialWithSRVResolver(&fakeSRVResolver{err: boom}))
	if !errors.Is(err, boom) {
		t.Fatalf("expected resolver error, got %v", err)
	}
}

func TestDialURLSRVServiceNameFollowsScheme(t *testing.T) {
	for scheme, service := range map[string]string{"ldap": "ldap", "ldaps": "ldaps"} {
		resolver := &fakeSRVResolver{}
		_, err := DialURL(scheme+"://srv.example.com", DialWithSRVResolver(resolver))
		if err == nil {
			t.Fatalf("%s://: expected error for empty SRV answer", scheme)
		}
		if resolver.service != service {
			t.Fatalf("%s:// used service %q, want %q", scheme, resolver.service, service)
		}
	}
}

// TestDialURLWithoutSRVOptIsUnchanged pins the default behaviour: without
// DialWithSRVDiscovery no SRV lookup is performed and the host and port from
// the URL are dialed directly.
func TestDialURLWithoutSRVOptIsUnchanged(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	conn, err := DialURL("ldap://" + ln.Addr().String())
	if err != nil {
		t.Fatalf("DialURL failed: %v", err)
	}
	_ = conn.Close()

	select {
	case c := <-accepted:
		_ = c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("direct dial did not reach the listener")
	}
}

func TestDialURLSRVNotUsedForOtherSchemes(t *testing.T) {
	resolver := &fakeSRVResolver{}
	conn, err := DialURL("cldap://127.0.0.1:389", DialWithSRVResolver(resolver))
	if err != nil {
		t.Fatalf("cldap DialURL failed: %v", err)
	}
	_ = conn.Close()

	if resolver.calls != 0 {
		t.Fatalf("SRV lookup was performed for cldap:// (%d calls)", resolver.calls)
	}
}

func unusedTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve a port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("failed to release the reserved port: %v", err)
	}
	return port
}

func recordingDialer(t *testing.T) (*net.Dialer, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var attempts []string
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	dialer.Control = func(_, address string, _ syscall.RawConn) error {
		mu.Lock()
		defer mu.Unlock()
		attempts = append(attempts, address)
		return nil
	}
	return dialer, func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := make([]string, len(attempts))
		copy(out, attempts)
		return out
	}
}
