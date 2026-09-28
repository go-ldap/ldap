package ldap

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"sort"
)

// SRVResolver resolves DNS SRV records. *net.Resolver implements it, which
// makes the resolver used for LookupSRV replaceable in tests.
type SRVResolver interface {
	LookupSRV(ctx context.Context, service, proto, name string) (cname string, addrs []*net.SRV, err error)
}

// LookupSRV looks up the SRV records for _service._proto.name as described in
// RFC 2782 and returns the targets ordered by the RFC 2782 usage rules.
//
// Records with a target of "." are dropped: RFC 2782 defines that target as
// proof that the service is decidedly not available for the domain, so it must
// never be dialed. A nil resolver falls back to net.DefaultResolver.
func LookupSRV(ctx context.Context, resolver SRVResolver, service, proto, name string) ([]*net.SRV, error) {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	_, addrs, err := resolver.LookupSRV(ctx, service, proto, name)
	if err != nil {
		return nil, err
	}
	available := make([]*net.SRV, 0, len(addrs))
	for _, addr := range addrs {
		if addr == nil || addr.Target == "" || addr.Target == "." {
			continue
		}
		available = append(available, addr)
	}
	if len(available) == 0 {
		return nil, fmt.Errorf("ldap: no SRV records for _%s._%s.%s", service, proto, name)
	}
	return OrderSRVRecords(available, rand.IntN), nil
}

// OrderSRVRecords returns the records ordered as prescribed by RFC 2782: by
// ascending priority, and within one priority by weighted random selection
// where a larger weight means a proportionately larger chance of being picked.
// Records with weight 0 are placed at the front of their priority group, as
// required by the RFC.
//
// randIntN must return a uniform random value in [0, n) and is called with
// n > 0; it exists so tests can order the records deterministically. A nil
// randIntN uses the global math/rand/v2 source. The input slice is not
// modified.
func OrderSRVRecords(records []*net.SRV, randIntN func(int) int) []*net.SRV {
	remaining := make([]*net.SRV, len(records))
	copy(remaining, records)
	sort.SliceStable(remaining, func(i, j int) bool {
		return remaining[i].Priority < remaining[j].Priority
	})

	ordered := make([]*net.SRV, 0, len(remaining))
	for len(remaining) > 0 {
		end := 1
		for end < len(remaining) && remaining[end].Priority == remaining[0].Priority {
			end++
		}
		ordered = append(ordered, orderByWeight(remaining[:end], randIntN)...)
		remaining = remaining[end:]
	}
	return ordered
}

// orderByWeight empties one priority group following the RFC 2782 ordering
// algorithm. Each round moves all weight-0 records to the front, draws a
// number in [0, sum(weights)] and takes the first record whose running weight
// sum reaches that number.
func orderByWeight(group []*net.SRV, randIntN func(int) int) []*net.SRV {
	if randIntN == nil {
		randIntN = rand.IntN
	}

	left := make([]*net.SRV, len(group))
	copy(left, group)

	ordered := make([]*net.SRV, 0, len(left))
	for len(left) > 0 {
		sort.SliceStable(left, func(i, j int) bool {
			return left[i].Weight == 0 && left[j].Weight != 0
		})

		sum := 0
		for _, rr := range left {
			sum += int(rr.Weight)
		}

		pick := 0
		if sum > 0 {
			target := randIntN(sum + 1)
			running := 0
			for i, rr := range left {
				running += int(rr.Weight)
				if running >= target {
					pick = i
					break
				}
			}
		}

		ordered = append(ordered, left[pick])
		left = append(left[:pick], left[pick+1:]...)
	}
	return ordered
}
