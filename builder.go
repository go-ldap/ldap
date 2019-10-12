package ldap

import (
	"fmt"
	"strings"
)

// Filter represents an LDAP filter.
type Filter fmt.Stringer

type LiteralFilter string

// BinaryFilter represents LDAP filters with two operands.
type BinaryFilter struct {
	// Left-hand side and Right-hand side arguments.
	Attribute, Value string

	// The operator.
	Operator string
}

// AndFilter represents an LDAP AND filter.
type AndFilter struct {
	Operands []Filter
}

// OrFilter represents and LDAP OR filter.
type OrFilter struct {
	Operands []Filter
}

// NotFilter represents an LDAP NOT filter.
type NotFilter struct {
	Operand Filter
}

// SubstringsFilter represents an LDAP substrings filter.
// Must contain at least one of {SubInitial, SubAny, SubFinal}.
type SubstringsFilter struct {
	// The attribute for the substring search.
	Attribute string
	// (Optional) initial substring component.
	SubInitial string
	// (Optional) inner substring components.
	SubAny []string
	// (Optional) ending substring component.
	SubFinal string
}

// PresenceFilter represents an LDAP presence filter.
// Presence filters check for the existence of the specified
// attribute.
type PresenceFilter struct {
	Attribute string
}

// ExtensibleMatchFilter represents an LDAP extensible match filters.
// Extensible match filters support additional matching rules.
type ExtensibleMatchFilter struct {
	// (Optional) an attribute to match.
	Attribute string
	// (Optional) If included, the filter will treat attributes which constitute the entries' DNs
	// (e.g. DC) as if they were part of the entry.
	Dn bool
	// (Optional) OID or name of the matching rule to apply to this filter.
	MatchingRule string
	// The value to test.
	Value string
}

// Factory Functions

// Creates an LDAP filter from a literal string.
func Literal(filter string) *LiteralFilter {
	lit := LiteralFilter(filter)
	return &lit
}

// Creates an LDAP Equals Filter, where the left-hand side is an LDAP attribute
// and the right-hand side is a value. This function escapes both sides using EscapeFilter.
func Equal(attribute, value string) *BinaryFilter {
	return &BinaryFilter{
		Attribute: EscapeFilter(attribute),
		Value:     EscapeFilter(value),
		Operator:  "=",
	}
}

// Creates an LDAP AND filter, using the provided Filter as a clause.
func And(op Filter) *AndFilter {
	return &AndFilter{
		Operands: []Filter{op},
	}
}

// Creates an LDAP OR filter, using the provided Filter as a clause.
func Or(op Filter) *OrFilter {
	return &OrFilter{
		Operands: []Filter{op},
	}
}

// Creates an LDAP NOT filter, using the provided Filter as the clause to be negated.
func Not(op Filter) *NotFilter {
	return &NotFilter{Operand: op}
}

// Creates an LDAP substring filter.
// All string arguments are escaped using EscapeFilter.
func Substring(attribute, subInitial string, subAny []string, subFinal string) *SubstringsFilter {
	for i, value := range subAny {
		subAny[i] = EscapeFilter(value)
	}
	return &SubstringsFilter{
		Attribute:  EscapeFilter(attribute),
		SubInitial: EscapeFilter(subInitial),
		SubAny:     subAny,
		SubFinal:   EscapeFilter(subFinal),
	}
}

// Creates an LDAP greater-or-equal filter.
// All string arguments are escaped using EscapeFilter.
func GreaterOrEqual(attribute, value string) *BinaryFilter {
	return &BinaryFilter{
		Attribute: EscapeFilter(attribute),
		Value:     EscapeFilter(value),
		Operator:  ">=",
	}
}

// Creates an LDAP less-or-equal filter.
// All string arguments are escaped using EscapeFilter.
func LessOrEqual(attribute, value string) *BinaryFilter {
	return &BinaryFilter{
		Attribute: EscapeFilter(attribute),
		Value:     EscapeFilter(value),
		Operator:  "<=",
	}
}

// Creates an LDAP approximate match filter.
// All string arguments are escaped using EscapeFilter.
func ApproximateMatch(attribute, value string) *BinaryFilter {
	return &BinaryFilter{
		Attribute: EscapeFilter(attribute),
		Value:     EscapeFilter(value),
		Operator:  "~=",
	}
}

// Creates an LDAP presence filter.
// All string arguments are escaped using EscapeFilter.
func Present(attribute string) *PresenceFilter {
	return &PresenceFilter{
		Attribute: EscapeFilter(attribute),
	}
}

// Creates an LDAP extensible match filter.
// All string arguments are escaped using EscapeFilter.
func ExtensibleMatch(attribute string, dn bool, matchingRule string, value string) *ExtensibleMatchFilter {
	return &ExtensibleMatchFilter{
		Attribute:    EscapeFilter(attribute),
		MatchingRule: EscapeFilter(matchingRule),
		Dn:           dn,
		Value:        EscapeFilter(value),
	}
}

// Builder Functions

// Adds the provided Filter as a clause to this And filter.
func (and *AndFilter) And(op Filter) *AndFilter {
	and.Operands = append(and.Operands, op)
	return and
}

// Adds the provided Filter as a clause to this Or filter.
func (or *OrFilter) Or(op Filter) *OrFilter {
	or.Operands = append(or.Operands, op)
	return or
}

// We could add ExtensibleMatch and SubStrings builders

// String Functions

func (literal *LiteralFilter) String() string {
	return string(*literal)
}

func (and *AndFilter) String() string {
	return encodeOperandList(and.Operands, "&")
}

func (or *OrFilter) String() string {
	return encodeOperandList(or.Operands, "|")
}

func (not *NotFilter) String() string {
	return "(!" + not.Operand.String() + ")"
}

func (bf *BinaryFilter) String() string {
	return "(" + bf.Attribute + bf.Operator + bf.Value + ")"
}

func (ssf *SubstringsFilter) String() string {
	var builder strings.Builder
	builder.WriteString("(")
	builder.WriteString(ssf.Attribute)
	builder.WriteString("=")
	builder.WriteString(ssf.SubInitial)
	builder.WriteString("*")
	for _, value := range ssf.SubAny {
		builder.WriteString(value)
		builder.WriteString("*")
	}
	builder.WriteString(ssf.SubFinal)
	builder.WriteString(")")
	return builder.String()
}

func (pf *PresenceFilter) String() string {
	return "(" + pf.Attribute + "=*)"
}

func (em *ExtensibleMatchFilter) String() string {
	var builder strings.Builder
	builder.WriteString("(")

	builder.WriteString(em.Attribute)

	if em.Dn {
		builder.WriteString(":dn")
	}

	if em.MatchingRule != "" {
		builder.WriteString(":")
		builder.WriteString(em.MatchingRule)
	}

	builder.WriteString(":=")
	builder.WriteString(em.Value)
	builder.WriteString(")")
	return builder.String()
}

func encodeOperandList(ops []Filter, operator string) string {
	var builder strings.Builder
	builder.WriteString("(" + operator)
	for _, op := range ops {
		builder.WriteString(op.String())
	}
	builder.WriteString(")")
	return builder.String()
}
