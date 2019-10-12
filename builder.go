package ldap

import (
	"fmt"
	"strings"
)

type Filter fmt.Stringer

type BinaryFilter struct {
	Lhs, Rhs string
	Operator string
}

type AndFilter struct {
	Operands []Filter
}

type OrFilter struct {
	Operands []Filter
}

type NotFilter struct {
	Operand Filter
}

type SubstringsFilter struct {
	Lhs, SubInitial, SubFinal string
	SubAny                    []string
}

type PresentFilter struct {
	Lhs string
}

type ExtensibleMatchFilter struct {
	Attribute, MatchingRule, rhs string
	Dn                           bool
}

// Factory Functions

// Creates an LDAP Equals Filter, where the left-hand side is an LDAP attribute
// and the right-hand side is a value. This function escapes the right-hand side.
func Equal(lhs, rhs string) *BinaryFilter {
	return &BinaryFilter{
		Lhs:      EscapeFilter(lhs),
		Rhs:      EscapeFilter(rhs),
		Operator: "=",
	}
}

func And(op Filter) *AndFilter {
	return &AndFilter{
		Operands: []Filter{op},
	}
}

func Or(op Filter) *OrFilter {
	return &OrFilter{
		Operands: []Filter{op},
	}
}

func Not(op Filter) *NotFilter {
	return &NotFilter{Operand: op}
}

func Substrings(lhs, subInitial string, subAny []string, subFinal string) *SubstringsFilter {
	for i, value := range subAny {
		subAny[i] = EscapeFilter(value)
	}
	return &SubstringsFilter{
		Lhs:        EscapeFilter(lhs),
		SubInitial: EscapeFilter(subInitial),
		SubAny:     subAny,
		SubFinal:   EscapeFilter(subFinal),
	}
}

func GreaterOrEqual(lhs, rhs string) *BinaryFilter {
	return &BinaryFilter{
		Lhs:      EscapeFilter(lhs),
		Rhs:      EscapeFilter(rhs),
		Operator: ">=",
	}
}

func LessOrEqual(lhs, rhs string) *BinaryFilter {
	return &BinaryFilter{
		Lhs:      EscapeFilter(lhs),
		Rhs:      EscapeFilter(rhs),
		Operator: "<=",
	}
}

func ApproximateMatch(lhs, rhs string) *BinaryFilter {
	return &BinaryFilter{
		Lhs:      EscapeFilter(lhs),
		Rhs:      EscapeFilter(rhs),
		Operator: "~=",
	}
}

func Present(lhs string) *PresentFilter {
	return &PresentFilter{
		Lhs: EscapeFilter(lhs),
	}
}

func ExtensibleMatch(attribute string, dn bool, matchingRule string, rhs string) *ExtensibleMatchFilter {
	return &ExtensibleMatchFilter{
		Attribute:    EscapeFilter(attribute),
		MatchingRule: EscapeFilter(matchingRule),
		Dn:           dn,
		rhs:          EscapeFilter(rhs),
	}
}

// Builder Functions

func (and *AndFilter) And(op Filter) *AndFilter {
	and.Operands = append(and.Operands, op)
	return and
}

func (or *OrFilter) Or(op Filter) *OrFilter {
	or.Operands = append(or.Operands, op)
	return or
}

// TODO ExtensibleMatch and SubStrings builders

// String Functions

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
	return "(" + bf.Lhs + bf.Operator + bf.Rhs + ")"
}

func (ssf *SubstringsFilter) String() string {
	var builder strings.Builder
	builder.WriteString("(")
	builder.WriteString(ssf.Lhs)
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

func (pf *PresentFilter) String() string {
	return "(" + pf.Lhs + "=*)"
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
	builder.WriteString(EscapeFilter(em.rhs))
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
