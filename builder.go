package ldap

import (
	"fmt"
	"strings"
)

type Filter fmt.Stringer

type BinaryFilter struct {
	lhs, rhs string
	operator string
}

type AndFilter struct {
	operands []Filter
}

type OrFilter struct {
	operands []Filter
}

type NotFilter struct {
	operand Filter
}

type SubstringsFilter struct {
	lhs, subInitial, subFinal string
	subAny                    []string
}

type PresentFilter struct {
	lhs string
}

type ExtensibleMatchFilter struct {
	attribute, matchingRule, rhs string
	dn                           bool
}

// Factory Functions

// Creates an LDAP Equals Filter, where the left-hand side is an LDAP attribute
// and the right-hand side is a value. This function escapes the right-hand side.
func Equal(lhs, rhs string) *BinaryFilter {
	return &BinaryFilter{
		lhs:      EscapeFilter(lhs),
		rhs:      EscapeFilter(rhs),
		operator: "=",
	}
}

func And(op Filter) *AndFilter {
	return &AndFilter{
		operands: []Filter{op},
	}
}

func Or(op Filter) *OrFilter {
	return &OrFilter{
		operands: []Filter{op},
	}
}

func Not(op Filter) *NotFilter {
	return &NotFilter{operand: op}
}

func Substrings(lhs, subInitial string, subAny []string, subFinal string) *SubstringsFilter {
	for i, value := range subAny {
		subAny[i] = EscapeFilter(value)
	}
	return &SubstringsFilter{
		lhs:        EscapeFilter(lhs),
		subInitial: EscapeFilter(subInitial),
		subAny:     subAny,
		subFinal:   EscapeFilter(subFinal),
	}
}

func GreaterOrEqual(lhs, rhs string) *BinaryFilter {
	return &BinaryFilter{
		lhs:      EscapeFilter(lhs),
		rhs:      EscapeFilter(rhs),
		operator: ">=",
	}
}

func LessOrEqual(lhs, rhs string) *BinaryFilter {
	return &BinaryFilter{
		lhs:      EscapeFilter(lhs),
		rhs:      EscapeFilter(rhs),
		operator: "<=",
	}
}

func ApproximateMatch(lhs, rhs string) *BinaryFilter {
	return &BinaryFilter{
		lhs:      EscapeFilter(lhs),
		rhs:      EscapeFilter(rhs),
		operator: "~=",
	}
}

func Present(lhs string) *PresentFilter {
	return &PresentFilter{
		lhs: EscapeFilter(lhs),
	}
}

func ExtensibleMatch(attribute string, dn bool, matchingRule string, rhs string) *ExtensibleMatchFilter {
	return &ExtensibleMatchFilter{
		attribute:    EscapeFilter(attribute),
		matchingRule: EscapeFilter(matchingRule),
		dn:           dn,
		rhs:          EscapeFilter(rhs),
	}
}

// Builder Functions

func (and *AndFilter) And(op Filter) *AndFilter {
	and.operands = append(and.operands, op)
	return and
}

func (or *OrFilter) Or(op Filter) *OrFilter {
	or.operands = append(or.operands, op)
	return or
}

// TODO ExtensibleMatch and SubStrings builders

// String Functions

func (and *AndFilter) String() string {
	return encodeOperandList(and.operands, "&")
}

func (or *OrFilter) String() string {
	return encodeOperandList(or.operands, "|")
}

func (not *NotFilter) String() string {
	return "(!" + not.operand.String() + ")"
}

func (bf *BinaryFilter) String() string {
	return "(" + bf.lhs + bf.operator + bf.rhs + ")"
}

func (ssf *SubstringsFilter) String() string {
	var builder strings.Builder
	builder.WriteString("(")
	builder.WriteString(ssf.lhs)
	builder.WriteString("=")
	builder.WriteString(ssf.subInitial)
	builder.WriteString("*")
	for _, value := range ssf.subAny {
		builder.WriteString(value)
		builder.WriteString("*")
	}
	builder.WriteString(ssf.subFinal)
	builder.WriteString(")")
	return builder.String()
}

func (pf *PresentFilter) String() string {
	return "(" + pf.lhs + "=*)"
}

func (em *ExtensibleMatchFilter) String() string {
	var builder strings.Builder
	builder.WriteString("(")

	builder.WriteString(em.attribute)

	if em.dn {
		builder.WriteString(":dn")
	}

	if em.matchingRule != "" {
		builder.WriteString(":")
		builder.WriteString(em.matchingRule)
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
