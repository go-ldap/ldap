package ldap

import (
	"strings"
)

type Filter interface {
	Encode() string
}

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
	lhs, rhs string
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
		lhs:      lhs,
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

func Substrings(lhs, rhs string) *SubstringsFilter {
	return &SubstringsFilter{
		lhs: lhs,
		rhs: EscapeFilter(rhs),
	}
}

func GreaterOrEqual(lhs, rhs string) *BinaryFilter {
	return &BinaryFilter{
		lhs:      lhs,
		rhs:      EscapeFilter(rhs),
		operator: ">=",
	}
}

func LessOrEqual(lhs, rhs string) *BinaryFilter {
	return &BinaryFilter{
		lhs:      lhs,
		rhs:      EscapeFilter(rhs),
		operator: "<=",
	}
}

func ApproximateMatch(lhs, rhs string) *BinaryFilter {
	return &BinaryFilter{
		lhs:      lhs,
		rhs:      EscapeFilter(rhs),
		operator: "~=",
	}
}

func Present(lhs string) *PresentFilter {
	return &PresentFilter{
		lhs: lhs,
	}
}

func ExtensibleMatch(attribute, matchingRule string, dn bool, rhs string) *ExtensibleMatchFilter {
	return &ExtensibleMatchFilter{
		attribute:    attribute,
		matchingRule: matchingRule,
		dn:           dn,
		rhs:          rhs,
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

// Encode Functions

func (and *AndFilter) Encode() string {
	return encodeOperandList(and.operands, "&")
}

func (or *OrFilter) Encode() string {
	return encodeOperandList(or.operands, "|")
}

func (not *NotFilter) Encode() string {
	return "(!" + not.operand.Encode() + ")"
}

func (bf *BinaryFilter) Encode() string {
	return "(" + bf.lhs + bf.operator + bf.rhs + ")"
}

func (not *SubstringsFilter) Encode() string {
	trimmed := strings.Trim(not.rhs, " ")
	var builder strings.Builder
	builder.WriteString("(")
	builder.WriteString(not.lhs)
	builder.WriteString("=")
	if strings.HasPrefix(trimmed, "*") {
		builder.WriteString("*")
	}
	for i, tok := range strings.Split(trimmed, "*") {
		builder.WriteString(EscapeFilter(tok))
		if i < len(trimmed)-1 || strings.HasSuffix(trimmed, "*") {
			builder.WriteString("*")
		}
	}
	builder.WriteString(")")
	return builder.String()
}

func (pf *PresentFilter) Encode() string {
	return "(" + pf.lhs + "=*)"
}

func (em *ExtensibleMatchFilter) Encode() string {
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
		builder.WriteString(op.Encode())
	}
	builder.WriteString(")")
	return builder.String()
}
