package ldap

import (
	"context"
	"errors"
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// Response defines an interface to get data from an LDAP server
type Response interface {
	Entry() *Entry
	Referral() string
	Controls() []Control
	Err() error
	Next() bool
}

type searchResponse struct {
	conn *Conn
	ch   chan *SearchSingleResult

	entry    *Entry
	referral string
	controls []Control
	err      error
}

// Entry returns an entry from the given search request
func (r *searchResponse) Entry() *Entry {
	return r.entry
}

// Referral returns a referral from the given search request
func (r *searchResponse) Referral() string {
	return r.referral
}

// Controls returns controls from the given search request
func (r *searchResponse) Controls() []Control {
	return r.controls
}

// Err returns an error when the given search request was failed
func (r *searchResponse) Err() error {
	return r.err
}

// Next returns whether next data exist or not
func (r *searchResponse) Next() bool {
	res, ok := <-r.ch
	if !ok {
		return false
	}
	if res == nil {
		return false
	}
	r.err = res.Error
	if r.err != nil {
		return false
	}
	r.entry = res.Entry
	r.referral = res.Referral
	r.controls = res.Controls
	return true
}

// send enqueues a result on the result channel, giving up when ctx is
// cancelled so an abandoned consumer cannot block the search goroutine
// forever on a full buffer. It reports whether the result was handed off to
// the channel; a true return does not mean the consumer received it. The
// give-up is best-effort: if ctx is already cancelled but buffer space is
// available, the result may still be enqueued. Callers that terminate the
// stream regardless of the outcome may ignore the return value.
func (r *searchResponse) send(ctx context.Context, res *SearchSingleResult) bool {
	select {
	case r.ch <- res:
		return true
	case <-ctx.Done():
		return false
	}
}

func (r *searchResponse) start(ctx context.Context, searchRequest *SearchRequest) {
	go func() {
		defer func() {
			close(r.ch)
			if err := recover(); err != nil {
				r.conn.setError(fmt.Errorf("ldap: recovered panic in searchResponse: %v", err))
			}
		}()

		if r.conn.IsClosing() {
			return
		}

		packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
		packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, r.conn.nextMessageID(), "MessageID"))
		// encode search request
		err := searchRequest.appendTo(packet)
		if err != nil {
			r.send(ctx, &SearchSingleResult{Error: err})
			return
		}
		r.conn.Debug.PrintPacket(packet)

		msgCtx, err := r.conn.sendMessage(packet)
		if err != nil {
			r.send(ctx, &SearchSingleResult{Error: err})
			return
		}
		defer r.conn.finishMessage(msgCtx)

		foundSearchSingleResultDone := false
		for !foundSearchSingleResultDone {
			r.conn.Debug.Printf("%d: waiting for response", msgCtx.id)
			select {
			case <-ctx.Done():
				r.conn.Debug.Printf("%d: %s", msgCtx.id, ctx.Err().Error())
				return
			case packetResponse, ok := <-msgCtx.responses:
				if !ok {
					err := NewError(ErrorNetwork, errors.New("ldap: response channel closed"))
					r.send(ctx, &SearchSingleResult{Error: err})
					return
				}
				packet, err = packetResponse.ReadPacket()
				r.conn.Debug.Printf("%d: got response %p", msgCtx.id, packet)
				if err != nil {
					r.send(ctx, &SearchSingleResult{Error: err})
					return
				}

				if r.conn.Debug {
					if err := addLDAPDescriptions(packet); err != nil {
						r.send(ctx, &SearchSingleResult{Error: err})
						return
					}
					ber.PrintPacket(packet)
				}

				protocolOp, err := packetChild(packet, 1)
				if err != nil {
					r.send(ctx, &SearchSingleResult{Error: err})
					return
				}

				switch protocolOp.Tag {
				case ApplicationSearchResultEntry:
					attributesChild, err := packetChild(protocolOp, 1)
					if err != nil {
						r.send(ctx, &SearchSingleResult{Error: err})
						return
					}
					attributes, err := unpackAttributes(attributesChild.Children)
					if err != nil {
						r.ch <- &SearchSingleResult{Error: err}
						return
					}
					dn, err := packetStringAt(protocolOp, 0)
					if err != nil {
						r.ch <- &SearchSingleResult{Error: err}
						return
					}
					result := &SearchSingleResult{
						Entry: &Entry{
							DN:         dn,
							Attributes: attributes,
						},
					}
					entryChildren, err := packetChildCount(packet, 2, 3, "search result entry")
					if err != nil {
						r.send(ctx, &SearchSingleResult{Error: err})
						return
					}
					if len(entryChildren) != 3 {
						if !r.send(ctx, result) {
							return
						}
						continue
					}
					controlsChild, err := packetChild(packet, 2)
					if err != nil {
						r.send(ctx, &SearchSingleResult{Error: err})
						return
					}
					controlChild, err := packetChild(controlsChild, 0)
					if err != nil {
						r.send(ctx, &SearchSingleResult{Error: err})
						return
					}
					decoded, err := DecodeControl(controlChild)
					if err != nil {
						werr := fmt.Errorf("failed to decode search result entry: %w", err)
						result.Error = werr
						r.send(ctx, result)
						return
					}
					result.Controls = append(result.Controls, decoded)
					if !r.send(ctx, result) {
						return
					}

				case ApplicationSearchResultDone:
					if err := GetLDAPError(packet); err != nil {
						r.send(ctx, &SearchSingleResult{Error: err})
						return
					}
					doneChildren, err := packetChildCount(packet, 2, 3, "search result done")
					if err != nil {
						r.send(ctx, &SearchSingleResult{Error: err})
						return
					}
					if len(doneChildren) == 3 {
						controlsChild, err := packetChild(packet, 2)
						if err != nil {
							r.send(ctx, &SearchSingleResult{Error: err})
							return
						}
						result := &SearchSingleResult{}
						for _, child := range controlsChild.Children {
							decodedChild, err := DecodeControl(child)
							if err != nil {
								werr := fmt.Errorf("failed to decode child control: %w", err)
								r.send(ctx, &SearchSingleResult{Error: werr})
								return
							}
							result.Controls = append(result.Controls, decodedChild)
						}
						r.send(ctx, result)
					}
					foundSearchSingleResultDone = true

				case ApplicationSearchResultReference:
					ref, err := packetStringAt(protocolOp, 0)
					if err != nil {
						r.send(ctx, &SearchSingleResult{Error: err})
						return
					}
					if !r.send(ctx, &SearchSingleResult{Referral: ref}) {
						return
					}

				case ApplicationIntermediateResponse:
					decoded, err := DecodeControl(protocolOp)
					if err != nil {
						werr := fmt.Errorf("failed to decode intermediate response: %w", err)
						r.send(ctx, &SearchSingleResult{Error: werr})
						return
					}
					result := &SearchSingleResult{}
					result.Controls = append(result.Controls, decoded)
					if !r.send(ctx, result) {
						return
					}

				default:
					err := fmt.Errorf("unknown tag: %d", protocolOp.Tag)
					r.send(ctx, &SearchSingleResult{Error: err})
					return
				}
			}
		}
		r.conn.Debug.Printf("%d: returning", msgCtx.id)
	}()
}

func newSearchResponse(conn *Conn, bufferSize int) *searchResponse {
	var ch chan *SearchSingleResult
	if bufferSize > 0 {
		ch = make(chan *SearchSingleResult, bufferSize)
	} else {
		ch = make(chan *SearchSingleResult)
	}
	return &searchResponse{
		conn: conn,
		ch:   ch,
	}
}
