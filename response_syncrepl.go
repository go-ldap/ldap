package ldap

import (
	"context"
	"errors"
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
)

type syncreplResponse struct {
	sr *searchResponse
}

// Entry returns an entry from the given search request
func (r *syncreplResponse) Entry() *Entry {
	return r.sr.entry
}

// Referral returns a referral from the given search request
func (r *syncreplResponse) Referral() string {
	return r.sr.referral
}

// Controls returns controls from the given search request
func (r *syncreplResponse) Controls() []Control {
	return r.sr.controls
}

// Err returns an error when the given search request was failed
func (r *syncreplResponse) Err() error {
	return r.sr.err
}

// Next returns whether next data exist or not
func (r *syncreplResponse) Next() bool {
	return r.sr.Next()
}

func (r *syncreplResponse) start(ctx context.Context, searchRequest *SearchRequest) {
	go func() {
		defer func() {
			close(r.sr.ch)
			if err := recover(); err != nil {
				r.sr.conn.err = fmt.Errorf("ldap: recovered panic in syncreplResponse: %v", err)
			}
		}()

		if r.sr.conn.IsClosing() {
			return
		}

		packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
		packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, r.sr.conn.nextMessageID(), "MessageID"))
		// encode search request
		err := searchRequest.appendTo(packet)
		if err != nil {
			r.sr.ch <- &SearchSingleResult{Error: err}
			return
		}
		r.sr.conn.Debug.PrintPacket(packet)

		msgCtx, err := r.sr.conn.sendMessage(packet)
		if err != nil {
			r.sr.ch <- &SearchSingleResult{Error: err}
			return
		}
		defer r.sr.conn.finishMessage(msgCtx)

		for {
			select {
			case <-ctx.Done():
				r.sr.conn.Debug.Printf("%d: %s", msgCtx.id, ctx.Err().Error())
				return
			default:
				r.sr.conn.Debug.Printf("%d: waiting for response", msgCtx.id)
				packetResponse, ok := <-msgCtx.responses
				if !ok {
					err := NewError(ErrorNetwork, errors.New("ldap: response channel closed"))
					r.sr.ch <- &SearchSingleResult{Error: err}
					return
				}
				packet, err = packetResponse.ReadPacket()
				r.sr.conn.Debug.Printf("%d: got response %p", msgCtx.id, packet)
				if err != nil {
					r.sr.ch <- &SearchSingleResult{Error: err}
					return
				}

				switch packet.Children[1].Tag {
				case ApplicationSearchResultEntry:
					result := &SearchSingleResult{
						Entry: &Entry{
							DN:         packet.Children[1].Children[0].Value.(string),
							Attributes: unpackAttributes(packet.Children[1].Children[1].Children),
						},
					}
					if len(packet.Children) != 3 {
						r.sr.ch <- result
						continue
					}
					controlPacket := packet.Children[2].Children[0]
					decoded, err := DecodeSyncreplControl(controlPacket)
					if err != nil {
						werr := fmt.Errorf("failed to decode search result entry: %w", err)
						result.Error = werr
						r.sr.ch <- result
						return
					}
					result.Controls = append(result.Controls, decoded)
					r.sr.ch <- result

				case ApplicationSearchResultDone:
					if err := GetLDAPError(packet); err != nil {
						r.sr.ch <- &SearchSingleResult{Error: err}
						return
					}
					if len(packet.Children) != 3 {
						return
					}
					controlPacket := packet.Children[2].Children[0]
					decoded, err := DecodeSyncreplControl(controlPacket)
					if err != nil {
						werr := fmt.Errorf("failed to decode search result done: %w", err)
						r.sr.ch <- &SearchSingleResult{Error: werr}
						return
					}
					result := &SearchSingleResult{}
					result.Controls = append(result.Controls, decoded)
					r.sr.ch <- result
					return

				case ApplicationIntermediateResponse:
					decoded, err := DecodeSyncreplControl(packet.Children[1])
					if err != nil {
						werr := fmt.Errorf("failed to decode intermediate response: %w", err)
						r.sr.ch <- &SearchSingleResult{Error: werr}
						return
					}
					result := &SearchSingleResult{}
					result.Controls = append(result.Controls, decoded)
					r.sr.ch <- result

				default:
					r.sr.conn.Debug.Printf("got application code: %d", packet.Children[1].Tag)
				}
			}
		}
	}()
}

func newSyncreplResponse(conn *Conn, bufferSize int) *syncreplResponse {
	return &syncreplResponse{
		sr: newSearchResponse(conn, bufferSize),
	}
}
