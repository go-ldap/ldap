package ldap

import (
	"context"
	"errors"
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// IntermediateResponse represents an IntermediateResponse message sent by the
// server while an operation is in progress.
// See: https://www.rfc-editor.org/rfc/rfc4511#section-4.13
type IntermediateResponse struct {
	// IntermediateResponse ::= [APPLICATION 25] SEQUENCE {
	//   responseName     [0] LDAPOID OPTIONAL,
	//   responseValue    [1] OCTET STRING OPTIONAL }

	// Name is the responseName, empty when the server omitted it.
	Name string
	// Value is the responseValue element as received (its Data holds the
	// octets), nil when the server omitted it.
	Value *ber.Packet
	// Controls are the controls attached to the message.
	Controls []Control
}

// ExtendedAsyncResponse gives access to the responses of an extended operation
// started with ExtendedAsync: the IntermediateResponse messages, one at a
// time, and then the final ExtendedResponse.
//
//	r := l.ExtendedAsync(ctx, req, 64)
//	for r.Next() {
//		handle(r.Intermediate())
//	}
//	if err := r.Err(); err != nil {
//		// network error, ctx done, or the resultCode of the final response
//	}
//	final := r.Response() // may be non-nil also when Err() is an LDAP error
type ExtendedAsyncResponse interface {
	// Next waits for the next IntermediateResponse and reports whether one
	// is available through Intermediate. It returns false when the final
	// ExtendedResponse has been received, when ctx is done or on error.
	Next() bool
	// Intermediate returns the IntermediateResponse read by the last call to
	// Next that returned true.
	Intermediate() *IntermediateResponse
	// Response returns the final ExtendedResponse once Next has returned
	// false, or nil if it was not received. When the server returned a
	// resultCode other than success, Err reports it and Response still holds
	// the decoded responseName, responseValue and controls.
	Response() *ExtendedResponse
	// Err returns the error that ended the operation, if any: a network or
	// decoding error, ctx.Err(), or the *Error built from the resultCode of
	// the final ExtendedResponse.
	Err() error
}

// ExtendedAsync performs an extended request and returns an
// ExtendedAsyncResponse to read the IntermediateResponse messages sent by the
// server (RFC 4511 section 4.13) and then the final ExtendedResponse.
//
// The responses are read in a separate goroutine and buffered up to
// bufferSize messages (at least 1). The operation ends when the final
// ExtendedResponse is received, on error, or when ctx is done; cancelling ctx
// stops reading on the client side only, it does not abandon the operation on
// the server.
//
// The messages are queued in memory as they arrive, so a caller that reads
// them slowly does not block the other requests of the connection. A caller
// that stops calling Next before the operation ends must cancel ctx to release
// them. The methods of the returned ExtendedAsyncResponse must be called from a
// single goroutine.
func (l *Conn) ExtendedAsync(ctx context.Context, er *ExtendedRequest, bufferSize int) ExtendedAsyncResponse {
	r := newExtendedAsyncResponse(ctx, l, bufferSize)
	if er == nil {
		r.ch <- &extendedAsyncResult{err: NewError(ErrorNetwork, errors.New("ExtendedRequest cannot be nil"))}
		close(r.ch)
		return r
	}
	r.start(er)
	return r
}

type extendedAsyncResult struct {
	intermediate *IntermediateResponse
	response     *ExtendedResponse
	err          error
}

type extendedAsyncResponse struct {
	ctx  context.Context
	conn *Conn
	ch   chan *extendedAsyncResult

	intermediate *IntermediateResponse
	response     *ExtendedResponse
	err          error
	done         bool
}

func newExtendedAsyncResponse(ctx context.Context, conn *Conn, bufferSize int) *extendedAsyncResponse {
	// at least one slot, so the nil-request error never blocks ExtendedAsync
	return &extendedAsyncResponse{
		ctx:  ctx,
		conn: conn,
		ch:   make(chan *extendedAsyncResult, max(bufferSize, 1)),
	}
}

// Next implements ExtendedAsyncResponse.
func (r *extendedAsyncResponse) Next() bool {
	if r.done {
		return false
	}
	res, ok := <-r.ch
	if !ok || res == nil {
		r.done = true
		r.intermediate = nil
		if r.err == nil && r.response == nil {
			// the reader stopped without a final response: report why
			if err := r.ctx.Err(); err != nil {
				r.err = err
			} else {
				r.err = NewError(ErrorNetwork, errRespChanClosed)
			}
		}
		return false
	}
	if res.intermediate != nil {
		r.intermediate = res.intermediate
		return true
	}
	r.done = true
	r.intermediate = nil
	r.response = res.response
	r.err = res.err
	return false
}

// Intermediate implements ExtendedAsyncResponse.
func (r *extendedAsyncResponse) Intermediate() *IntermediateResponse {
	return r.intermediate
}

// Response implements ExtendedAsyncResponse.
func (r *extendedAsyncResponse) Response() *ExtendedResponse {
	return r.response
}

// Err implements ExtendedAsyncResponse.
func (r *extendedAsyncResponse) Err() error {
	return r.err
}

// send enqueues a result, giving up when ctx is done so an abandoned consumer
// cannot block the reader goroutine forever.
func (r *extendedAsyncResponse) send(res *extendedAsyncResult) bool {
	select {
	case r.ch <- res:
		return true
	case <-r.ctx.Done():
		return false
	}
}

func (r *extendedAsyncResponse) start(er *ExtendedRequest) {
	go func() {
		defer func() {
			close(r.ch)
			if err := recover(); err != nil {
				r.conn.setError(fmt.Errorf("ldap: recovered panic in extendedAsyncResponse: %v", err))
			}
		}()

		msgCtx, err := r.conn.doRequest(er)
		if err != nil {
			r.send(&extendedAsyncResult{err: err})
			return
		}
		defer r.conn.finishMessage(msgCtx)

		for {
			r.conn.Debug.Printf("%d: waiting for response", msgCtx.id)
			var packetResponse *PacketResponse
			var ok bool
			select {
			case <-r.ctx.Done():
				r.conn.Debug.Printf("%d: %s", msgCtx.id, r.ctx.Err().Error())
				return
			case packetResponse, ok = <-msgCtx.responses:
			}
			if !ok {
				r.send(&extendedAsyncResult{err: NewError(ErrorNetwork, errRespChanClosed)})
				return
			}
			packet, err := packetResponse.ReadPacket()
			r.conn.Debug.Printf("%d: got response %p", msgCtx.id, packet)
			if err == nil && packet == nil {
				err = NewError(ErrorNetwork, errCouldNotRetMsg)
			}
			if err != nil {
				r.send(&extendedAsyncResult{err: err})
				return
			}
			if r.conn.Debug {
				if err := addLDAPDescriptions(packet); err != nil {
					r.send(&extendedAsyncResult{err: err})
					return
				}
				ber.PrintPacket(packet)
			}

			protocolOp, err := packetChild(packet, 1)
			if err != nil {
				r.send(&extendedAsyncResult{err: err})
				return
			}
			switch protocolOp.Tag {
			case ApplicationIntermediateResponse:
				intermediate, err := decodeIntermediateResponse(packet)
				if err != nil {
					r.send(&extendedAsyncResult{err: err})
					return
				}
				if !r.send(&extendedAsyncResult{intermediate: intermediate}) {
					return
				}
			case ApplicationExtendedResponse:
				response, err := decodeExtendedResponseFields(packet)
				if err != nil {
					r.send(&extendedAsyncResult{err: err})
					return
				}
				r.send(&extendedAsyncResult{response: response, err: GetLDAPError(packet)})
				return
			default:
				r.send(&extendedAsyncResult{err: fmt.Errorf("ldap: unexpected response tag %d for an extended request", protocolOp.Tag)})
				return
			}
		}
	}()
}

// decodeIntermediateResponse decodes an IntermediateResponse envelope,
// including any response controls. It is kept out of the network loop so it
// can be exercised directly by the fuzz targets.
func decodeIntermediateResponse(packet *ber.Packet) (*IntermediateResponse, error) {
	protocolOp, err := packetChild(packet, 1)
	if err != nil {
		return nil, err
	}
	if protocolOp.ClassType != ber.ClassApplication || protocolOp.Tag != ApplicationIntermediateResponse {
		return nil, fmt.Errorf("ldap: expected an intermediate response, got tag %d", protocolOp.Tag)
	}
	response := &IntermediateResponse{}
	for _, child := range protocolOp.Children {
		if child.ClassType != ber.ClassContext {
			continue
		}
		switch child.Tag {
		case 0:
			name, err := packetData(child)
			if err != nil {
				return nil, err
			}
			response.Name = string(name)
		case 1:
			response.Value = child
		}
	}
	controlsChild, ok, err := packetChildIfPresent(packet, 2)
	if err != nil {
		return nil, err
	}
	if ok {
		for _, child := range controlsChild.Children {
			decoded, err := DecodeControl(child)
			if err != nil {
				return nil, fmt.Errorf("failed to decode intermediate response control: %w", err)
			}
			response.Controls = append(response.Controls, decoded)
		}
	}
	return response, nil
}
