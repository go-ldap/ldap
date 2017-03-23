package ldap

import (
	"crypto/tls"
	"log"
)

// PoolConn implements Client to override the Close() method
type PoolConn struct {
	Conn     Client
	c        *channelPool
	unusable bool
	closeAt  []uint8
}

func (p *PoolConn) Start() {
	p.Conn.Start()
}

func (p *PoolConn) StartTLS(config *tls.Config) error {
	// FIXME - check if already TLS and then ignore?
	return p.Conn.StartTLS(config)
}

// Close() puts the given connects back to the pool instead of closing it.
func (p *PoolConn) Close() {
	if p.unusable {
		log.Printf("Closing unusable connection %v", p.Conn)
		if p.Conn != nil {
			p.Conn.Close()
		}
		return
	}
	p.c.put(p.Conn)
}

func (p *PoolConn) Alive() bool {
	if !p.Conn.Alive() {
		p.MarkUnusable()
		return false
	}
	return true
}

func (p *PoolConn) SimpleBind(simpleBindRequest *SimpleBindRequest) (*SimpleBindResult, error) {
	return p.Conn.SimpleBind(simpleBindRequest)
}

func (p *PoolConn) Bind(username, password string) error {
	return p.Conn.Bind(username, password)
}

// MarkUnusable() marks the connection not usable any more, to let the pool close it
// instead of returning it to pool.
func (p *PoolConn) MarkUnusable() {
	p.unusable = true
}

func (p *PoolConn) autoClose(err error) {
	for _, code := range p.closeAt {
		if IsErrorWithCode(err, code) {
			p.MarkUnusable()
			return
		}
	}
}

func (p *PoolConn) Add(addRequest *AddRequest) error {
	return p.Conn.Add(addRequest)
}

func (p *PoolConn) Del(delRequest *DelRequest) error {
	return p.Conn.Del(delRequest)
}

func (p *PoolConn) Modify(modifyRequest *ModifyRequest) error {
	return p.Conn.Modify(modifyRequest)
}

func (p *PoolConn) Compare(dn, attribute, value string) (bool, error) {
	return p.Conn.Compare(dn, attribute, value)
}

func (p *PoolConn) PasswordModify(passwordModifyRequest *PasswordModifyRequest) (*PasswordModifyResult, error) {
	return p.Conn.PasswordModify(passwordModifyRequest)
}

func (p *PoolConn) Search(searchRequest *SearchRequest) (*SearchResult, error) {
	return p.Conn.Search(searchRequest)
}
func (p *PoolConn) SearchWithPaging(searchRequest *SearchRequest, pagingSize uint32) (*SearchResult, error) {
	return p.Conn.SearchWithPaging(searchRequest, pagingSize)
}
