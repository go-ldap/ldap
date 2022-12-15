package ldap

import (
	"context"
	"crypto/tls"
	"time"
)

// Client knows how to interact with an LDAP server
type Client interface {
	Start()
	StartTLS(*tls.Config) error
	Close()
	IsClosing() bool
	SetTimeout(time.Duration)
	TLSConnectionState() (tls.ConnectionState, bool)

	Bind(username, password string) error
	UnauthenticatedBind(username string) error
	SimpleBind(*SimpleBindRequest) (*SimpleBindResult, error)
	ExternalBind() error
	NTLMUnauthenticatedBind(domain, username string) error
	Unbind() error

	Add(*AddRequest) error
	AddContext(context.Context, *AddRequest) error
	Del(*DelRequest) error
	DelContext(context.Context, *DelRequest) error
	Modify(*ModifyRequest) error
	ModifyContext(context.Context, *ModifyRequest) error
	ModifyDN(*ModifyDNRequest) error
	ModifyDNContext(context.Context, *ModifyDNRequest) error
	ModifyWithResult(*ModifyRequest) (*ModifyResult, error)
	ModifyWithResultContext(context.Context, *ModifyRequest) (*ModifyResult, error)

	Compare(dn, attribute, value string) (bool, error)
	CompareContext(ctx context.Context, dn, attribute, value string) (bool, error)
	PasswordModify(*PasswordModifyRequest) (*PasswordModifyResult, error)
	PasswordModifyContext(context.Context, *PasswordModifyRequest) (*PasswordModifyResult, error)

	Search(*SearchRequest) (*SearchResult, error)
	SearchContext(context.Context, *SearchRequest) (*SearchResult, error)
	SearchWithPaging(searchRequest *SearchRequest, pagingSize uint32) (*SearchResult, error)
	SearchWithPagingContext(ctx context.Context, searchRequest *SearchRequest, pagingSize uint32) (*SearchResult, error)
}
