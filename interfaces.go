package hub

import (
	"net/http"
	"time"

	"github.com/gofrs/uuid"
)

type Perm string

type User interface {
	Fields() UserFields
	UpdateAvatar(url string, fileName string) error
}

// IssueToken contains token information used for login and verifying accounts
type IssuedToken interface {
	ID() string
	Blacklisted() bool
}

type UserFields interface {
	ID() uuid.UUID
	Email() string
	FirstName() string
	LastName() string
	Verified() bool
	Deleted() bool
	AvatarID() *uuid.UUID
	Nonce() string
	PublicAddress() string
	DeletedAt() *time.Time
}

type Sessions interface {
	Connect(*Client)
	Login(*Client)
	Disconnect(*Client)
	Cookie(*http.Request) *http.Cookie
	User(*http.Request) User
}
