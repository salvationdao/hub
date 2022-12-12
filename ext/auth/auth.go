package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"

	goaway "github.com/TwiN/go-away"
	"github.com/ethereum/go-ethereum/common"
	"github.com/salvationdao/hub"

	"net/http"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v4"

	"github.com/lestrrat-go/jwx/jwt/openid"

	oidc "github.com/coreos/go-oidc"
	twitch_jwt "github.com/golang-jwt/jwt"

	"github.com/gofrs/uuid"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/salvationdao/terror"
	"google.golang.org/api/idtoken"
)

// Auth holds handlers for authentication
type Auth struct {
	hub                      *hub.Hub
	cookieSecure             bool
	google                   *GoogleConfig
	twitch                   *TwitchConfig
	twitter                  *TwitterConfig
	discord                  *DiscordConfig
	user                     UserController
	sessions                 hub.Sessions
	tokens                   Tokens
	eip712Message            string
	whitelist                bool
	createUserIfNotExist     bool
	createAndGetOAuthUserVia IdType
	walletConnectOnly        bool
	whitelistCheckEndpoint   string
}

type SecureUser interface {
	CheckPassword(pw string) bool
	SendVerificationEmail(token string, tokenID string, newAccount bool) error
	SendForgotPasswordEmail(token string, tokenID string) error
	Verify() error
	UpdatePasswordSetting(oldPasswordRequired bool) error
	HasPermission(perm string) bool
	NewNonce() (string, error)
	hub.User
}

type GoogleConfig struct {
	ClientID string
}

type TwitchConfig struct {
	ExtensionSecret []byte
	ClientID        string
	ClientSecret    string
}

type TwitterConfig struct {
	APIKey    string
	APISecret string
}

type DiscordConfig struct {
	ClientID     string
	ClientSecret string
}

type IdType string

const IdTypeID IdType = "ID"
const IdTypeEmail IdType = "Email"

func (idt IdType) IsValid() bool {
	switch idt {
	case IdTypeID, IdTypeEmail:
		return true
	default:
		return false
	}
}

type Config struct {
	Google  *GoogleConfig
	Twitch  *TwitchConfig
	Twitter *TwitterConfig
	Discord *DiscordConfig

	// user
	UserController           UserController
	CreateUserIfNotExist     bool
	CreateAndGetOAuthUserVia IdType // defaults to Email

	CookieSecure           bool
	Tokens                 Tokens
	Whitelist              bool
	Eip712Message          string
	OnlyWalletConnect      bool
	WhitelistCheckEndpoint string
}

type UserController interface {
	ID(uuid.UUID) (SecureUser, error)
	Token(uuid.UUID) (SecureUser, error)
	Email(string) (SecureUser, error)
	Username(string) (SecureUser, error)
	PublicAddress(string) (SecureUser, error)
	FacebookID(string) (SecureUser, error)
	GoogleID(string) (SecureUser, error)
	TwitchID(string) (SecureUser, error)
	TwitterID(string) (SecureUser, error)
	DiscordID(string) (SecureUser, error)
	UserCreator(firstName, lastName, username, email, facebookID, googleID, twitchID, twitterID, discordID, number, publicAddress, password string, other ...interface{}) (SecureUser, error)
	FingerprintUpsert(fingerprint Fingerprint, userID uuid.UUID) error
}

type Tokens interface {
	Save(token string) error
	Remove(uuid.UUID) error
	Retrieve(uuid.UUID) (Token, SecureUser, error)
	TokenExpirationDays() int
	EncryptToken() bool
	EncryptTokenKey() []byte
}

type Token interface {
	Whitelisted() bool
	TokenID() uuid.UUID
}

const (
	EventLogin       hub.Event = "AUTH:LOGIN"
	EventIssuedToken hub.Event = "AUTH:ISSUEDTOKEN"
	EventLogout      hub.Event = "AUTH:LOGOUT"
)

type TokenAction string

func (t *TokenAction) String() string {
	return string(*t)
}

const LoginAction TokenAction = "LOGIN"
const EmailVerificationAction TokenAction = "VERIFYEMAIL"

// ErrTokenNotWhitelisted is returned when an issue token is not found
var ErrTokenNotWhitelisted = fmt.Errorf("token is blacklisted")
var ErrUserNotMatch = fmt.Errorf("provided user account does not match")

var ErrNoUserRetrievalConfig = errors.New("nil user retrieval interface")
var ErrNoTokensConfig = errors.New("nil token retrieval interface")
var ErrTokenEncryptButNoKey = errors.New("missing token encrypt key")
var ErrTokenExpired = errors.New("token has expired")

// ErrUserAlreadyVerified is returned when processing an unverified user that is already verified
var ErrUserAlreadyVerified = fmt.Errorf("user is already verified")

func New(hub *hub.Hub, config *Config) (*Auth, error) {
	// TODO: rework config, since it cannot be nil itself?
	// TODO: add twitch extension secret AND twitch oAuth details for website
	if config.UserController == nil {
		return nil, ErrNoUserRetrievalConfig
	}
	if config.Tokens == nil {
		return nil, ErrNoTokensConfig
	}
	cookieSecure := false
	idType := IdTypeEmail
	var google *GoogleConfig
	var twitch *TwitchConfig
	var twitter *TwitterConfig
	var discord *DiscordConfig
	if config != nil {
		cookieSecure = config.CookieSecure
		google = config.Google
		twitch = config.Twitch
		twitter = config.Twitter
		discord = config.Discord
		if config.Tokens.EncryptToken() && (config.Tokens.EncryptTokenKey() == nil || len(config.Tokens.EncryptTokenKey()) == 0) {
			return nil, ErrTokenEncryptButNoKey
		}
		if config.CreateAndGetOAuthUserVia.IsValid() {
			idType = config.CreateAndGetOAuthUserVia
		}
	}
	auth := &Auth{
		cookieSecure:             cookieSecure,
		hub:                      hub,
		user:                     config.UserController,
		google:                   google,
		twitch:                   twitch,
		twitter:                  twitter,
		discord:                  discord,
		tokens:                   config.Tokens,
		eip712Message:            config.Eip712Message,
		createUserIfNotExist:     config.CreateUserIfNotExist,
		createAndGetOAuthUserVia: idType,
		walletConnectOnly:        config.OnlyWalletConnect,
		whitelistCheckEndpoint:   config.WhitelistCheckEndpoint,
	}

	hub.Handle(HubKeyAuthRegister, auth.RegisterUserHandler)
	hub.Handle(HubKeyAuthPasswordLogin, auth.PasswordLoginHandler)
	hub.Handle(HubKeyAuthTokenLogin, auth.TokenLoginHandler)
	hub.Handle(HubKeyAuthSignUpWallet, auth.WalletSignUpHandler)
	hub.Handle(HubKeyAuthLoginWallet, auth.WalletLoginHandler)
	hub.Handle(HubKeyAuthSignUpGoogle, auth.GoogleSignUpHandler)
	hub.Handle(HubKeyAuthLoginGoogle, auth.GoogleLoginHandler)
	hub.Handle(HubKeyAuthSignUpFacebook, auth.FacebookSignUpHandler)
	hub.Handle(HubKeyAuthLoginFacebook, auth.FacebookLoginHandler)
	hub.Handle(HubKeyAuthSignUpTwitch, auth.TwitchSignUpHandler)
	hub.Handle(HubKeyAuthLoginTwitch, auth.TwitchLoginHandler)
	hub.Handle(HubKeyAuthLoginTwitchExtension, auth.TwitchExtensionLoginHandler)
	hub.Handle(HubKeyAuthSignUpTwitter, auth.TwitterSignUpHandler)
	hub.Handle(HubKeyAuthLoginTwitter, auth.TwitterLoginHandler)
	hub.Handle(HubKeyAuthSignUpDiscord, auth.DiscordSignUpHandler)
	hub.Handle(HubKeyAuthLoginDiscord, auth.DiscordLoginHandler)
	hub.Handle(HubKeyAuthSendVerifyEmail, auth.SendVerifyEmailHandler)
	hub.Handle(HubKeyAuthLogout, auth.TokenLogoutHandler)
	return auth, nil
}

// Login checks user is valid to log and triggers the login event
func (auth *Auth) Login(user SecureUser, hubc *hub.Client) error {
	if !hubc.LockClient {
		hubc.SetIdentifier(user.Fields().ID().String())
	}

	if user.Fields().DeletedAt() != nil {
		return terror.Error(terror.ErrUnauthorised, "This account is no longer active")
	}

	// trigger login event
	auth.hub.Events.Trigger(context.Background(), EventLogin, hubc, func(err error) {})

	return nil
}

func (auth *Auth) EvaluateClientBySessionID(user SecureUser, sessionID hub.SessionID) error {
	hubc, ok := auth.hub.Client(sessionID)
	if !ok {
		return terror.Error(ErrNoUserInformation, "session not found")
	}

	if !hubc.LockClient {
		hubc.SetIdentifier(user.Fields().ID().String())
	}

	if user.Fields().DeletedAt() != nil {
		return terror.Error(ErrNoUserInformation, "user does not exist")
	}

	auth.hub.Events.Trigger(context.Background(), EventLogin, hubc, func(err error) {})

	return nil
}

type IssueTokenConfig struct {
	Encrypted bool
	Key       []byte
	Device    string
	Action    TokenAction
	Email     string
	Picture   string
	User      SecureUser
	Mutate    func(jwt.Token) jwt.Token
}

var ErrNoUserInformation = errors.New("no user information provided to IssueToken()")

func (auth *Auth) IssueToken(hubc *hub.Client, config *IssueTokenConfig) (SecureUser, uuid.UUID, string, error) {
	var err error
	errMsg := "There was a problem with your authentication, please check your details and try again."

	// Get user by email

	if config.Email == "" && config.User == nil {
		return nil, uuid.Nil, "", terror.Error(ErrNoUserInformation, errMsg)
	}
	var user SecureUser
	if config.User == nil {
		user, err = auth.user.Email(config.Email)
		if err != nil {
			return nil, uuid.Nil, "", terror.Error(err, errMsg)
		}
	} else {
		user = config.User
	}

	// No avatar? use google avatar
	if config.Picture != "" {
		if user.Fields().AvatarID() == nil && len(config.Picture) > 0 {
			err := user.UpdateAvatar(config.Picture, "google_profile_picture.jpg")
			if err != nil {
				return nil, uuid.Nil, "", terror.Error(err, errMsg)
			}
		}
	}

	if err := auth.Login(user, hubc); err != nil {
		return nil, uuid.Nil, "", err
	}

	tokenID := uuid.Must(uuid.NewV4())

	// save user detail in encrypted cookie and make it persist
	jwt, sign, err := GenerateJWT(
		tokenID,
		user,
		config.Device,
		config.Action.String(),
		false,
		auth.tokens.TokenExpirationDays())
	if err != nil {
		return nil, uuid.Nil, "", terror.Error(err, errMsg)
	}
	// Record token in issued token records
	if config.Mutate != nil {
		jwt = config.Mutate(jwt)
	}
	jwtSigned, err := sign(jwt, config.Encrypted, config.Key)
	if err != nil {
		return nil, uuid.Nil, "", terror.Error(err, "unable to sign jwt")
	}

	token := base64.StdEncoding.EncodeToString(jwtSigned)

	ctx := context.WithValue(context.WithValue(context.Background(), "jwt", jwt), "token", token)
	ctx = context.WithValue(ctx, "token-device", config.Device)

	err = auth.tokens.Save(token)
	if err != nil {
		return nil, uuid.Nil, "", terror.Error(err, "unable to save jwt")
	}

	auth.hub.Events.Trigger(ctx, EventIssuedToken, hubc, func(err error) {})

	return user, tokenID, token, nil
}

// HubKeyAuthTokenLogin for token login
const HubKeyAuthTokenLogin = hub.HubCommandKey("AUTH:TOKEN")

// TokenLoginRequest is an auth request that uses a JWT
type TokenLoginRequest struct {
	*hub.HubCommandRequest
	Payload struct {
		Token              string        `json:"token"`
		SessionID          hub.SessionID `json:"session_id"`
		TwitchExtensionJWT string        `json:"twitch_extension_jwt"`
		Fingerprint        *Fingerprint  `json:"fingerprint"`
	} `json:"payload"`
}

// TokenLoginResponse is an auth request that uses a JWT
type TokenLoginResponse struct {
	User SecureUser `json:"user"`
}

// TokenLoginHandler lets you log in with just a jwt
func (auth *Auth) TokenLoginHandler(ctx context.Context, hubc *hub.Client, payload []byte, reply hub.ReplyFunc) error {
	req := &TokenLoginRequest{}
	err := json.Unmarshal(payload, req)
	if err != nil {
		return terror.Error(err, "Failed to unmarshal req")
	}

	resp, err := auth.TokenLogin(ctx, hubc, req.Payload.Token, req.Payload.TwitchExtensionJWT)
	if err != nil {
		return terror.Error(err, "Failed to login")
	}

	// Fingerprint user
	if req.Payload.Fingerprint != nil {
		userID := resp.User.Fields().ID()
		// todo: include ip in upsert
		err = auth.DoFingerprintUpsert(*req.Payload.Fingerprint, userID)
		if err != nil {
			return err
		}
	}

	if req.Payload.SessionID != "" {
		auth.EvaluateClientBySessionID(resp.User, req.Payload.SessionID)
	}

	reply(resp)
	return nil
}

// TokenLogin gets a user from the token
func (auth *Auth) TokenLogin(ctx context.Context, hubc *hub.Client, tokenBase64 string, twitchExtensionJWT string) (*TokenLoginResponse, error) {
	tokenStr, err := base64.StdEncoding.DecodeString(tokenBase64)
	if err != nil {
		return nil, terror.Error(err, "")
	}

	token, err := ReadJWT(tokenStr, auth.tokens.EncryptToken(), auth.tokens.EncryptTokenKey())
	if err != nil {
		if errors.Is(err, ErrTokenExpired) {
			tknUuid, err := tokenID(token)
			if err != nil {
				return nil, terror.Error(err)
			}
			err = auth.tokens.Remove(tknUuid)
			if err != nil {
				return nil, terror.Error(err)
			}
			return nil, terror.Warn(err, "Session has expired, please log in again.")
		}
		return nil, terror.Error(err)
	}

	jwtIDI, ok := token.Get(openid.JwtIDKey)

	if !ok {
		return nil, terror.Error(errors.New("unable to get ID from token"), "unable to read token")
	}

	jwtID, err := uuid.FromString(jwtIDI.(string))
	if err != nil {
		return nil, terror.Error(err, "unable to form UUID from token")
	}

	retrievedToken, user, err := auth.tokens.Retrieve(jwtID)
	if err != nil {
		return nil, terror.Error(err)
	}

	if !retrievedToken.Whitelisted() {
		return nil, terror.Error(ErrTokenNotWhitelisted)
	}

	// check twitch extension jwt
	if twitchExtensionJWT != "" {
		claims, err := auth.GetClaimsFromTwitchExtensionToken(twitchExtensionJWT)
		if err != nil {
			return nil, terror.Error(err, "failed to parse twitch extension token")
		}

		twitchUser, err := auth.user.TwitchID(claims.TwitchAccountID)
		if err != nil {
			return nil, terror.Error(err, "failed to get twitch user")
		}

		// check twitch user match the token user
		if twitchUser.Fields().ID() != user.Fields().ID() {
			return nil, terror.Error(ErrUserNotMatch, "twitch id does not match")
		}
	}

	if err := auth.Login(user, hubc); err != nil {
		return nil, err
	}

	return &TokenLoginResponse{user}, nil
}

// HubKeyAuthLogout for token logout
const HubKeyAuthLogout = hub.HubCommandKey("AUTH:LOGOUT")

// TokenLogoutRequest is an auth request that uses a JWT
type TokenLogoutRequest struct {
	*hub.HubCommandRequest
	Payload struct {
		Token string `json:"token"`
	} `json:"payload"`
}

// TokenLogoutResponse is an auth request that uses a JWT
type TokenLogoutResponse struct {
	User SecureUser `json:"user"`
}

// TokenLogoutHandler lets you log in with just a jwt
func (auth *Auth) TokenLogoutHandler(ctx context.Context, hubc *hub.Client, payload []byte, reply hub.ReplyFunc) error {
	req := &TokenLogoutRequest{}
	err := json.Unmarshal(payload, req)
	if err != nil {
		return terror.Error(err, "Failed to unmarshal req")
	}
	tokenStr, err := base64.StdEncoding.DecodeString(req.Payload.Token)
	if err != nil {
		return terror.Error(err)
	}

	token, err := ReadJWT(tokenStr, auth.tokens.EncryptToken(), auth.tokens.EncryptTokenKey())
	if err != nil && !errors.Is(err, ErrTokenExpired) {
		return terror.Error(err)
	}

	jwtIDI, ok := token.Get(openid.JwtIDKey)

	if !ok {
		return terror.Error(errors.New("unable to get ID from token"), "unable to read token")
	}

	jwtID, err := uuid.FromString(jwtIDI.(string))
	if err != nil {
		return terror.Error(err, "unable to form UUID from token")
	}

	err = auth.tokens.Remove(jwtID)
	if err != nil {
		return terror.Error(err)
	}

	auth.hub.Events.Trigger(context.Background(), EventLogout, hubc, func(err error) {})

	reply(true)
	return nil
}

// HubKeyAuthPasswordLogin is the key used to run the AuthLogin handler
const HubKeyAuthPasswordLogin = hub.HubCommandKey("AUTH:LOGIN")

// PasswordLoginRequest is a request to login
type PasswordLoginRequest struct {
	*hub.HubCommandRequest
	Payload struct {
		Email       string        `json:"email"`
		Password    string        `json:"password"`
		SessionID   hub.SessionID `json:"session_id"`
		Fingerprint *Fingerprint  `json:"fingerprint"`
	} `json:"payload"`
}

// PasswordLoginResponse is a response for login
type PasswordLoginResponse struct {
	User  SecureUser `json:"user"`
	Token string     `json:"token"`
	IsNew bool       `json:"is_new"`
}

// PasswordLoginHandler handles JSON processing
func (auth *Auth) PasswordLoginHandler(ctx context.Context, hubc *hub.Client, payload []byte, reply hub.ReplyFunc) error {
	if auth.walletConnectOnly {
		return terror.Error(fmt.Errorf("wallet connect only"), "Only wallet connections are allowed during the whitelist period")
	}
	req := &PasswordLoginRequest{}
	err := json.Unmarshal(payload, req)
	if err != nil {
		return terror.Error(err, "Failed to unmarshal data")
	}

	resp, err := auth.PasswordLogin(ctx, hubc, strings.ToLower(req.Payload.Email), req.Payload.Password)
	if err != nil {
		return terror.Error(err)
	}

	// Fingerprint user
	if req.Payload.Fingerprint != nil {
		userID := resp.User.Fields().ID()
		// todo: include ip in upsert
		err = auth.DoFingerprintUpsert(*req.Payload.Fingerprint, userID)
		if err != nil {
			return err
		}
	}

	if req.Payload.SessionID != "" {
		auth.EvaluateClientBySessionID(resp.User, req.Payload.SessionID)
	}

	reply(resp)
	return nil
}

// PasswordLogin logs a user in with an email and password
func (auth *Auth) PasswordLogin(ctx context.Context, hubc *hub.Client, email, password string) (*PasswordLoginResponse, error) {
	// load user details
	errMsg := "There was a problem with your email or password, please check your details and try again."
	user, err := auth.user.Email(strings.ToLower(email))
	if err != nil {
		return nil, terror.Error(err, errMsg)
	}

	if !user.CheckPassword(password) {
		return nil, terror.Error(fmt.Errorf("wrong password"), errMsg)
	}

	_, _, token, err := auth.IssueToken(hubc, &IssueTokenConfig{
		Encrypted: auth.tokens.EncryptToken(),
		Key:       auth.tokens.EncryptTokenKey(),
		Device:    hubc.Request.UserAgent(),
		Action:    LoginAction,
		User:      user,
	})
	if err != nil {
		if errors.Is(err, ErrTokenExpired) {
			return nil, terror.Error(err, "Session has expired, please log in again.")
		}
		return nil, terror.Error(err, errMsg)
	}

	return &PasswordLoginResponse{user, token, false}, nil
}

const HubKeyAuthSignUpDiscord = hub.HubCommandKey("AUTH:SIGNUP_DISCORD")

type DiscordSignUpRequest struct {
	*hub.HubCommandRequest
	Payload struct {
		Code        string        `json:"code"`
		SessionID   hub.SessionID `json:"session_id"`
		RedirectURI string        `json:"redirect_uri"`
		Username    string        `json:"username"`
		Fingerprint *Fingerprint  `json:"fingerprint"`
	} `json:"payload"`
}

func (auth *Auth) DiscordSignUpHandler(ctx context.Context, hubc *hub.Client, payload []byte, reply hub.ReplyFunc) error {
	if auth.walletConnectOnly {
		return terror.Error(fmt.Errorf("wallet connect only"), "Only wallet connections are allowed during the whitelist period")
	}
	req := &DiscordSignUpRequest{}
	err := json.Unmarshal(payload, req)
	if err != nil {
		return terror.Error(err, "Failed to unmarshal req")
	}

	// Get user's Discord details
	discordDetails, err := auth.GetOAuthDiscordDetails(ctx, hubc, req.Payload.Code, req.Payload.RedirectURI)
	if err != nil {
		return terror.Error(err)
	}

	discordID := discordDetails.ID

	// Check if there are any existing users associated with that Discord ID
	user, err := auth.user.DiscordID(discordID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return terror.Error(err)
	}

	if user != nil {
		return terror.Error(fmt.Errorf("user already exists"), "A user with that Discord account already exists. Perhaps you'd like to login instead?")
	}

	// Create new user
	user, err = auth.user.UserCreator("", "", req.Payload.Username, "", "", "", "", "", discordID, "", "", "")
	if err != nil {
		return terror.Error(err)
	}

	// Fingerprint user
	if req.Payload.Fingerprint != nil {
		userID := user.Fields().ID()
		// todo: include ip in upsert
		err = auth.DoFingerprintUpsert(*req.Payload.Fingerprint, userID)
		if err != nil {
			return err
		}
	}

	user, _, token, err := auth.IssueToken(hubc, &IssueTokenConfig{
		Encrypted: auth.tokens.EncryptToken(),
		Key:       auth.tokens.EncryptTokenKey(),
		Device:    hubc.Request.UserAgent(),
		Action:    LoginAction,
		User:      user,
	})
	if err != nil {
		return terror.Error(err, "There was a problem creating the account, please try again.")
	}

	if req.Payload.SessionID != "" {
		auth.EvaluateClientBySessionID(user, req.Payload.SessionID)
	}
	reply(&RegisterResponse{user, token})

	return nil
}

type DiscordLoginRequest struct {
	*hub.HubCommandRequest
	Payload struct {
		Code        string        `json:"code"`
		SessionID   hub.SessionID `json:"session_id"`
		RedirectURI string        `json:"redirect_uri"`
		Fingerprint *Fingerprint  `json:"fingerprint"`
	} `json:"payload"`
}

const HubKeyAuthLoginDiscord = hub.HubCommandKey("AUTH:LOGIN_DISCORD")

func (auth *Auth) DiscordLoginHandler(ctx context.Context, hubc *hub.Client, payload []byte, reply hub.ReplyFunc) error {
	if auth.walletConnectOnly {
		return terror.Error(fmt.Errorf("wallet connect only"), "Only wallet connections are allowed during the whitelist period")
	}
	req := &DiscordLoginRequest{}
	err := json.Unmarshal(payload, req)
	if err != nil {
		return terror.Error(err, "Failed to unmarshal req")
	}

	// Get user's Discord details
	discordDetails, err := auth.GetOAuthDiscordDetails(ctx, hubc, req.Payload.Code, req.Payload.RedirectURI)
	if err != nil {
		return terror.Error(err)
	}
	discordID := discordDetails.ID
	username := discordDetails.Username
	truncID := discordID[len(discordID)-4:]

	// if username has profanity or too short
	if goaway.IsProfane(username) || len(username) <= 3 {
		username = fmt.Sprintf("twitch_%s", truncID)
	}

	// truncate username if too long
	if len(username) > 10 {
		username = username[0:9]
	}

	// Check if there are any existing users associated with that Discord ID
	user, err := auth.user.DiscordID(discordID)
	isNew := false
	if err != nil {
		newUsername := ""
		// check if any user with username exist
		_, err = auth.user.Username(username)
		// if username exist append the last part their discord id to username
		if err == nil {
			newUsername = fmt.Sprintf("%s_%s", username, truncID)
		}

		userNameExist := true
		if userNameExist {
			_, err = auth.user.Username(newUsername)
			// if new username exist append random chars to their username
			if err == nil {
				randStr := fmt.Sprintf("%s_%s", username, RandString())
				newUsername = username + randStr
			} else {
				userNameExist = false
			}
		}

		if newUsername == "" {
			newUsername = username
		}

		// If user does not exist, create new user with their username set to their Discord ID
		user, err = auth.user.UserCreator("", "", newUsername, "", "", "", "", "", discordID, "", "", "")
		if err != nil {
			return terror.Error(err)
		}

		// Indicate to client that user needs to sign up
		isNew = true
	}

	// Fingerprint user
	if req.Payload.Fingerprint != nil {
		userID := user.Fields().ID()
		// todo: include ip in upsert
		err = auth.DoFingerprintUpsert(*req.Payload.Fingerprint, userID)
		if err != nil {
			return err
		}
	}

	user, _, token, err := auth.IssueToken(hubc, &IssueTokenConfig{
		Encrypted: auth.tokens.EncryptToken(),
		Key:       auth.tokens.EncryptTokenKey(),
		Device:    hubc.Request.UserAgent(),
		Action:    LoginAction,
		User:      user,
	})
	if err != nil {
		return terror.Error(err, "There was a problem creating a session for your account, please try again.")
	}

	if req.Payload.SessionID != "" {
		auth.EvaluateClientBySessionID(user, req.Payload.SessionID)
	}
	reply(&PasswordLoginResponse{user, token, isNew})

	return nil
}

type DiscordDetails struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

// GetOAuthDiscordID will attempt to retrieve a Discord user's ID using the code and redirectURI.
// code is the code obtained from Discord's OAuth 2.0 flow.
// redirectURI specifies the URI of the callback URI specified when initialising the OAuth flow.
func (auth *Auth) GetOAuthDiscordDetails(ctx context.Context, hubc *hub.Client, code string, redirectURI string) (*DiscordDetails, error) {
	// Validate Discord code and get access token
	data := url.Values{}
	data.Set("code", code)
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", redirectURI)

	client := &http.Client{}
	req, err := http.NewRequest("POST", "https://discord.com/api/oauth2/token", strings.NewReader(data.Encode()))
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth.discord.ClientID+":"+auth.discord.ClientSecret)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		return nil, terror.Error(err)
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, terror.Error(err, "Failed to verify token")
	}
	defer res.Body.Close()

	resp := &struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
	}{}
	err = json.NewDecoder(res.Body).Decode(resp)
	if err != nil {
		return nil, terror.Error(err, "Failed to authenticate user with Discord.")
	}

	// Get Discord user using access token
	client = &http.Client{}
	req2, err := http.NewRequest("GET", "https://discord.com/api/oauth2/@me", nil)
	if err != nil {
		return nil, terror.Error(err)
	}
	req2.Header.Set("Authorization", "Bearer "+resp.AccessToken)
	res2, err := client.Do(req2)
	if err != nil {
		return nil, terror.Error(err, "Failed to get user with access token.")
	}
	defer res2.Body.Close()

	resp2 := &struct {
		User struct {
			ID       string `json:"id"`
			Username string `json:"username"`
		} `json:"user"`
	}{}
	err = json.NewDecoder(res2.Body).Decode(resp2)
	if err != nil {
		return nil, terror.Error(err, "Failed to authenticate user with Discord.")
	}

	return &DiscordDetails{ID: resp2.User.ID, Username: resp2.User.Username}, nil
}

type TwitterSignUpRequest struct {
	*hub.HubCommandRequest
	Payload struct {
		// Note that the token and verifier parameters come from Twitter's OAuth 1.0a flow
		OAuthToken    string        `json:"oauth_token"`
		OAuthVerifier string        `json:"oauth_verifier"`
		Username      string        `json:"username"`
		SessionID     hub.SessionID `json:"session_id"`
		Fingerprint   *Fingerprint  `json:"fingerprint"`
	} `json:"payload"`
}

const HubKeyAuthSignUpTwitter = hub.HubCommandKey("AUTH:SIGNUP_TWITTER")

func (auth *Auth) TwitterSignUpHandler(ctx context.Context, hubc *hub.Client, payload []byte, reply hub.ReplyFunc) error {
	if auth.walletConnectOnly {
		return terror.Error(fmt.Errorf("wallet connect only"), "Only wallet connections are allowed during the whitelist period")
	}
	req := &TwitterSignUpRequest{}
	err := json.Unmarshal(payload, req)
	if err != nil {
		return terror.Error(err, "Failed to unmarshal req")
	}

	// Get user's Twitter ID
	twitterDetails, err := auth.GetOAuthTwitterDetails(ctx, hubc, req.Payload.OAuthToken, req.Payload.OAuthVerifier)
	if err != nil {
		return terror.Error(err)
	}
	twitterID := twitterDetails.ID

	// Check if there are any existing users associated with that Twitter ID
	user, err := auth.user.TwitterID(twitterID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return terror.Error(err)
	}

	if user != nil {
		return terror.Error(fmt.Errorf("user already exists"), "A user with that Twitter account already exists. Perhaps you'd like to login instead?")
	}

	// Create new user
	user, err = auth.user.UserCreator("", "", req.Payload.Username, "", "", "", "", twitterID, "", "", "", "")
	if err != nil {
		return terror.Error(err)
	}

	// Fingerprint user
	if req.Payload.Fingerprint != nil {
		userID := user.Fields().ID()
		// todo: include ip in upsert
		err = auth.DoFingerprintUpsert(*req.Payload.Fingerprint, userID)
		if err != nil {
			return err
		}
	}

	user, _, token, err := auth.IssueToken(hubc, &IssueTokenConfig{
		Encrypted: auth.tokens.EncryptToken(),
		Key:       auth.tokens.EncryptTokenKey(),
		Device:    hubc.Request.UserAgent(),
		Action:    LoginAction,
		User:      user,
	})
	if err != nil {
		return terror.Error(err, "There was a problem creating a session for your account, please try again.")
	}

	if req.Payload.SessionID != "" {
		auth.EvaluateClientBySessionID(user, req.Payload.SessionID)
	}
	reply(&RegisterResponse{user, token})

	return nil
}

type TwitterLoginRequest struct {
	*hub.HubCommandRequest
	Payload struct {
		// Note that the token and verifier parameters come from Twitter's OAuth 1.0a flow
		OAuthToken    string        `json:"oauth_token"`
		OAuthVerifier string        `json:"oauth_verifier"`
		SessionID     hub.SessionID `json:"session_id"`
		Fingerprint   *Fingerprint  `json:"fingerprint"`
	} `json:"payload"`
}

const HubKeyAuthLoginTwitter = hub.HubCommandKey("AUTH:LOGIN_TWITTER")

func (auth *Auth) TwitterLoginHandler(ctx context.Context, hubc *hub.Client, payload []byte, reply hub.ReplyFunc) error {
	if auth.walletConnectOnly {
		return terror.Error(fmt.Errorf("wallet connect only"), "Only wallet connections are allowed during the whitelist period")
	}
	req := &TwitterLoginRequest{}
	err := json.Unmarshal(payload, req)
	if err != nil {
		return terror.Error(err, "Failed to unmarshal req")
	}

	// Get user's Twitter details
	twitterDetails, err := auth.GetOAuthTwitterDetails(ctx, hubc, req.Payload.OAuthToken, req.Payload.OAuthVerifier)
	if err != nil {
		return terror.Error(err)
	}

	twitterID := twitterDetails.ID
	truncID := twitterID[len(twitterID)-4:]
	username := twitterDetails.ScreenName

	// if username has profanity or too short
	if goaway.IsProfane(username) || len(username) <= 3 {
		username = fmt.Sprintf("twitter_%s", truncID)
	}

	// truncate username if too long
	if len(username) > 10 {
		username = username[0:9]
	}

	// Check if there are any existing users associated with that Twitter ID
	user, err := auth.user.TwitterID(twitterID)
	isNew := false
	if err != nil {

		newUsername := ""
		// check if any user with username exist
		_, err = auth.user.Username(username)
		// if username exist append last part of their google id to username
		if err == nil {
			newUsername = fmt.Sprintf("%s_%s", username, truncID)
		}

		_, err = auth.user.Username(newUsername)
		userNameExist := true
		if userNameExist {
			_, err = auth.user.Username(newUsername)
			// if new username exist append random chars to their username
			if err == nil {
				randStr := fmt.Sprintf("%s_%s", username, RandString())
				newUsername = username + randStr
			} else {
				userNameExist = false
			}
		}

		if newUsername == "" {
			newUsername = username
		}

		// If user does not exist, create new user with their username set to their Twitter ID
		user, err = auth.user.UserCreator("", "", newUsername, "", "", "", "", twitterID, "", "", "", "")
		if err != nil {
			return terror.Error(err)
		}

		// Indicate to client that user needs to sign up
		isNew = true
	}

	// Fingerprint user
	if req.Payload.Fingerprint != nil {
		userID := user.Fields().ID()
		// todo: include ip in upsert
		err = auth.DoFingerprintUpsert(*req.Payload.Fingerprint, userID)
		if err != nil {
			return err
		}
	}

	user, _, token, err := auth.IssueToken(hubc, &IssueTokenConfig{
		Encrypted: auth.tokens.EncryptToken(),
		Key:       auth.tokens.EncryptTokenKey(),
		Device:    hubc.Request.UserAgent(),
		Action:    LoginAction,
		User:      user,
	})
	if err != nil {
		return terror.Error(err, "There was a problem creating a session for your account, please try again.")
	}

	if req.Payload.SessionID != "" {
		auth.EvaluateClientBySessionID(user, req.Payload.SessionID)
	}
	reply(&PasswordLoginResponse{user, token, isNew})

	return nil
}

type TwitterDetails struct {
	ID         string `json:"id"`
	ScreenName string `json:"screen_name"`
}

// GetOAuthTwitterDetails will attempt to retrieve a Twitter user's Details using the oauthToken and oauthVerifier.
// oauthToken and oauthVerifier is the token and verifier code obtained from Twitter's 3-legged OAuth 1.0a flow.
func (auth *Auth) GetOAuthTwitterDetails(ctx context.Context, hubc *hub.Client, oauthToken string, oauthVerifier string) (*TwitterDetails, error) {
	// Get Twitter access token using OAuth token and verifier
	params := url.Values{}
	params.Set("oauth_token", oauthToken)
	params.Set("oauth_verifier", oauthVerifier)

	client := &http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("https://api.twitter.com/oauth/access_token?%s", params.Encode()), nil)
	if err != nil {
		return nil, terror.Error(err)
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, terror.Error(err)
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, terror.Error(err)
	}

	resp := &struct {
		OauthToken       string
		OauthTokenSecret string
		UserID           string
		ScreenName       string
	}{}
	values := strings.Split(string(body), "&")
	for _, v := range values {
		pair := strings.Split(v, "=")
		switch pair[0] {
		case "oauth_token":
			resp.OauthToken = pair[1]
		case "oauth_token_secret":
			resp.OauthTokenSecret = pair[1]
		case "user_id":
			resp.UserID = pair[1]
		case "screen_name":
			resp.ScreenName = pair[1]
		}
	}

	return &TwitterDetails{ID: resp.UserID, ScreenName: resp.ScreenName}, nil
}

type TwitchSignUpRequest struct {
	*hub.HubCommandRequest
	Payload struct {
		Token       string        `json:"token"`
		Username    string        `json:"username"`
		SessionID   hub.SessionID `json:"session_id"`
		Fingerprint *Fingerprint  `json:"fingerprint"`
	} `json:"payload"`
}

const HubKeyAuthSignUpTwitch = hub.HubCommandKey("AUTH:SIGNUP_TWITCH")

func (auth *Auth) TwitchSignUpHandler(ctx context.Context, hubc *hub.Client, payload []byte, reply hub.ReplyFunc) error {
	if auth.walletConnectOnly {
		return terror.Error(fmt.Errorf("wallet connect only"), "Only wallet connections are allowed during the whitelist period")
	}
	req := &TwitchSignUpRequest{}
	err := json.Unmarshal(payload, req)
	if err != nil {
		return terror.Error(err, "Failed to unmarshal req")
	}

	// Get user's Twitch ID
	twitchDetails, err := auth.GetOAuthTwitchDetails(ctx, hubc, req.Payload.Token)
	if err != nil {
		return terror.Error(err)
	}

	twitchID := twitchDetails.Sub
	// Check if there are any existing users associated with that Twitch ID
	user, err := auth.user.TwitchID(twitchID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return terror.Error(err)
	}

	if user != nil {
		return terror.Error(fmt.Errorf("user already exists"), "A user with that Twitch account already exists. Perhaps you'd like to login instead?")
	}

	// Create new user
	user, err = auth.user.UserCreator("", "", req.Payload.Username, "", "", "", twitchID, "", "", "", "", "")
	if err != nil {
		return terror.Error(err)
	}

	// Fingerprint user
	if req.Payload.Fingerprint != nil {
		userID := user.Fields().ID()
		// todo: include ip in upsert
		err = auth.DoFingerprintUpsert(*req.Payload.Fingerprint, userID)
		if err != nil {
			return err
		}
	}

	user, _, token, err := auth.IssueToken(hubc, &IssueTokenConfig{
		Encrypted: auth.tokens.EncryptToken(),
		Key:       auth.tokens.EncryptTokenKey(),
		Device:    hubc.Request.UserAgent(),
		Action:    LoginAction,
		User:      user,
	})
	if err != nil {
		return terror.Error(err, "There was a problem creating a session for your account, please try again.")
	}

	if req.Payload.SessionID != "" {
		auth.EvaluateClientBySessionID(user, req.Payload.SessionID)
	}
	reply(&RegisterResponse{user, token})

	return nil
}

type TwitchLoginRequest struct {
	*hub.HubCommandRequest
	Payload struct {
		Token       string        `json:"token"`
		SessionID   hub.SessionID `json:"session_id"`
		Fingerprint *Fingerprint  `json:"fingerprint"`
	} `json:"payload"`
}

const HubKeyAuthLoginTwitch = hub.HubCommandKey("AUTH:LOGIN_TWITCH")

func (auth *Auth) TwitchLoginHandler(ctx context.Context, hubc *hub.Client, payload []byte, reply hub.ReplyFunc) error {
	if auth.walletConnectOnly {
		return terror.Error(fmt.Errorf("wallet connect only"), "Only wallet connections are allowed during the whitelist period")
	}
	req := &TwitchLoginRequest{}
	err := json.Unmarshal(payload, req)
	if err != nil {
		return terror.Error(err, "Failed to unmarshal req")
	}

	// Get user's Twitch ID
	twitchDetails, err := auth.GetOAuthTwitchDetails(ctx, hubc, req.Payload.Token)
	if err != nil {
		return terror.Error(err)
	}

	twitchID := twitchDetails.Sub
	truncID := twitchID[len(twitchID)-4:]
	username := twitchDetails.PreferredUsername

	// if username has profanity or too short
	if goaway.IsProfane(username) || len(username) <= 3 {
		username = fmt.Sprintf("twitch_%s", truncID)
	}

	// truncate username if too long
	if len(username) > 10 {
		username = username[0:9]
	}

	// Check if there are any existing users associated with that Twitch ID
	user, err := auth.user.TwitchID(twitchID)
	isNew := false
	if err != nil {
		newUsername := ""
		// check if any user with username exist
		_, err = auth.user.Username(username)
		// if username exist append last part of their twitch id to username
		if err == nil {
			newUsername = fmt.Sprintf("%s_%s", username, truncID)
		}

		userNameExist := true
		if userNameExist {
			_, err = auth.user.Username(newUsername)
			// if new username exist append random chars to their username
			if err == nil {
				randStr := fmt.Sprintf("%s_%s", username, RandString())
				newUsername = username + randStr
			} else {
				userNameExist = false
			}
		}

		if newUsername == "" {
			newUsername = username
		}

		// If user does not exist, create new user with their username set to their Twitch ID
		user, err = auth.user.UserCreator("", "", newUsername, "", "", "", twitchID, "", "", "", "", "")
		if err != nil {
			return terror.Error(err)
		}

		// Indicate to client that user needs to sign up
		isNew = true
	}

	// Fingerprint user
	if req.Payload.Fingerprint != nil {
		userID := user.Fields().ID()
		// todo: include ip in upsert
		err = auth.DoFingerprintUpsert(*req.Payload.Fingerprint, userID)
		if err != nil {
			return err
		}
	}

	user, _, token, err := auth.IssueToken(hubc, &IssueTokenConfig{
		Encrypted: auth.tokens.EncryptToken(),
		Key:       auth.tokens.EncryptTokenKey(),
		Device:    hubc.Request.UserAgent(),
		Action:    LoginAction,
		User:      user,
	})
	if err != nil {
		return terror.Error(err, "There was a problem creating a session for your account, please try again.")
	}

	if req.Payload.SessionID != "" {
		auth.EvaluateClientBySessionID(user, req.Payload.SessionID)
	}
	reply(&PasswordLoginResponse{user, token, isNew})

	return nil
}

type TwitchExtensionLoginRequest struct {
	*hub.HubCommandRequest
	Payload struct {
		Token         string        `json:"token"`
		Username      string        `json:"username"`
		SessionID     hub.SessionID `json:"session_id"`
		CreateNewUser bool          `json:"create_new_user"`
	} `json:"payload"`
}

const HubKeyAuthLoginTwitchExtension = hub.HubCommandKey("AUTH:TWITCH")

func (auth *Auth) TwitchExtensionLoginHandler(ctx context.Context, hubc *hub.Client, payload []byte, reply hub.ReplyFunc) error {
	if auth.walletConnectOnly {
		return terror.Error(fmt.Errorf("wallet connect only"), "Only wallet connections are allowed during the whitelist period")
	}
	req := &TwitchExtensionLoginRequest{}
	err := json.Unmarshal(payload, req)
	if err != nil {
		return terror.Error(err, "Failed to unmarshal req")
	}

	resp, err := auth.TwitchLoginExtension(ctx, hubc, req.Payload.Token, req.Payload.Username, req.Payload.CreateNewUser)
	if err != nil {
		return terror.Error(err)
	}
	if req.Payload.SessionID != "" {
		auth.EvaluateClientBySessionID(resp.User, req.Payload.SessionID)
	}
	reply(resp)

	return nil
}

// TwitchJWTClaims is the payload of a JWT sent by the Twitch extension
type TwitchJWTClaims struct {
	OpaqueUserID    string `json:"opaque_user_id,omitempty"`
	TwitchAccountID string `json:"user_id"`
	ChannelID       string `json:"channel_id,omitempty"`
	Role            string `json:"role"`
	twitch_jwt.StandardClaims
}

// GetClaimsFromTwitchExtensionToken verifies token from Twitch extension
func (auth *Auth) GetClaimsFromTwitchExtensionToken(token string) (*TwitchJWTClaims, error) {
	// Get claims
	claims := &TwitchJWTClaims{}

	_, err := twitch_jwt.ParseWithClaims(token, claims, func(t *twitch_jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*twitch_jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return auth.twitch.ExtensionSecret, nil
	})
	if err != nil {
		return nil, terror.Error(terror.ErrBadClaims, "Invalid token")
	}

	return claims, nil
}

// TwitchLoginExtension gets a user from the twitch oauth token
func (auth *Auth) TwitchLoginExtension(ctx context.Context, hubc *hub.Client, twitchToken string, username string, createNewUser bool) (*PasswordLoginResponse, error) {
	// Validate Twitch token
	errMsg := "There was a problem finding a user associated with the provided Google account, please check your details and try again."

	var user SecureUser

	claims, err := auth.GetClaimsFromTwitchExtensionToken(twitchToken)
	if err != nil {
		return nil, terror.Error(err)
	}

	if !strings.HasPrefix(claims.OpaqueUserID, "U") {
		return nil, terror.Error(terror.ErrInvalidInput, "Twitch user is not login")
	}

	if claims.TwitchAccountID == "" {
		return nil, terror.Error(terror.ErrInvalidInput, "No twitch account id is provided")
	}

	username = claims.TwitchAccountID

	user, err = auth.user.TwitchID(claims.TwitchAccountID)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) || !auth.createUserIfNotExist {
			return nil, terror.Error(err, errMsg)
		}

		if createNewUser {
			user, err = auth.user.UserCreator("", "", username, "", "", "", claims.TwitchAccountID, "", "", "", "", "")
			if err != nil {
				return nil, terror.Error(err, errMsg)
			}
		}
	}

	if user == nil {
		return nil, terror.Error(fmt.Errorf("user is nil somehow"), errMsg)
	}

	user, _, token, err := auth.IssueToken(hubc, &IssueTokenConfig{
		Encrypted: auth.tokens.EncryptToken(),
		Key:       auth.tokens.EncryptTokenKey(),
		Device:    hubc.Request.UserAgent(),
		Action:    LoginAction,
		User:      user,
	})

	if err != nil {
		return nil, terror.Error(err, errMsg)
	}

	return &PasswordLoginResponse{user, token, false}, nil
}

type TwitchDetails struct {
	Sub               string `json:"sub"`
	PreferredUsername string `json:"preferred_username"`
}

// GetOAuthTwitchDetails will attempt to retrieve a Twitch user's ID using the token.
// token is the JWT obtained from Twitch's PCKE-OAuth flow.
func (auth *Auth) GetOAuthTwitchDetails(ctx context.Context, hubc *hub.Client, token string) (*TwitchDetails, error) {
	// Validate Twitch token
	keySet := oidc.NewRemoteKeySet(ctx, "https://id.twitch.tv/oauth2/keys")
	oidcVerifier := oidc.NewVerifier("https://id.twitch.tv/oauth2", keySet, &oidc.Config{
		ClientID: auth.twitch.ClientID,
	})

	idToken, err := oidcVerifier.Verify(ctx, token)
	if err != nil {
		return nil, terror.Error(err, "Failed to verify Twitch JWT")
	}

	var claims struct {
		Iss               string `json:"iss"`
		Sub               string `json:"sub"`
		Aud               string `json:"aud"`
		Exp               int32  `json:"exp"`
		Iat               int32  `json:"iat"`
		Nonce             string `json:"nonce"`
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, terror.Error(err, "Failed to get claims from token")
	}

	return &TwitchDetails{Sub: claims.Sub, PreferredUsername: claims.PreferredUsername}, nil
}

type FacebookSignUpRequest struct {
	*hub.HubCommandRequest
	Payload struct {
		Token       string        `json:"token"`
		Username    string        `json:"username"`
		SessionID   hub.SessionID `json:"session_id"`
		Fingerprint *Fingerprint  `json:"fingerprint"`
	} `json:"payload"`
}

const HubKeyAuthSignUpFacebook = hub.HubCommandKey("AUTH:SIGNUP_FACEBOOK")

func (auth *Auth) FacebookSignUpHandler(ctx context.Context, hubc *hub.Client, payload []byte, reply hub.ReplyFunc) error {
	if auth.walletConnectOnly {
		return terror.Error(fmt.Errorf("wallet connect only"), "Only wallet connections are allowed during the whitelist period")
	}
	req := &FacebookSignUpRequest{}
	err := json.Unmarshal(payload, req)
	if err != nil {
		return terror.Error(err, "Failed to unmarshal req")
	}

	// Get user's Facebook ID
	facebookID, err := auth.GetOAuthFacebookID(ctx, hubc, req.Payload.Token)
	if err != nil {
		return terror.Error(err)
	}

	// Check if there are any existing users associated with that Facebook ID
	user, err := auth.user.FacebookID(*facebookID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return terror.Error(err)
	}

	if user != nil {
		return terror.Error(fmt.Errorf("user already exists"), "A user with that Facebook account already exists. Perhaps you'd like to login instead?")
	}

	// Create new user
	user, err = auth.user.UserCreator("", "", req.Payload.Username, "", *facebookID, "", "", "", "", "", "", "")
	if err != nil {
		return terror.Error(err)
	}

	// Fingerprint user
	if req.Payload.Fingerprint != nil {
		userID := user.Fields().ID()
		// todo: include ip in upsert
		err = auth.DoFingerprintUpsert(*req.Payload.Fingerprint, userID)
		if err != nil {
			return err
		}
	}

	user, _, token, err := auth.IssueToken(hubc, &IssueTokenConfig{
		Encrypted: auth.tokens.EncryptToken(),
		Key:       auth.tokens.EncryptTokenKey(),
		Device:    hubc.Request.UserAgent(),
		Action:    LoginAction,
		User:      user,
	})
	if err != nil {
		return terror.Error(err, "There was a problem creating a session for your account, please try again.")
	}

	if req.Payload.SessionID != "" {
		auth.EvaluateClientBySessionID(user, req.Payload.SessionID)
	}
	reply(&RegisterResponse{user, token})

	return nil
}

const HubKeyAuthLoginFacebook = hub.HubCommandKey("AUTH:LOGIN_FACEBOOK")

func (auth *Auth) FacebookLoginHandler(ctx context.Context, hubc *hub.Client, payload []byte, reply hub.ReplyFunc) error {
	if auth.walletConnectOnly {
		return terror.Error(fmt.Errorf("wallet connect only"), "Only wallet connections are allowed during the whitelist period")
	}
	req := &TokenLoginRequest{}
	err := json.Unmarshal(payload, req)
	if err != nil {
		return terror.Error(err, "Failed to unmarshal req")
	}

	// Get user's Facebook ID
	facebookID, err := auth.GetOAuthFacebookID(ctx, hubc, req.Payload.Token)
	if err != nil {
		return terror.Error(err)
	}
	truncID := (*facebookID)[len(*facebookID)-5:]
	username := fmt.Sprintf("facbook_%s", truncID)

	// Check if there are any existing users associated with that Facebook ID
	user, err := auth.user.FacebookID(*facebookID)
	isNew := false
	if err != nil {
		newUsername := ""

		// check if any user with username exist
		_, err = auth.user.Username(username)
		userNameExist := true
		if userNameExist {
			_, err = auth.user.Username(newUsername)
			// if new username exist append random chars to their username
			if err == nil {
				randStr := fmt.Sprintf("%s_%s", username, RandString())
				newUsername = "facebook" + randStr
			} else {
				userNameExist = false
			}
		}

		if newUsername == "" {
			newUsername = username
		}

		// If user does not exist, create new user
		user, err = auth.user.UserCreator("", "", newUsername, "", "", *facebookID, "", "", "", "", "", "")
		if err != nil {
			return terror.Error(err)
		}

		// Indicate to client that user needs to sign up
		isNew = true
	}

	// Fingerprint user
	if req.Payload.Fingerprint != nil {
		userID := user.Fields().ID()
		// todo: include ip in upsert
		err = auth.DoFingerprintUpsert(*req.Payload.Fingerprint, userID)
		if err != nil {
			return err
		}
	}

	user, _, token, err := auth.IssueToken(hubc, &IssueTokenConfig{
		Encrypted: auth.tokens.EncryptToken(),
		Key:       auth.tokens.EncryptTokenKey(),
		Device:    hubc.Request.UserAgent(),
		Action:    LoginAction,
		User:      user,
	})
	if err != nil {
		return terror.Error(err, "There was a problem creating a session for your account, please try again.")
	}

	if req.Payload.SessionID != "" {
		auth.EvaluateClientBySessionID(user, req.Payload.SessionID)
	}
	reply(&PasswordLoginResponse{user, token, isNew})

	return nil
}

// GetOauthFacebookID will attempt to retrieve a Facebook user's ID using the token.
// token is the JWT obtained from Facebook's OAuth flow.
func (auth *Auth) GetOAuthFacebookID(ctx context.Context, hubc *hub.Client, facebookToken string) (*string, error) {
	// Validate Facebook token
	errMsg := "There was a problem finding a user associated with the provided Facebook account, please check your details and try again."
	r, err := http.Get("https://graph.facebook.com/me?fields=email,picture&access_token=" + url.QueryEscape(facebookToken))
	if err != nil {
		return nil, terror.Error(err)
	}
	defer r.Body.Close()
	resp := &struct {
		Email   string `json:"email"`
		ID      string `json:"id"`
		Picture *struct {
			Data struct {
				URL *string `json:"url"`
			} `json:"data"`
		} `json:"picture"`
	}{}
	err = json.NewDecoder(r.Body).Decode(resp)
	if err != nil {
		return nil, terror.Error(err, errMsg)
	}

	return &resp.ID, nil
}

type GoogleSignUpRequest struct {
	*hub.HubCommandRequest
	Payload struct {
		Token       string        `json:"token"`
		Username    string        `json:"username"`
		SessionID   hub.SessionID `json:"session_id"`
		Fingerprint *Fingerprint  `json:"fingerprint"`
	} `json:"payload"`
}

const HubKeyAuthSignUpGoogle = hub.HubCommandKey("AUTH:SIGNUP_GOOGLE")

func (auth *Auth) GoogleSignUpHandler(ctx context.Context, hubc *hub.Client, payload []byte, reply hub.ReplyFunc) error {
	if auth.walletConnectOnly {
		return terror.Error(fmt.Errorf("wallet connect only"), "Only wallet connections are allowed during the whitelist period")
	}
	req := &GoogleSignUpRequest{}
	err := json.Unmarshal(payload, req)
	if err != nil {
		return terror.Error(err, "Failed to unmarshal req")
	}

	// Get user's Google ID
	googleID, err := auth.GetOAuthGoogleID(ctx, hubc, req.Payload.Token)
	if err != nil {
		return terror.Error(err)
	}

	// Check if there are any existing users associated with that Google ID
	user, err := auth.user.GoogleID(*googleID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return terror.Error(err)
	}

	if user != nil {
		return terror.Error(fmt.Errorf("user already exists"), "A user with that Google account already exists. Perhaps you'd like to login instead?")
	}

	// Create new user
	user, err = auth.user.UserCreator("", "", req.Payload.Username, "", "", *googleID, "", "", "", "", "", "")
	if err != nil {
		return terror.Error(err)
	}

	// Fingerprint user
	if req.Payload.Fingerprint != nil {
		userID := user.Fields().ID()
		// todo: include ip in upsert
		err = auth.DoFingerprintUpsert(*req.Payload.Fingerprint, userID)
		if err != nil {
			return err
		}
	}

	user, _, token, err := auth.IssueToken(hubc, &IssueTokenConfig{
		Encrypted: auth.tokens.EncryptToken(),
		Key:       auth.tokens.EncryptTokenKey(),
		Device:    hubc.Request.UserAgent(),
		Action:    LoginAction,
		User:      user,
	})
	if err != nil {
		return terror.Error(err, "There was a problem creating a session for your account, please try again.")
	}

	if req.Payload.SessionID != "" {
		auth.EvaluateClientBySessionID(user, req.Payload.SessionID)
	}
	reply(&RegisterResponse{user, token})

	return nil
}

const HubKeyAuthLoginGoogle = hub.HubCommandKey("AUTH:LOGIN_GOOGLE")

func (auth *Auth) GoogleLoginHandler(ctx context.Context, hubc *hub.Client, payload []byte, reply hub.ReplyFunc) error {
	if auth.walletConnectOnly {
		return terror.Error(fmt.Errorf("wallet connect only"), "Only wallet connections are allowed during the whitelist period")
	}
	req := &TokenLoginRequest{}
	err := json.Unmarshal(payload, req)
	if err != nil {
		return terror.Error(err, "Failed to unmarshal req")
	}

	// Get user's Google ID
	googleID, err := auth.GetOAuthGoogleID(ctx, hubc, req.Payload.Token)
	if err != nil {
		return terror.Error(err)
	}
	truncID := (*googleID)[len(*googleID)-5:]
	username := fmt.Sprintf("google_%s", truncID)

	// Check if there are any existing users associated with that Google ID
	user, err := auth.user.GoogleID(*googleID)
	isNew := false
	if err != nil {
		newUsername := ""

		// check if any user with username exist
		_, err = auth.user.Username(username)
		userNameExist := true
		if userNameExist {
			_, err = auth.user.Username(newUsername)
			// if new username exist append random chars to their username
			if err == nil {
				randStr := fmt.Sprintf("%s_%s", username, RandString())
				newUsername = "google" + randStr
			} else {
				userNameExist = false
			}
		}

		if newUsername == "" {
			newUsername = username
		}

		// If user does not exist, create new user
		user, err = auth.user.UserCreator("", "", newUsername, "", "", *googleID, "", "", "", "", "", "")
		if err != nil {
			return terror.Error(err)
		}

		// Indicate to client that user needs to sign up
		isNew = true
	}

	// Fingerprint user
	if req.Payload.Fingerprint != nil {
		userID := user.Fields().ID()
		// todo: include ip in upsert
		err = auth.DoFingerprintUpsert(*req.Payload.Fingerprint, userID)
		if err != nil {
			return err
		}
	}

	user, _, token, err := auth.IssueToken(hubc, &IssueTokenConfig{
		Encrypted: auth.tokens.EncryptToken(),
		Key:       auth.tokens.EncryptTokenKey(),
		Device:    hubc.Request.UserAgent(),
		Action:    LoginAction,
		User:      user,
	})
	if err != nil {
		return terror.Error(err, "There was a problem creating a session for your account, please try again.")
	}

	if req.Payload.SessionID != "" {
		auth.EvaluateClientBySessionID(user, req.Payload.SessionID)
	}
	reply(&PasswordLoginResponse{user, token, isNew})

	return nil
}

// GetOAuthGoogleID will attempt to retrieve a Google user's ID using the token.
// token is the JWT obtained from Google's OAuth flow.
func (auth *Auth) GetOAuthGoogleID(ctx context.Context, hubc *hub.Client, token string) (*string, error) {
	// Validate Google token
	errMsg := "There was a problem finding a user associated with the provided Google account, please check your details and try again."
	payload, err := idtoken.Validate(ctx, token, auth.google.ClientID)
	if err != nil {
		return nil, terror.Error(err, errMsg)
	}

	googleID, ok := payload.Claims["sub"].(string)
	if !ok {
		return nil, terror.Error(err, errMsg)
	}

	return &googleID, nil
}

type Fingerprint struct {
	VisitorID  string  `json:"visitor_id"`
	OSCPU      string  `json:"os_cpu"`
	Platform   string  `json:"platform"`
	Timezone   string  `json:"timezone"`
	Confidence float32 `json:"confidence"`
	UserAgent  string  `json:"user_agent"`
}

type WalletSignUpRequest struct {
	*hub.HubCommandRequest
	Payload struct {
		PublicAddress string        `json:"public_address"`
		Username      string        `json:"username"`
		SessionID     hub.SessionID `json:"session_id"`
		Fingerprint   *Fingerprint  `json:"fingerprint"`
	} `json:"payload"`
}

const HubKeyAuthSignUpWallet = hub.HubCommandKey("AUTH:SIGNUP_WALLET")

type WhitelistCheck struct {
	Type     string `json:"type"`
	CanEnter bool   `json:"can_enter"`
	Time     string `json:"time"`
	TimeLeft string `json:"time_left"`
}

func (auth *Auth) WalletSignUpHandler(ctx context.Context, hubc *hub.Client, payload []byte, reply hub.ReplyFunc) error {
	req := &WalletSignUpRequest{}
	err := json.Unmarshal(payload, req)
	if err != nil {
		return terror.Error(err, "Failed to unmarshal data")
	}

	if auth.walletConnectOnly {
		resp, err := http.Get(fmt.Sprintf("%s/%s", auth.whitelistCheckEndpoint, req.Payload.PublicAddress))
		if err != nil {
			return terror.Error(err, "Failed whitelist check")
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return terror.Error(err, "Failed whitelist check")
		}
		var whitelistCheck WhitelistCheck
		err = json.Unmarshal(body, &whitelistCheck)
		if err != nil {
			return terror.Error(err, "Failed whitelist check")
		}

		if !whitelistCheck.CanEnter {
			switch whitelistCheck.Type {
			case "alpha":
				return terror.Error(err, fmt.Sprintf("You're an alpha citizen but it is not time to enter. Please wait for another %s", whitelistCheck.TimeLeft))
			case "death":
				return terror.Error(err, fmt.Sprintf("You're a death citizen, it will soon be your time to enter. Please wait for another %s", whitelistCheck.TimeLeft))
			case "early":
				return terror.Error(err, fmt.Sprintf("Thank you for your early contribution. It will soon be your time to enter. Please wait for another %s", whitelistCheck.TimeLeft))
			case "none":
				return terror.Error(err, fmt.Sprintf("You have not been whitelisted. But its not too late. Run the simulation. Please wait for another %s", whitelistCheck.TimeLeft))
			case "death-nft":
				return terror.Error(err, fmt.Sprintf("You have a death key. It will soon be your time to enter. Please wait for another %s", whitelistCheck.TimeLeft))
			case "alpha-nft":
				return terror.Error(err, fmt.Sprintf("You have an alpha key. It will soon be your time to enter. Please wait for another %s", whitelistCheck.TimeLeft))
			}
		}
	}

	// Take public address Hex to address(Make it a checksum mixed case address) convert back to Hex for string of checksum
	commonAddr := common.HexToAddress(req.Payload.PublicAddress).Hex()

	// Check if there are any existing users associated with the public address
	user, err := auth.user.PublicAddress(commonAddr)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return terror.Error(err)
	}

	if user != nil {
		return terror.Error(fmt.Errorf("user already exists"), "A user with that MetaMask account already exists. Perhaps you'd like to login instead?")
	}

	// Create new user
	user, err = auth.user.UserCreator("", "", req.Payload.Username, "", "", "", "", "", "", "", commonAddr, "")
	if err != nil {
		return terror.Error(err)
	}

	// Create fingerprint for user
	if req.Payload.Fingerprint != nil {
		userID := user.Fields().ID()
		// todo: include ip in upsert
		err = auth.DoFingerprintUpsert(*req.Payload.Fingerprint, userID)
		if err != nil {
			return err
		}
	}

	user, _, token, err := auth.IssueToken(hubc, &IssueTokenConfig{
		Encrypted: auth.tokens.EncryptToken(),
		Key:       auth.tokens.EncryptTokenKey(),
		Device:    hubc.Request.UserAgent(),
		Action:    LoginAction,
		User:      user,
	})
	if err != nil {
		return terror.Error(err, "There was a problem creating a session for your account, please try again.")
	}

	if req.Payload.SessionID != "" {
		auth.EvaluateClientBySessionID(user, req.Payload.SessionID)
	}
	reply(&RegisterResponse{user, token})

	return nil
}

type WalletLoginRequest struct {
	*hub.HubCommandRequest
	Payload struct {
		PublicAddress string        `json:"public_address"`
		Signature     string        `json:"signature"`
		SessionID     hub.SessionID `json:"session_id"`
		Fingerprint   *Fingerprint  `json:"fingerprint"`
	} `json:"payload"`
}

const HubKeyAuthLoginWallet = hub.HubCommandKey("AUTH:LOGIN_WALLET")

func (auth *Auth) WalletLoginHandler(ctx context.Context, hubc *hub.Client, payload []byte, reply hub.ReplyFunc) error {
	req := &WalletLoginRequest{}
	err := json.Unmarshal(payload, req)
	if err != nil {
		return terror.Error(err, "Failed to unmarshal data")
	}

	// Take public address Hex to address(Make it a checksum mixed case address) convert back to Hex for string of checksum
	commonAddr := common.HexToAddress(req.Payload.PublicAddress).Hex()

	// Check if there are any existing users associated with the public address
	user, err := auth.user.PublicAddress(commonAddr)
	if err != nil {
		return terror.Error(err)
	}

	// Fingerprint user
	if req.Payload.Fingerprint != nil {
		userID := user.Fields().ID()
		// todo: include ip in upsert
		err = auth.DoFingerprintUpsert(*req.Payload.Fingerprint, userID)
		if err != nil {
			return err
		}
	}

	user, _, token, err := auth.IssueToken(hubc, &IssueTokenConfig{
		Encrypted: auth.tokens.EncryptToken(),
		Key:       auth.tokens.EncryptTokenKey(),
		Device:    hubc.Request.UserAgent(),
		Action:    LoginAction,
		User:      user,
	})
	if err != nil {
		return terror.Error(err, "There was a problem creating a session for your account, please try again.")
	}

	err = auth.VerifySignature(req.Payload.Signature, user.Fields().Nonce(), commonAddr)
	if err != nil {
		return terror.Error(err)
	}

	if req.Payload.SessionID != "" {
		auth.EvaluateClientBySessionID(user, req.Payload.SessionID)
	}
	reply(&PasswordLoginResponse{user, token, false})

	return nil
}

// HubKeyAuthSendVerifyEmail sends a verification email to complete registration or reset passwords
const HubKeyAuthSendVerifyEmail = hub.HubCommandKey("AUTH:SEND_VERIFY_EMAIL")

// SendVerifyEmailRequest is an auth request to send a verification email
type SendVerifyEmailRequest struct {
	*hub.HubCommandRequest
	Payload struct {
		Email          string `json:"email"`
		ForgotPassword *bool  `json:"forgot_password"`
		NewAccount     *bool  `json:"new_account"`
	} `json:"payload"`
}

// SendVerifyEmailResponse is an auth response to initial reset password
type SendVerifyEmailResponse struct {
	Success bool `json:"success"`
}

// SendVerifyEmailHandler generates a password reset token
func (auth *Auth) SendVerifyEmailHandler(ctx context.Context, hubc *hub.Client, payload []byte, reply hub.ReplyFunc) error {
	if auth.walletConnectOnly {
		return terror.Error(fmt.Errorf("wallet connect only"), "Only wallet connections are allowed during the whitelist period")
	}
	req := &SendVerifyEmailRequest{}
	err := json.Unmarshal(payload, req)
	if err != nil {
		return terror.Error(err, "Failed to unmarshal req")
	}

	user, tokenID, token, err := auth.IssueToken(hubc, &IssueTokenConfig{
		Encrypted: auth.tokens.EncryptToken(),
		Key:       auth.tokens.EncryptTokenKey(),
		Device:    hubc.Request.UserAgent(),
		Action:    EmailVerificationAction,
		Email:     req.Payload.Email,
	})
	if err != nil {
		return terror.Error(err, "unable to create token")
	}

	// Send email
	// TODO: Check user's origin for HostFromX argument
	forgot := req.Payload.ForgotPassword != nil && *req.Payload.ForgotPassword
	if forgot {
		err = user.SendForgotPasswordEmail(token, tokenID.String())
	} else {
		err = user.SendVerificationEmail(token, tokenID.String(), req.Payload.NewAccount != nil && *req.Payload.NewAccount)
	}
	if err != nil {
		return terror.Error(err)
	}

	// Respond
	resp := &SendVerifyEmailResponse{
		Success: true,
	}
	reply(resp)
	return nil
}

// HubKeyAuthVerifyAccount verifies a user's account with email and code
const HubKeyAuthVerifyAccount = hub.HubCommandKey("AUTH:VERIFY_ACCOUNT")

// VerifyAccountRequest is an auth request to verify an account
type VerifyAccountRequest struct {
	*hub.HubCommandRequest
	Payload struct {
		EncryptedToken string `json:"token"`
		ForgotPassword *bool  `json:"forgot_password,omitempty"`
	} `json:"payload"`
}

// VerifyAccountResponse is an auth response to verify an account
type VerifyAccountResponse struct {
	User  SecureUser `json:"user"`
	Token string     `json:"token"`
}

// VerifyAccountHandler verifies an account and logs the user in
func (auth *Auth) VerifyAccountHandler(w http.ResponseWriter, r *http.Request) (int, error) {
	// Get token
	encryptedToken := r.URL.Query().Get("token")
	if encryptedToken == "" {
		return http.StatusBadRequest, terror.Error(terror.ErrInvalidInput, "Missing token from request.")
	}

	// Get if forgotten password
	forgotPassword := r.URL.Query().Get("forgot") == "true"

	errMsg := "Verification Code is incorrect"

	// Find Token
	tokenStr, err := base64.StdEncoding.DecodeString(encryptedToken)
	if err != nil {
		return http.StatusBadRequest, terror.Error(err, "")
	}

	token, err := ReadJWT(tokenStr, auth.tokens.EncryptToken(), auth.tokens.EncryptTokenKey())
	if err != nil {
		if errors.Is(err, ErrTokenExpired) {
			tknUuid, err := tokenID(token)
			if err != nil {
				return http.StatusBadRequest, terror.Error(err)
			}
			err = auth.tokens.Remove(tknUuid)
			if err != nil {
				return http.StatusBadRequest, terror.Error(err)
			}
			return http.StatusBadRequest, terror.Warn(err, "Session has expired, please log in again.")
		}
		return http.StatusBadRequest, terror.Error(err, "")
	}

	tokenID, err := tokenID(token)
	if err != nil {
		return http.StatusBadRequest, terror.Error(err, "token id not found")
	}

	t, u, err := auth.tokens.Retrieve(tokenID)
	if err != nil {
		return http.StatusBadRequest, terror.Error(err, errMsg)
	}
	if auth.whitelist {
		if !t.Whitelisted() {
			return http.StatusBadRequest, terror.Error(ErrTokenNotWhitelisted, errMsg)
		}
	}

	// Get user by token
	errMsg = "Unable to Verify User, please try again"

	if !forgotPassword {
		if u.Fields().Verified() {
			return http.StatusBadRequest, terror.Error(ErrUserAlreadyVerified, "User is already verified")
		}
		err = u.Verify()
		if err != nil {
			return http.StatusBadRequest, terror.Error(err, errMsg)
		}
	} else {
		err = u.UpdatePasswordSetting(false)
		if err != nil {
			return http.StatusBadRequest, terror.Error(err, errMsg)
		}
	}

	if err != nil {
		return http.StatusBadRequest, terror.Error(err)
	}
	err = auth.tokens.Remove(t.TokenID())
	if err != nil {
		return http.StatusBadRequest, terror.Error(err)
	}

	if u.Fields().DeletedAt() != nil {
		return http.StatusForbidden, terror.Error(fmt.Errorf("users account is deleted"), "Account deactivated.")
	}

	tokenID = uuid.Must(uuid.NewV4())

	// save user detail in encrypted cookie and make it persist
	jwt, sign, err := GenerateJWT(
		tokenID,
		u,
		"",
		string(LoginAction),
		false,
		auth.tokens.TokenExpirationDays())
	if err != nil {
		return http.StatusBadRequest, terror.Error(err)
	}
	// Record token in issued token records

	jwtSigned, err := sign(jwt, auth.tokens.EncryptToken(), auth.tokens.EncryptTokenKey())
	if err != nil {
		return http.StatusInternalServerError, terror.Error(err)
	}

	tokenEncoded := base64.StdEncoding.EncodeToString(jwtSigned)

	err = auth.tokens.Save(tokenEncoded)
	if err != nil {
		return http.StatusBadRequest, terror.Error(err)
	}

	resp := &VerifyAccountResponse{
		User:  u,
		Token: tokenEncoded,
	}

	err = json.NewEncoder(w).Encode(resp)
	if err != nil {
		return http.StatusInternalServerError, terror.Error(err)
	}

	return http.StatusOK, nil
}

// HubKeyAuthRegister is the key used to run the register handler
const HubKeyAuthRegister = hub.HubCommandKey("AUTH:REGISTER")

type RegisterUserRequest struct {
	*hub.HubCommandRequest
	Payload struct {
		FirstName   string       `json:"first_name"`
		LastName    string       `json:"last_name"`
		Username    string       `json:"username"`
		Email       string       `json:"email"`
		Number      string       `json:"number"`
		Password    string       `json:"password"`
		Other       interface{}  `json:"other"`
		Fingerprint *Fingerprint `json:"fingerprint"`
	} `json:"payload"`
}

type RegisterResponse struct {
	User  SecureUser `json:"user"`
	Token string     `json:"token"`
}

// RegisterUserHandler lets you register a user
func (auth *Auth) RegisterUserHandler(ctx context.Context, hubc *hub.Client, payload []byte, reply hub.ReplyFunc) error {
	if auth.walletConnectOnly {
		return terror.Error(fmt.Errorf("wallet connect only"), "Only wallet connections are allowed during the whitelist period")
	}
	req := &RegisterUserRequest{}

	err := json.Unmarshal(payload, req)
	if err != nil {
		return terror.Error(err, "Failed to unmarshal req")
	}

	user, err := auth.user.UserCreator(req.Payload.FirstName, req.Payload.LastName, req.Payload.Username, strings.ToLower(req.Payload.Email), "", "", "", "", "", req.Payload.Number, "", req.Payload.Password, req.Payload.Other)
	if err != nil {
		return terror.Error(err)
	}

	// Fingerprint user
	if req.Payload.Fingerprint != nil {
		userID := user.Fields().ID()
		// todo: include ip in upsert
		err = auth.DoFingerprintUpsert(*req.Payload.Fingerprint, userID)
		if err != nil {
			return err
		}
	}

	_, _, token, err := auth.IssueToken(hubc, &IssueTokenConfig{
		Encrypted: auth.tokens.EncryptToken(),
		Key:       auth.tokens.EncryptTokenKey(),
		Device:    hubc.Request.UserAgent(),
		Action:    LoginAction,
		User:      user,
	})
	if err != nil {
		return terror.Error(err)
	}

	reply(&RegisterResponse{user, token})
	return nil
}

func (auth *Auth) DoFingerprintUpsert(fingerprint Fingerprint, userID uuid.UUID) error {
	err := auth.user.FingerprintUpsert(fingerprint, userID)
	if err != nil {
		return terror.Warn(err, fmt.Sprintf("Could not upsert fingerprint for user %s", userID))
	}

	return nil
}
