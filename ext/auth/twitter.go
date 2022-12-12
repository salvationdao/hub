package auth

import (
	"fmt"
	"net/http"

	"github.com/dghubble/oauth1"
	"github.com/dghubble/oauth1/twitter"
	"github.com/salvationdao/terror"
)

// The TwitterAuth endpoint kicks off the OAuth 1.0a flow
// https://developer.twitter.com/en/docs/authentication/oauth-1-0a/obtaining-user-access-tokens
func (auth *Auth) TwitterAuth(w http.ResponseWriter, r *http.Request) (int, error) {
	oauthCallback := r.URL.Query().Get("oauth_callback")
	if oauthCallback == "" {
		return http.StatusBadRequest, terror.Error(fmt.Errorf("Invalid OAuth callback url provided"))
	}

	oauthConfig := oauth1.Config{
		ConsumerKey:    auth.twitter.APIKey,
		ConsumerSecret: auth.twitter.APISecret,
		CallbackURL:    oauthCallback,
		Endpoint:       twitter.AuthorizeEndpoint,
	}

	requestToken, _, err := oauthConfig.RequestToken()
	if err != nil {
		return http.StatusInternalServerError, terror.Error(err)
	}

	http.Redirect(w, r, fmt.Sprintf("https://api.twitter.com/oauth/authorize?oauth_token=%s", requestToken), http.StatusSeeOther)

	return http.StatusOK, nil
}
