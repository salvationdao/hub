package auth

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"os/user"
	"path"
	"time"

	"github.com/salvationdao/hub"

	"github.com/gofrs/uuid"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/lestrrat-go/jwx/jwt/openid"
	"github.com/salvationdao/terror"
)

var key = []byte("*G-KaPdSgVkYp3s6v9y$B?E(H+MbQeTh")

var src = rand.NewSource(time.Now().UnixNano())

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

var jwtKey []byte

func RandomKey(n int) []byte {
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return b
}

func init() {
	user, err := user.Current()
	if err != nil {
		panic(err)
	}
	keyPath := path.Join(user.HomeDir, ".passport.key")
	jwtKeyEncrypted, err := ioutil.ReadFile(keyPath)

	if err != nil {
		jwtKey = RandomKey(32)

		jwtKeyEncrypted, err := encrypt(key, jwtKey)
		if err != nil {
			log.Println("unable to generate key")
			log.Fatal(err)
		}

		err = os.WriteFile(keyPath, jwtKeyEncrypted, 0644)
		if err != nil {
			log.Println("unable to write key to file")
			log.Fatal(err)
		}
	} else {
		jwtKey, err = decrypt(key, jwtKeyEncrypted)
		if err != nil {
			log.Println("unable to decrypt key from file")
			log.Fatal(err)
		}
	}
}

// ReadJWT grabs the user from the token
func ReadJWT(tokenB []byte, decryptToken bool, decryptKey []byte) (jwt.Token, error) {
	if !decryptToken {
		token, err := jwt.Parse(tokenB, jwt.WithVerify(jwa.HS256, jwtKey))
		if err != nil {
			return nil, terror.Error(err, "token verification failed")
		}
		if token.Expiration().Before(time.Now()) {
			return token, ErrTokenExpired
		}

		return token, err
	}

	decrpytedToken, err := decrypt(decryptKey, tokenB)
	if err != nil {
		return nil, err
	}

	return ReadJWT(decrpytedToken, false, nil)
}

const JwtIsImpersonation = "isImpersonation"

// GenerateJWT returns the token for client side persistence
func GenerateJWT(tokenID uuid.UUID, u hub.User, deviceName, action string, isImpersonation bool, expireInDays int) (jwt.Token, func(jwt.Token, bool, []byte) ([]byte, error), error) {
	token := openid.New()
	token.Set("user-id", u.Fields().ID().String())
	token.Set(openid.EmailKey, u.Fields().Email())
	token.Set(openid.EmailKey, u.Fields().Email())
	token.Set(openid.EmailVerifiedKey, u.Fields().Verified())
	token.Set(openid.NameKey, u.Fields().FirstName())
	token.Set(openid.FamilyNameKey, u.Fields().LastName())
	token.Set(openid.JwtIDKey, tokenID.String())
	token.Set(openid.ExpirationKey, time.Now().AddDate(0, 0, expireInDays))
	token.Set("device", deviceName)
	token.Set("action", action)
	if isImpersonation {
		token.Set(JwtIsImpersonation, true)
	}
	sign := func(t jwt.Token, encryptToken bool, encryptKey []byte) ([]byte, error) {
		if !encryptToken {
			return jwt.Sign(t, jwa.HS256, jwtKey)
		}

		// sign
		signedJWT, err := jwt.Sign(t, jwa.HS256, jwtKey)
		if err != nil {
			return nil, err
		}

		// then encrypt
		encryptedAndSignedToken, err := encrypt(encryptKey, signedJWT)
		if err != nil {
			return nil, err
		}

		return encryptedAndSignedToken, nil
	}
	return token, sign, nil
}

// See alternate IV creation from ciphertext below
//var iv = []byte{35, 46, 57, 24, 85, 35, 24, 74, 87, 35, 88, 98, 66, 32, 14, 05}

func encrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(crand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return ciphertext, nil
}

func decrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(text) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return nil, err
	}
	return data, nil
}

func tokenID(token jwt.Token) (uuid.UUID, error) {
	jwtIDI, ok := token.Get(openid.JwtIDKey)

	if !ok {
		return uuid.Nil, terror.Error(errors.New("unable to get ID from token"), "unable to read token")
	}

	jwtID, err := uuid.FromString(jwtIDI.(string))
	if err != nil {
		return uuid.Nil, terror.Error(err, "unable to form UUID from token")
	}
	return jwtID, nil
}
