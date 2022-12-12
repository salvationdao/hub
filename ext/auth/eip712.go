package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gofrs/uuid"
	"github.com/jackc/pgx/v4"
	"github.com/salvationdao/terror"
)

func (auth *Auth) VerifySignature(signature string, nonce string, publicKey string) error {
	decodedSig, err := hexutil.Decode(signature)
	if err != nil {
		return terror.Error(err)
	}

	if decodedSig[64] == 0 || decodedSig[64] == 1 {
		//https://ethereum.stackexchange.com/questions/102190/signature-signed-by-go-code-but-it-cant-verify-on-solidity
		decodedSig[64] += 27
	} else if decodedSig[64] != 27 && decodedSig[64] != 28 {
		return terror.Error(fmt.Errorf("decode sig invalid %v", decodedSig[64]))
	}
	decodedSig[64] -= 27

	msg := []byte(fmt.Sprintf("%s:\n %s", auth.eip712Message, nonce))
	prefixedNonce := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(msg), msg)

	hash := crypto.Keccak256Hash([]byte(prefixedNonce))
	recoveredPublicKey, err := crypto.Ecrecover(hash.Bytes(), decodedSig)
	if err != nil {
		return terror.Error(err)
	}

	secp256k1RecoveredPublicKey, err := crypto.UnmarshalPubkey(recoveredPublicKey)
	if err != nil {
		return terror.Error(err)
	}

	recoveredAddress := crypto.PubkeyToAddress(*secp256k1RecoveredPublicKey).Hex()
	isClientAddressEqualToRecoveredAddress := strings.ToLower(publicKey) == strings.ToLower(recoveredAddress)
	if !isClientAddressEqualToRecoveredAddress {
		return terror.Error(fmt.Errorf("public address does not match recovered address"))
	}
	return nil
}

type GetNonceResponse struct {
	Nonce string `json:"nonce"`
}

func (auth *Auth) GetNonce(w http.ResponseWriter, r *http.Request) (int, error) {
	publicAddress := r.URL.Query().Get("public-address")
	userID := r.URL.Query().Get("user-id")

	if publicAddress == "" && userID == "" {
		return http.StatusBadRequest, terror.Error(fmt.Errorf("missing public address or user id"))
	}

	if publicAddress != "" {

		// Take public address Hex to address(Make it a checksum mixed case address) convert back to Hex for string of checksum
		commonAddr := common.HexToAddress(publicAddress).Hex()

		user, err := auth.user.PublicAddress(commonAddr)
		if err != nil && err.Error() == pgx.ErrNoRows.Error() {
			username := commonAddr[0:10]

			// If user does not exist, create new user with their username set to their MetaMask public address
			user, err = auth.user.UserCreator("", "", username, "", "", "", "", "", "", "", commonAddr, "")
			if err != nil {
				return http.StatusInternalServerError, terror.Error(err)
			}
		} else if err != nil {
			return http.StatusInternalServerError, terror.Error(err)
		}
		newNonce, err := user.NewNonce()
		if err != nil {
			return http.StatusBadRequest, terror.Error(err)
		}

		resp := &GetNonceResponse{
			Nonce: newNonce,
		}

		err = json.NewEncoder(w).Encode(resp)
		if err != nil {
			return http.StatusInternalServerError, terror.Error(err)
		}
		return http.StatusOK, nil
	}

	userUuid, err := uuid.FromString(userID)
	if err != nil {
		return http.StatusBadRequest, terror.Error(err, "Invalid user ID")
	}
	user, err := auth.user.ID(userUuid)
	if err != nil {
		return http.StatusBadRequest, terror.Error(err)
	}

	newNonce, err := user.NewNonce()
	if err != nil {
		return http.StatusBadRequest, terror.Error(err)
	}

	resp := &GetNonceResponse{
		Nonce: newNonce,
	}

	err = json.NewEncoder(w).Encode(resp)
	if err != nil {
		return http.StatusInternalServerError, terror.Error(err)
	}
	return http.StatusOK, nil
}
