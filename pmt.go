package pmt

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"

	"github.com/google/tink/go/subtle/signature"
	"github.com/pkg/errors"
)

type ProtocolVersion string

const (
	ECv1            ProtocolVersion = "ECv1"
	ECv2            ProtocolVersion = "ECv2"
	ECv2SigningOnly ProtocolVersion = "ECv2SigningOnly"
)

type IntermediateSigningKey struct {
	SignedKey  string   `json:"signedKey"`
	Signatures []string `json:"signatures"`
}

type SignedMessage struct {
	ProtocolVersion        ProtocolVersion        `json:"protocolVersion"`
	IntermediateSigningKey IntermediateSigningKey `json:"intermediateSigningKey"`
	SignedMessage          string                 `json:"signedMessage"`
	Signature              string                 `json:"signature"`
}

func signedMessageFromJSON(data []byte) (*SignedMessage, error) {
	o := SignedMessage{}
	err := json.Unmarshal(data, &o)
	if err != nil {
		return nil, err
	}

	return &o, nil
}

type PublicKeysManager interface {
	GetSigningKeys() ([]Key, error)
}

type PaymentMethodTokenRecipient struct {
	protocolVersion ProtocolVersion
	senderID        string
	recipientID     string
	keysManager     PublicKeysManager
}

func NewPaymentMethodTokenRecipient(opts ...PaymentMethodTokenRecipientOption) (*PaymentMethodTokenRecipient, error) {
	r := &PaymentMethodTokenRecipient{}
	for _, opt := range opts {
		opt(r)
	}

	err := r.validate()
	if err != nil {
		return nil, err
	}

	return r, nil
}

func (r PaymentMethodTokenRecipient) Unseal(sealedMessage []byte) ([]byte, error) {
	m, err := signedMessageFromJSON(sealedMessage)
	if err != nil {
		return nil, err
	}

	switch m.ProtocolVersion {
	case ECv2SigningOnly:
		return r.unsealECv2SigningOnly(m)
	default:
		return nil, errors.New("unsupported protocol version")
	}
}

func (r PaymentMethodTokenRecipient) unsealECv2SigningOnly(msg *SignedMessage) ([]byte, error) {
	err := r.verifyIntermediateSigningKey(msg.IntermediateSigningKey)
	if err != nil {
		return nil, err
	}

	imkObjects, err := keyFromJSON([]byte(msg.IntermediateSigningKey.SignedKey))
	if err != nil {
		return nil, err
	}

	imk, err := r.parsePublicKeys(*imkObjects)
	if err != nil {
		return nil, err
	}

	sign, err := base64.StdEncoding.DecodeString(msg.Signature)
	if err != nil {
		return nil, err
	}

	signedBytes := toLengthValue(r.senderID, r.recipientID, string(r.protocolVersion), msg.SignedMessage)
	err = r.verify([][]byte{sign}, signedBytes, imk)
	if err != nil {
		return nil, err
	}

	return []byte(msg.SignedMessage), nil
}

func (r PaymentMethodTokenRecipient) verifyIntermediateSigningKey(key IntermediateSigningKey) error {
	signatures := make([][]byte, len(key.Signatures))
	for i, s := range key.Signatures {
		d, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return err
		}

		signatures[i] = d
	}

	keyObjects, err := r.keysManager.GetSigningKeys()
	if err != nil {
		return err
	}

	verifyingKeys, err := r.parsePublicKeys(keyObjects...)
	if err != nil {
		return err
	}

	signedBytes := toLengthValue(r.senderID, string(r.protocolVersion), key.SignedKey)
	err = r.verify(signatures, signedBytes, verifyingKeys)
	if err != nil {
		return err
	}

	return nil
}

func (r PaymentMethodTokenRecipient) verify(signatures [][]byte, signedBytes []byte, keys []*ecdsa.PublicKey) error {
	var verified bool
	for _, k := range keys {
		verifier, err := signature.NewECDSAVerifierFromPublicKey("SHA256", "DER", k)
		if err != nil {
			continue
		}

		for _, s := range signatures {
			err := verifier.Verify(s, signedBytes)
			if err != nil {
				continue
			}

			verified = true
			break
		}
	}

	if !verified {
		return errors.New("could not verify signature")
	}

	return nil
}

func (r PaymentMethodTokenRecipient) parsePublicKeys(keys ...Key) ([]*ecdsa.PublicKey, error) {
	res := make([]*ecdsa.PublicKey, len(keys))
	for i, k := range keys {
		err := k.IsValid()
		if err != nil {
			return nil, err
		}

		key, err := base64.StdEncoding.DecodeString(k.KeyValue)
		if err != nil {
			return nil, err
		}

		pub, err := x509.ParsePKIXPublicKey(key)
		if err != nil {
			return nil, err
		}

		res[i] = pub.(*ecdsa.PublicKey)
	}

	return res, nil
}

func (r PaymentMethodTokenRecipient) validate() error {
	if r.protocolVersion != ECv2SigningOnly {
		return errors.New("invalid protocol version: " + string(r.protocolVersion))
	}

	if r.keysManager == nil {
		return errors.New("must set keys manager")
	}

	if len(r.senderID) == 0 {
		return errors.New("must set sender ID")
	}

	if len(r.recipientID) == 0 {
		return errors.New("must set recipient ID")
	}

	return nil
}
