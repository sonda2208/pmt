package pmt

import (
	"encoding/json"
	"errors"
	"strconv"
	"time"
)

const (
	GooglePayKeysURLProduction = "https://payments.developers.google.com/paymentmethodtoken/keys.json"
	GooglePayKeysURLTest       = "https://payments.developers.google.com/paymentmethodtoken/test/keys.json"
)

type Key struct {
	ProtocolVersion ProtocolVersion `json:"protocolVersion"`
	KeyValue        string          `json:"keyValue"`
	KeyExpiration   string          `json:"keyExpiration"`
}

func (k Key) IsValid() error {
	if len(k.KeyExpiration) > 0 {
		keyExpiration, err := strconv.ParseInt(k.KeyExpiration, 10, 64)
		if err != nil {
			return err
		}

		expr := time.Unix(0, keyExpiration*int64(time.Millisecond))
		if time.Now().After(expr) {
			return errors.New("expired key")
		}
	}

	return nil
}

func keyFromJSON(data []byte) (*Key, error) {
	var k Key
	err := json.Unmarshal(data, &k)
	if err != nil {
		return nil, err
	}

	return &k, nil
}

type Keys struct {
	Keys []Key `json:"keys"`
}

type KeysDownloader interface {
	Download() (string, error)
}

type GPayPublicKeysManager struct {
	downloader KeysDownloader
}

func NewGPayPublicKeysManager(opts ...GPayPublicKeysManagerOption) (*GPayPublicKeysManager, error) {
	m := &GPayPublicKeysManager{}
	for _, opt := range opts {
		opt(m)
	}

	err := m.validate()
	if err != nil {
		return nil, err
	}

	return m, nil
}

func (m GPayPublicKeysManager) GetSigningKeys() ([]Key, error) {
	data, err := m.downloader.Download()
	if err != nil {
		return nil, err
	}

	var keys Keys
	err = json.Unmarshal([]byte(data), &keys)
	if err != nil {
		return nil, err
	}

	return keys.Keys, nil
}

func (m GPayPublicKeysManager) validate() error {
	if m.downloader == nil {
		return errors.New("keys downloader must be set")
	}

	return nil
}
