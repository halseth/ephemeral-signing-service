package service

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/davecgh/go-spew/spew"
)

type Service struct {
}

type Session struct {
	priv   *btcec.PrivateKey
	nonces *musig2.Nonces
}

func (s *Session) PubKey() *btcec.PublicKey {
	return s.priv.PubKey()
}

func (s *Session) PrivKey() *btcec.PrivateKey {
	return s.priv
}

func (s *Session) PubNonce() [musig2.PubNonceSize]byte {
	return s.nonces.PubNonce
}

func (s *Session) SecNonce() [musig2.SecNonceSize]byte {
	return s.nonces.SecNonce
}

func NewSession() (*Session, error) {
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, err
	}

	pub := priv.PubKey()

	nonce, err := musig2.GenNonces(
		musig2.WithPublicKey(pub),
	)
	if err != nil {
		return nil, err
	}

	return &Session{
		priv:   priv,
		nonces: nonce,
	}, nil
}

type Signer struct {
	PubKey   *btcec.PublicKey
	PubNonce [musig2.PubNonceSize]byte
}

func (s *Session) Sign(msgHash [32]byte, co [32]byte) (*musig2.PartialSignature, error) {

	var pubKeys []*btcec.PublicKey
	pubKeys = append(pubKeys, s.priv.PubKey())

	allOpts := append(
		[]musig2.ContextOption{
			musig2.WithKnownSigners(pubKeys),
		},
	)

	muSigContext, err := musig2.NewContext(s.priv, true, allOpts...)
	if err != nil {
		fmt.Println("here4", err)
		return nil, err
	}

	var sessionOpts []musig2.SessionOption
	sessionOpts = append(
		sessionOpts, musig2.WithPreGeneratedNonce(s.nonces),
	)

	muSigSession, err := muSigContext.NewSession(sessionOpts...)
	if err != nil {
		fmt.Println("here5", err)
		return nil, err
	}

	//	for _, sign := range signs {
	//		haveAll, err := muSigSession.RegisterPubNonce(sign.PubNonce)
	//		if err != nil {
	//			fmt.Println("here6", err)
	//			return nil, err
	//		}
	//		fmt.Println("have all nonce", haveAll)
	//	}

	var opts []musig2.SignOption
	opts = append(opts, musig2.WithSortedKeys())

	fmt.Printf("local nonces: %s\n", spew.Sdump(muSigSession.Nonces()))

	partialSig, err := muSigSession.Sign(msgHash, co, opts...)
	if err != nil {
		fmt.Println("here7", err)
		return nil, err
	}

	return partialSig, nil
}
