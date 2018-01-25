package goverify

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// RsaSign ...
type RsaSign struct {
	priv *rsa.PrivateKey
	pub  *rsa.PublicKey
}

// NewRsaSign ...
func NewRsaSign(priv *rsa.PrivateKey, pub *rsa.PublicKey) RsaSign {
	return RsaSign{
		priv: priv,
		pub:  pub,
	}
}

// RsaPriKeyFromPEM ...
// -----BEGIN RSA PRIVATE KEY-----
// MIICXQIBAAKBgQDeW/4acKeTLrsZDSgssMTTcvUV/pByAgvbD4wGdahZpoAUhUlc
// NM1veJ+AfxHM8WohuBPpmYsEC9CDUW4I6wLCwenRGxoV3xi6iR2SHzf7qNv11uKA
// difnoco8iow7eiRa0O/wiOw/mQAZSh/i87jM4IDSSKWn+bdW9Yfl28DWYwIDAQAB
// AoGBAIi/KlY4UdZCNu4BGWPikik32WHdXBfBCml99i9CzHXV346/KY57KpwTIoRz
// oQ7YqNxzyEsxEj06xtD7kyAI53iZLQGuhvnPFQXMxyws/YrpzUXaLbuxgpRvGuZM
// h7D3hf33qNSI+771VpNr23CzkzF35/QYCsv80UTQXMXhEvIBAkEA8bhDx2HiTTWt
// 0KTkePas3hrVSZHbCRIWPQXg02kAY3OcxfBlIgt/cI10sYOAWFdmfeoMOEs5dO9+
// bURvQ0HXcQJBAOt+7GCSPcu4b8vMxOVN3AH84usYNJ/O8htlZ1r5YEoR3Q3m+Y4A
// tn8Z3cwKrEsR5SVZan9WcVDdyXsku2lI6RMCQB/2d6/zt5LyGCvQwg1kwPMVpUJ3
// MPmAFMS49EPATLbZ4M8jvJvF3XIqolWex+fmlrzrp/YBrHVT/enA9N115WECQQCt
// MdiYoZVPKaMXCM9aMWv4Dku5SUESszl+CpL75mH5t6+S1Od+l2mgip6DvOnAADY9
// xMg9RI7sQWE37ujiYtv/AkA3tmDFhjKL8F8u/VSxPar97hyWp4DM8DcwDLmODVTL
// ckkBZwstpwaHzAmzcQS4mkJVndXkwK4+9yBMJW3Gzs2k
// -----END RSA PRIVATE KEY-----
func RsaPriKeyFromPEM(priKeyPEM []byte) (*rsa.PrivateKey, error) {
	PEMBlock, _ := pem.Decode(priKeyPEM)
	if PEMBlock == nil {
		return nil, fmt.Errorf("pem.Decode failed")
	}
	if PEMBlock.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("Wrong key type, type=%s", PEMBlock.Type)
	}
	return x509.ParsePKCS1PrivateKey(PEMBlock.Bytes)
}

// RsaPubKeyFromPEM ...
// -----BEGIN PUBLIC KEY-----
// MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDeW/4acKeTLrsZDSgssMTTcvUV
// /pByAgvbD4wGdahZpoAUhUlcNM1veJ+AfxHM8WohuBPpmYsEC9CDUW4I6wLCwenR
// GxoV3xi6iR2SHzf7qNv11uKAdifnoco8iow7eiRa0O/wiOw/mQAZSh/i87jM4IDS
// SKWn+bdW9Yfl28DWYwIDAQAB
// -----END PUBLIC KEY-----
func RsaPubKeyFromPEM(pubKeyPEM []byte) (*rsa.PublicKey, error) {
	PEMBlock, _ := pem.Decode(pubKeyPEM)
	if PEMBlock == nil {
		return nil, fmt.Errorf("pem.Decode failed")
	}
	if PEMBlock.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("Wrong key type, type=%s", PEMBlock.Type)
	}
	pub, err := x509.ParsePKIXPublicKey(PEMBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return pub.(*rsa.PublicKey), nil
}

// RsaPriKeyFromString ...
func RsaPriKeyFromString(data string) (*rsa.PrivateKey, error) {
	buf, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS1PrivateKey(buf)
}

// RsaPubKeyFromString ...
func RsaPubKeyFromString(data string) (*rsa.PublicKey, error) {
	buf, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}
	pub, err := x509.ParsePKIXPublicKey(buf)
	if err != nil {
		return nil, err
	}
	return pub.(*rsa.PublicKey), nil
}

// Sign ...
func (p RsaSign) Sign(data string) (string, error) {
	buf, err := rsa.SignPKCS1v15(rand.Reader,
		p.priv,
		crypto.SHA1, hash(data))
	return string(buf), err
}

// Verify ...
func (p RsaSign) Verify(data, sign string) error {
	return rsa.VerifyPKCS1v15(p.pub,
		crypto.SHA1,
		hash(data),
		[]byte(sign))
}

func hash(msg string) []byte {
	s := crypto.SHA1.New()
	s.Write([]byte(msg))
	return s.Sum(nil)
}

// RsaKey ...
type RsaKey struct {
	*rsa.PrivateKey
}

// NewRsaKey ...
func NewRsaKey(bits int) RsaKey {
	priv, _ := rsa.GenerateKey(rand.Reader, bits)
	return RsaKey{priv}
}

// PrivateKeyBytes ...
func (p RsaKey) PrivateKeyBytes() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(p.PrivateKey),
	})
}

// PublicKeyBytes ...
func (p RsaKey) PublicKeyBytes() []byte {
	publicKeyBytes, _ := x509.MarshalPKIXPublicKey(&p.PublicKey)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
}
