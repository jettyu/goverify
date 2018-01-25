package goverify_test

import (
	"strings"
	"testing"

	"github.com/jettyu/goverify"
)

func TestRsa(t *testing.T) {
	privstr := `MIICXQIBAAKBgQDeW/4acKeTLrsZDSgssMTTcvUV/pByAgvbD4wGdahZpoAUhUlc
NM1veJ+AfxHM8WohuBPpmYsEC9CDUW4I6wLCwenRGxoV3xi6iR2SHzf7qNv11uKA
difnoco8iow7eiRa0O/wiOw/mQAZSh/i87jM4IDSSKWn+bdW9Yfl28DWYwIDAQAB
AoGBAIi/KlY4UdZCNu4BGWPikik32WHdXBfBCml99i9CzHXV346/KY57KpwTIoRz
oQ7YqNxzyEsxEj06xtD7kyAI53iZLQGuhvnPFQXMxyws/YrpzUXaLbuxgpRvGuZM
h7D3hf33qNSI+771VpNr23CzkzF35/QYCsv80UTQXMXhEvIBAkEA8bhDx2HiTTWt
0KTkePas3hrVSZHbCRIWPQXg02kAY3OcxfBlIgt/cI10sYOAWFdmfeoMOEs5dO9+
bURvQ0HXcQJBAOt+7GCSPcu4b8vMxOVN3AH84usYNJ/O8htlZ1r5YEoR3Q3m+Y4A
tn8Z3cwKrEsR5SVZan9WcVDdyXsku2lI6RMCQB/2d6/zt5LyGCvQwg1kwPMVpUJ3
MPmAFMS49EPATLbZ4M8jvJvF3XIqolWex+fmlrzrp/YBrHVT/enA9N115WECQQCt
MdiYoZVPKaMXCM9aMWv4Dku5SUESszl+CpL75mH5t6+S1Od+l2mgip6DvOnAADY9
xMg9RI7sQWE37ujiYtv/AkA3tmDFhjKL8F8u/VSxPar97hyWp4DM8DcwDLmODVTL
ckkBZwstpwaHzAmzcQS4mkJVndXkwK4+9yBMJW3Gzs2k`

	pubstr := `MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDeW/4acKeTLrsZDSgssMTTcvUV
/pByAgvbD4wGdahZpoAUhUlcNM1veJ+AfxHM8WohuBPpmYsEC9CDUW4I6wLCwenR
GxoV3xi6iR2SHzf7qNv11uKAdifnoco8iow7eiRa0O/wiOw/mQAZSh/i87jM4IDS
SKWn+bdW9Yfl28DWYwIDAQAB`

	data := `123456`

	privstr = strings.Replace(privstr, "\r", "", -1)
	privstr = strings.Replace(privstr, "\n", "", -1)
	pubstr = strings.Replace(pubstr, "\r", "", -1)
	pubstr = strings.Replace(pubstr, "\n", "", -1)
	priv, err := goverify.RsaPriKeyFromString(privstr)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := goverify.RsaPubKeyFromString(pubstr)
	if err != nil {
		t.Fatal(err)
	}
	signstr, err := goverify.NewRsaSign(priv, nil).Sign(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := goverify.NewRsaSign(nil, pub).Verify(data, signstr); err != nil {
		t.Fatal(err)
	}
}

func TestRsa1(t *testing.T) {
	privstr := `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDeW/4acKeTLrsZDSgssMTTcvUV/pByAgvbD4wGdahZpoAUhUlc
NM1veJ+AfxHM8WohuBPpmYsEC9CDUW4I6wLCwenRGxoV3xi6iR2SHzf7qNv11uKA
difnoco8iow7eiRa0O/wiOw/mQAZSh/i87jM4IDSSKWn+bdW9Yfl28DWYwIDAQAB
AoGBAIi/KlY4UdZCNu4BGWPikik32WHdXBfBCml99i9CzHXV346/KY57KpwTIoRz
oQ7YqNxzyEsxEj06xtD7kyAI53iZLQGuhvnPFQXMxyws/YrpzUXaLbuxgpRvGuZM
h7D3hf33qNSI+771VpNr23CzkzF35/QYCsv80UTQXMXhEvIBAkEA8bhDx2HiTTWt
0KTkePas3hrVSZHbCRIWPQXg02kAY3OcxfBlIgt/cI10sYOAWFdmfeoMOEs5dO9+
bURvQ0HXcQJBAOt+7GCSPcu4b8vMxOVN3AH84usYNJ/O8htlZ1r5YEoR3Q3m+Y4A
tn8Z3cwKrEsR5SVZan9WcVDdyXsku2lI6RMCQB/2d6/zt5LyGCvQwg1kwPMVpUJ3
MPmAFMS49EPATLbZ4M8jvJvF3XIqolWex+fmlrzrp/YBrHVT/enA9N115WECQQCt
MdiYoZVPKaMXCM9aMWv4Dku5SUESszl+CpL75mH5t6+S1Od+l2mgip6DvOnAADY9
xMg9RI7sQWE37ujiYtv/AkA3tmDFhjKL8F8u/VSxPar97hyWp4DM8DcwDLmODVTL
ckkBZwstpwaHzAmzcQS4mkJVndXkwK4+9yBMJW3Gzs2k
-----END RSA PRIVATE KEY-----
`

	pubstr := `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDeW/4acKeTLrsZDSgssMTTcvUV
/pByAgvbD4wGdahZpoAUhUlcNM1veJ+AfxHM8WohuBPpmYsEC9CDUW4I6wLCwenR
GxoV3xi6iR2SHzf7qNv11uKAdifnoco8iow7eiRa0O/wiOw/mQAZSh/i87jM4IDS
SKWn+bdW9Yfl28DWYwIDAQAB
-----END PUBLIC KEY-----
`

	data := `123456`
	priv, err := goverify.RsaPriKeyFromPEM([]byte(privstr))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := goverify.RsaPubKeyFromPEM([]byte(pubstr))
	if err != nil {
		t.Fatal(err)
	}
	signstr, err := goverify.NewRsaSign(priv, nil).Sign(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := goverify.NewRsaSign(nil, pub).Verify(data, signstr); err != nil {
		t.Fatal(err)
	}
}

func TestRsaKey1(t *testing.T) {
	rk := goverify.NewRsaKey(1024)
	t.Log(string(rk.PrivateKeyBytes()))
	t.Log(string(rk.PublicKeyBytes()))
}

func TestRsaKey2(t *testing.T) {
	privstr := `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDeW/4acKeTLrsZDSgssMTTcvUV/pByAgvbD4wGdahZpoAUhUlc
NM1veJ+AfxHM8WohuBPpmYsEC9CDUW4I6wLCwenRGxoV3xi6iR2SHzf7qNv11uKA
difnoco8iow7eiRa0O/wiOw/mQAZSh/i87jM4IDSSKWn+bdW9Yfl28DWYwIDAQAB
AoGBAIi/KlY4UdZCNu4BGWPikik32WHdXBfBCml99i9CzHXV346/KY57KpwTIoRz
oQ7YqNxzyEsxEj06xtD7kyAI53iZLQGuhvnPFQXMxyws/YrpzUXaLbuxgpRvGuZM
h7D3hf33qNSI+771VpNr23CzkzF35/QYCsv80UTQXMXhEvIBAkEA8bhDx2HiTTWt
0KTkePas3hrVSZHbCRIWPQXg02kAY3OcxfBlIgt/cI10sYOAWFdmfeoMOEs5dO9+
bURvQ0HXcQJBAOt+7GCSPcu4b8vMxOVN3AH84usYNJ/O8htlZ1r5YEoR3Q3m+Y4A
tn8Z3cwKrEsR5SVZan9WcVDdyXsku2lI6RMCQB/2d6/zt5LyGCvQwg1kwPMVpUJ3
MPmAFMS49EPATLbZ4M8jvJvF3XIqolWex+fmlrzrp/YBrHVT/enA9N115WECQQCt
MdiYoZVPKaMXCM9aMWv4Dku5SUESszl+CpL75mH5t6+S1Od+l2mgip6DvOnAADY9
xMg9RI7sQWE37ujiYtv/AkA3tmDFhjKL8F8u/VSxPar97hyWp4DM8DcwDLmODVTL
ckkBZwstpwaHzAmzcQS4mkJVndXkwK4+9yBMJW3Gzs2k
-----END RSA PRIVATE KEY-----
`

	pubstr := `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDeW/4acKeTLrsZDSgssMTTcvUV
/pByAgvbD4wGdahZpoAUhUlcNM1veJ+AfxHM8WohuBPpmYsEC9CDUW4I6wLCwenR
GxoV3xi6iR2SHzf7qNv11uKAdifnoco8iow7eiRa0O/wiOw/mQAZSh/i87jM4IDS
SKWn+bdW9Yfl28DWYwIDAQAB
-----END PUBLIC KEY-----
`

	priv, err := goverify.RsaPriKeyFromPEM([]byte(privstr))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := goverify.RsaPubKeyFromPEM([]byte(pubstr))
	if err != nil {
		t.Fatal(err)
	}

	priv.PublicKey = *pub
	rc := goverify.RsaKey{priv}
	if string(rc.PrivateKeyBytes()) != privstr {
		t.Fatal(len(string(rc.PrivateKeyBytes())), len(privstr))
	}
	if string(rc.PublicKeyBytes()) != pubstr {
		t.Fatal(string(len(rc.PublicKeyBytes())), len(pubstr))
	}
}
