package password

import (
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type TestData struct {
	password  string
	salt      []byte
	rounds    int
	encrypted Password
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

var testData = []TestData{
	// from passlib
	{
		"password",
		must(ab64.DecodeString("RHY0Fr3IDMSVO/RSZyb5ow")),
		1212,
		"$pbkdf2-sha512$1212$RHY0Fr3IDMSVO/RSZyb5ow$eNLfBK.eVozomMr.1gYa17k9B7KIK25NOEshvhrSX.esqY3s.FvWZViXz4KoLlQI.BzY/YTNJOiKc5gBYFYGww",
	},

	// from passlib
	{
		"Ιωαννης",
		must(ab64.DecodeString("KkbvoKGsAIcF8IslDR6skQ")),
		1212,
		"$pbkdf2-sha512$1212$KkbvoKGsAIcF8IslDR6skQ$8be/PRmd88Ps8fmPowCJttH9G3vgxpG.Krjt3KT.NP6cKJ0V4Prarqf.HBwz0dCkJ6xgWnSj2ynXSV7MlvMa8Q",
	},
}

type PasswordSuite struct{}

var _ = Suite(&PasswordSuite{})

func (*PasswordSuite) TestNormal(c *C) {
	for _, d := range testData {
		p := Encrypt(d.password, d.rounds, d.salt)
		c.Check(p, Equals, d.encrypted)
		c.Check(p.Verify(d.password), Equals, true)
	}
}

func (*PasswordSuite) BenchmarkNormal(c *C) {
	d := testData[0]

	c.ResetTimer()
	for i := 0; i < c.N; i++ {
		Encrypt(d.password, d.rounds, d.salt)
	}
}
