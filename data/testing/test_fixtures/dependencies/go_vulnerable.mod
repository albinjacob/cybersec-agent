// github.com/dgrijalva/jwt-go v3.2.0+incompatible -> CVE-2020-26160 (aud-claim bypass)
// golang.org/x/text v0.3.0 -> CVE-2022-32149 (DoS parsing Accept-Language)
module example.com/test-fixture

go 1.16

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	golang.org/x/text v0.3.0
)
