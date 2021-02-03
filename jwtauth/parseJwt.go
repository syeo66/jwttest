package jwtauth

import (
	"fmt"

	"github.com/dgrijalva/jwt-go"
)

// Claims is an alias for MapClaims
type Claims = jwt.MapClaims

type ServiceAccountKey struct {
	AuthProviderX509CertUrl string `json:"auth_provider_x509_cert_url"`
	ClientX509CertUrl       string `json:"client_x509_cert_url"`
}

// ParseJWT parses a JWT and returns Claims object
// Claims can be access using index notation such as claims["foo"]
func ParseJWT(tokenString, key string) (Claims, error) {
	var keyFunc = func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		rsaPublicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(key))
		if err != nil {
			return nil, err
		}
		return rsaPublicKey, nil
	}

	token, err := jwt.Parse(tokenString, keyFunc)

	if token.Valid {
		if claims, ok := token.Claims.(Claims); ok {
			return claims, nil
		}

		return nil, err
	} else if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&jwt.ValidationErrorMalformed != 0 {
			fmt.Printf("[x] Malformed JWT: %v", err)
			return nil, err
		} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
			// Token is either expired or not active yet
			fmt.Printf("[x] Token is expired or not valid yet: %v", err)
			return nil, err
		} else {
			return nil, err
		}
	} else {
		return nil, err
	}
}
