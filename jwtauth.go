package httprest

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type JWTAuth struct {
	SecretKey []byte
}

type JWTToken struct {
	Username string
	Roles    []string
	Token    string
}

func (auth JWTAuth) Login(ctx *HttpContext) bool {
	encoded := strings.Replace(ctx.R.Header.Get("Authorization"), "Authorization ", "", -1)
	fmt.Println("encoded username/password: ", encoded)
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		fmt.Println("decode error:", err)
		return false
	}
	arr := strings.Split(string(decoded), ":")
	if len(arr) != 2 {
		ctx.RespERRString(http.StatusForbidden, "Invalid authorization header!")
		return false
	}
	username := arr[0]
	// validate the password
	password := arr[1]
	if password != username {
		ctx.RespERRString(http.StatusForbidden, "Invalid username or password")
		return false
	}
	roles := []string{"admin", "operator"}
	fmt.Println("decoded username/password: "+username+"/"+password+", ", roles)

	// create jwt token
	fmt.Println("creating jwt token...")
	token, err := auth.createJWT(username, roles)
	if err != nil {
		fmt.Println("Error creating jwt token:", err)
		ctx.RespERRString(http.StatusForbidden, "Invalid authorization header!")
		return false
	}
	fmt.Println("jwt token:", token)

	// return the token & user's roles
	jwtToken := JWTToken{Username: username, Roles: roles, Token: token}

	err = ctx.RespOK(jwtToken)
	if err != nil {
		fmt.Println("Failed to marshal response", err)
		return false
	}
	return true
}

func (auth JWTAuth) Authenticate(ctx *HttpContext) bool {
	token, err := auth.validateJWT(ctx.R)
	if err != nil {
		fmt.Printf("%s\n", err.Error())
		return false
	}
	claims := token.Claims.(jwt.MapClaims)
	fmt.Printf("%v\n", claims)
	ctx.User.Name = claims["id"].(string)
	roles := claims["rol"].(string)
	json.Unmarshal([]byte(roles), &ctx.User.Roles)
	return true
}

func (auth JWTAuth) createJWT(username string, roles []string) (string, error) {
	rolesJson, _ := json.Marshal(roles)
	fmt.Println("createJWT - rolesJson:" + string(rolesJson))

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":  username,
		"rol": string(rolesJson),
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Minute * 30).Unix(),
	})
	return token.SignedString(auth.SecretKey)
}

func (auth JWTAuth) validateJWT(r *http.Request) (*jwt.Token, error) {
	jwtString := r.Header.Get("Authorization")
	token, err := jwt.Parse(jwtString, func(token *jwt.Token) (interface{}, error) {
		// validate the alg
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return auth.SecretKey, nil
	})

	if err == nil && token.Valid {
		return token, nil
	}
	return nil, err
}
