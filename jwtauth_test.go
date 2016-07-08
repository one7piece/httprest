package httprest

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

type TestUser struct {
	username string
	password string
	roles    []string
}

func (t TestUser) Validate(username string, password string) bool {
	return t.username == username && t.password == password
}

func (t TestUser) GetRoles(username string) []string {
	if username == t.username {
		return t.roles
	}
	return []string{}
}

func TestJwtAuth(t *testing.T) {
	secreteKey := []byte("windycity")
	fmt.Println("TestJwtAuth...")
	user := TestUser{username: "dvan", password: "123", roles: []string{"admin", "operator"}}
	jwtAuth := JWTAuth{SecretKey: secreteKey, Handler: &user}

	// test login method
	r, err := http.NewRequest("POST", "/login", nil)
	if err != nil {
		t.Errorf("Error creating request: %v\n", err)
		t.FailNow()
	}

	w := httptest.NewRecorder()
	ctx := HttpContext{W: w, R: r}
	badAuthStr := base64.StdEncoding.EncodeToString([]byte(user.username + ":" + user.password + "xxx"))
	r.Header.Add("Authorization", "Authorization "+badAuthStr)
	if jwtAuth.Login(&ctx) {
		t.Error("Can login with invalid password!")
	}

	w = httptest.NewRecorder()
	ctx = HttpContext{W: w, R: r}
	validAuthStr := base64.StdEncoding.EncodeToString([]byte(user.username + ":" + user.password))
	r.Header.Del("Authorization")
	r.Header.Add("Authorization", "Authorization "+validAuthStr)

	if !jwtAuth.Login(&ctx) {
		t.Error(w.Body.String())
		t.FailNow()
	}
	// check the user
	if ctx.User.Name != user.username {
		t.Error("Invalid context username, expecting: " + user.username + ", got: " + ctx.User.Name)
	}
	// extract jwt token
	respJson := JWTToken{}
	err = json.Unmarshal([]byte(w.Body.String()), &respJson)
	if err != nil {
		t.Errorf("Error extracting JWT token: %v\n", err)
		t.FailNow()
	}
	// validate jwt token
	token, err := jwt.Parse(respJson.Token, func(token *jwt.Token) (interface{}, error) {
		// validate the alg
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return secreteKey, nil
	})
	if err != nil || !token.Valid {
		t.Errorf("Invalid JWT token: %v\n", err)
		t.FailNow()
	}

	claims := token.Claims.(jwt.MapClaims)
	fmt.Printf("token claims: %v\n", claims)
	if user.username != claims["id"].(string) {
		t.Errorf("Invalid JWT token {id}\n")
	}
	var roles []string
	json.Unmarshal([]byte(claims["rol"].(string)), &roles)
	if !reflect.DeepEqual(roles, user.roles) {
		t.Errorf("Invalid JWT token {rol}\n")
	}

	// test Validate method
	r, err = http.NewRequest("POST", "/authenticate", nil)
	if err != nil {
		t.Errorf("Error creating request: %v\n", err)
		t.FailNow()
	}
	r.Header.Add("Authorization", respJson.Token)
	w = httptest.NewRecorder()
	ctx = HttpContext{W: w, R: r}
	if !jwtAuth.Authenticate(&ctx) {
		t.Error(w.Body.String())
		t.FailNow()
	}
}
