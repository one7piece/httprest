package httprest

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestHttpRest(t *testing.T) {
	fmt.Println("TestHttpRest...")
	arr := []string{"john", "dvan"}
	str, _ := json.Marshal(arr)
	fmt.Println("encoded str:", string(str))
	var arr2 []string
	json.Unmarshal([]byte(str), &arr2)
	fmt.Println("decoded arr:", arr2)

	var rest *HttpRest
	rest = New()
	rest.Auth = JWTAuth{SecretKey: []byte("windycity")}
	rest.LOGON("/logon")
	rest.GET("/user/:id", func(ctx *HttpContext) {
		u := ctx.User
		// marshal the json object
		json, _ := json.Marshal(u)
		// write the content type, status code, payload
		ctx.W.Header().Set("Content-Type", "application/json")
		ctx.W.WriteHeader(200)
		fmt.Fprintf(ctx.W, "%s", json)
	})
}
