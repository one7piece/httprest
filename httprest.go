package httprest

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/julienschmidt/httprouter"
)

type User struct {
	Name  string
	Roles []string
}

type HttpContext struct {
	W      http.ResponseWriter
	R      *http.Request
	User   User
	params httprouter.Params
}

type Handler interface {
	Serve(Context *HttpContext)
}

type AuthService interface {
	Login(ctx *HttpContext) bool
	Authenticate(ctx *HttpContext) bool
}

type HttpRest struct {
	Router *httprouter.Router
	Auth   AuthService
}

func New() *HttpRest {
	r := HttpRest{Router: httprouter.New()}
	return &r
}

func (rest *HttpRest) LOGON(pattern string) {
	// assume the logon pattern will be POST
	rest.Router.POST(pattern, func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		// create context
		ctx := HttpContext{W: w, R: r, params: p}
		if rest.Auth != nil {
			rest.Auth.Login(&ctx)
		}
	})
}

func (rest *HttpRest) GET(pattern string, handler func(ctx *HttpContext)) {
	rest.Router.GET(pattern, func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		// create context
		ctx := HttpContext{W: w, R: r, params: p}
		// authenticate
		if rest.Auth != nil && !rest.Auth.Authenticate(&ctx) {
			ctx.RespERRString(http.StatusForbidden, "Not logged in!")
		}
		// if authenticate, pass to handle
		handler(&ctx)
	})
}

func (rest *HttpRest) POST(pattern string, handler func(ctx *HttpContext)) {
	rest.Router.POST(pattern, func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		// create context
		ctx := HttpContext{W: w, R: r, params: p}
		// authenticate
		if rest.Auth != nil && !rest.Auth.Authenticate(&ctx) {
			ctx.RespERRString(http.StatusForbidden, "Not logged in!")
		}
		// if authenticate, pass to handle
		handler(&ctx)
	})
}

func (ctx *HttpContext) GetPayload(p *interface{}) error {
	return json.NewDecoder(ctx.R.Body).Decode(p)
}

func (ctx *HttpContext) GetParam(name string) string {
	return ctx.params.ByName(name)
}

func (ctx *HttpContext) RespOK(value interface{}) error {
	fmt.Println("writing response value: ", value)
	// convert value to json string
	str, err := json.Marshal(value)
	if err != nil {
		return err
	}
	fmt.Println("writing response str: ", str)
	ctx.W.Header().Set("Content-Type", "application/json")
	ctx.W.WriteHeader(http.StatusOK)
	fmt.Fprintf(ctx.W, "%s", str)
	return nil
}

func (ctx *HttpContext) RespOKString(value string) {
	ctx.W.Header().Set("Content-Type", "application/json")
	ctx.W.WriteHeader(http.StatusOK)
	fmt.Fprintf(ctx.W, "%s", value)
}

func (ctx *HttpContext) RespERRString(status int, value string) {
	//ctx.W.Header().Set("Content-Type", "application/json")
	ctx.W.WriteHeader(status)
	fmt.Fprintf(ctx.W, "%s", value)
}
