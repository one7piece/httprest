package httprest

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/julienschmidt/httprouter"
	"github.com/rs/cors"
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
	CorsPt *cors.Cors
}

func New() *HttpRest {
	rest := HttpRest{Router: httprouter.New()}
	return &rest
}

func (rest *HttpRest) handlePreflight(pattern string) {
	rest.Router.OPTIONS(pattern, func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		fmt.Printf("OPTIONS - url:%v\n", r.URL)
		rest.handleCors(w, r)
	})
}

func (rest *HttpRest) handleCors(w http.ResponseWriter, r *http.Request) bool {
	fmt.Printf("handleCors - URL:%s, request headers:%+v", r.URL, r.Header)
	if rest.CorsPt != nil {
		rest.CorsPt.HandlerFunc(w, r)
		fmt.Printf("handleCors - handle url:%s, request headers:%+v, response headers:%+v\n", r.URL, r.Header, w.Header())
		return (r.Method == "OPTIONS")
	}
	fmt.Printf("handleCors - no handle url:%s, response headers:%+v\n", r.URL, w.Header())
	return false
}

func (rest *HttpRest) LOGON(pattern string, handler func(ctx *HttpContext)) {
	rest.handlePreflight(pattern)
	// assume the logon pattern will be POST
	rest.Router.POST(pattern, func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		rest.handleCors(w, r)
		// create context
		ctx := HttpContext{W: w, R: r, params: p}
		if rest.Auth != nil {
			if !rest.Auth.Login(&ctx) {
				return
			}
		}
		handler(&ctx)
	})
}

func (rest *HttpRest) Handle(method string, pattern string, handler func(ctx *HttpContext)) {
	rest.handlePreflight(pattern)
	rest.Router.Handle(method, pattern, func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		rest.handleCors(w, r)
		// create context
		ctx := HttpContext{W: w, R: r, params: p}
		// authenticate
		if rest.Auth != nil && !rest.Auth.Authenticate(&ctx) {
			ctx.RespERRString(http.StatusForbidden, "Not logged in!")
			return
		}
		// if authenticate, pass to handle
		handler(&ctx)
	})
}

func (rest *HttpRest) GET(pattern string, handler func(ctx *HttpContext)) {
	rest.handlePreflight(pattern)
	rest.Router.GET(pattern, func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		rest.handleCors(w, r)
		// create context
		ctx := HttpContext{W: w, R: r, params: p}
		// authenticate
		if rest.Auth != nil && !rest.Auth.Authenticate(&ctx) {
			ctx.RespERRString(http.StatusForbidden, "Not logged in!")
			return
		}
		// if authenticate, pass to handle
		handler(&ctx)
	})
}

func (rest *HttpRest) POST(pattern string, handler func(ctx *HttpContext)) {
	rest.handlePreflight(pattern)
	rest.Router.POST(pattern, func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		rest.handleCors(w, r)
		// create context
		ctx := HttpContext{W: w, R: r, params: p}
		// authenticate
		if rest.Auth != nil && !rest.Auth.Authenticate(&ctx) {
			ctx.RespERRString(http.StatusForbidden, "Not logged in!")
			return
		}
		// if authenticate, pass to handle
		handler(&ctx)
	})
}

func (rest *HttpRest) PUT(pattern string, handler func(ctx *HttpContext)) {
	rest.handlePreflight(pattern)
	rest.Router.PUT(pattern, func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		rest.handleCors(w, r)
		// create context
		ctx := HttpContext{W: w, R: r, params: p}
		// authenticate
		if rest.Auth != nil && !rest.Auth.Authenticate(&ctx) {
			ctx.RespERRString(http.StatusForbidden, "Not logged in!")
			return
		}
		// if authenticate, pass to handle
		handler(&ctx)
	})
}

func (ctx *HttpContext) GetPayload(v interface{}) error {
	return json.NewDecoder(ctx.R.Body).Decode(v)
}

func (ctx *HttpContext) GetParam(name string) string {
	return ctx.params.ByName(name)
}

func (ctx *HttpContext) RespOK(value interface{}) error {
	//fmt.Println("writing response value: ", value)
	// convert value to json string
	str, err := json.Marshal(value)
	if err != nil {
		ctx.RespERRString(http.StatusInternalServerError, "Marshalling error! "+err.Error())
		return err
	}
	//fmt.Println("writing response str: ", str)
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
