//go:build js && wasm

// Command wasm is the voting client for the browser. It exposes the client
// package to the page as functions that take and return JSON text and
// answer with promises. All voter-side cryptography runs in this code;
// randomness comes from the browser's cryptographic generator.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"syscall/js"
	"time"

	"github.com/ansiwen/stimmig/client"
	"github.com/ansiwen/stimmig/tally"
)

// timeout bounds every call, including the wait for the login.
const timeout = 25 * time.Minute

// async wraps fn as a JavaScript function that returns a promise. The
// first argument is the state as JSON text.
func async(fn func(ctx context.Context, st *client.State, args []js.Value) (any, error)) js.Func {
	return js.FuncOf(func(_ js.Value, args []js.Value) any {
		return js.Global().Get("Promise").New(js.FuncOf(func(_ js.Value, settle []js.Value) any {
			go func() {
				out, err := func() (any, error) {
					var st client.State
					if len(args) == 0 {
						return nil, errors.New("the state is missing")
					}
					if err := json.Unmarshal([]byte(args[0].String()), &st); err != nil {
						return nil, err
					}
					ctx, cancel := context.WithTimeout(context.Background(), timeout)
					defer cancel()
					return fn(ctx, &st, args[1:])
				}()
				if err == nil {
					var data []byte
					if data, err = json.Marshal(out); err == nil {
						settle[0].Invoke(string(data))
						return
					}
				}
				settle[1].Invoke(js.Global().Get("Error").New(err.Error()))
			}()
			return nil
		}))
	})
}

// withState is the result of a call that changes the state. The page
// must store the state before it goes on.
type withState struct {
	State    *client.State `json:"state"`
	LoginURL string        `json:"login_url,omitempty"`
}

// info describes the election for the page.
type info struct {
	Title       string         `json:"title"`
	ReceiptMode string         `json:"receipt_mode"`
	Tally       tally.Manifest `json:"tally"`
	Phase       string         `json:"phase"`
	Eligible    uint64         `json:"eligible"`
	Issued      uint64         `json:"issued"`
	Cast        uint64         `json:"cast"`
	Result      *tally.Result  `json:"result,omitempty"`
}

func main() {
	g := js.Global()
	g.Set("stimmigInfo", async(func(ctx context.Context, st *client.State, _ []js.Value) (any, error) {
		rep, err := client.Log(ctx, st)
		if err != nil {
			return nil, err
		}
		m := rep.Log.Manifest
		return info{m.Title, m.ReceiptMode, m.Tally, rep.Phase, rep.Eligible, rep.Issued, rep.Cast, rep.Result}, nil
	}))
	g.Set("stimmigBegin", async(func(ctx context.Context, st *client.State, _ []js.Value) (any, error) {
		loginURL, err := client.Begin(ctx, st)
		return withState{st, loginURL}, err
	}))
	g.Set("stimmigComplete", async(func(ctx context.Context, st *client.State, _ []js.Value) (any, error) {
		return withState{State: st}, client.Complete(ctx, st)
	}))
	// The second argument is the ranking as JSON text: an array of rank
	// groups, each an array of candidate IDs.
	g.Set("stimmigCast", async(func(ctx context.Context, st *client.State, args []js.Value) (any, error) {
		var ranking tally.Ballot
		if len(args) == 0 || json.Unmarshal([]byte(args[0].String()), &ranking) != nil {
			return nil, errors.New("the ranking is missing or malformed")
		}
		err := client.Cast(ctx, st, ranking)
		// The state comes back also after a failure: it may hold the
		// ballot that must be sent again.
		return struct {
			withState
			Error string `json:"error,omitempty"`
		}{withState{State: st}, errText(err)}, nil
	}))
	g.Set("stimmigCheck", async(func(ctx context.Context, st *client.State, _ []js.Value) (any, error) {
		return client.Check(ctx, st)
	}))
	g.Call("dispatchEvent", g.Get("Event").New("stimmig-ready"))
	select {} // keep the functions alive
}

func errText(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}
