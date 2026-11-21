package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/99designs/gqlgen/graphql"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	gorilla "github.com/gorilla/websocket"
	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/gqlerror"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/auth"
	"github.com/secflow/secflow/services/internal/obs"
)

type gorillaWebsocketImpl struct{}

func (gorillaWebsocketImpl) Accept(w http.ResponseWriter, r *http.Request, options transport.WebsocketAcceptOptions) (transport.WebsocketConn, error) {
	subprotocols := []string{"graphql-transport-ws", "graphql-ws"}
	for _, sp := range options.Subprotocols {
		if !slices.Contains(subprotocols, sp) {
			subprotocols = append(subprotocols, sp)
		}
	}
	upgrader := gorilla.Upgrader{
		ReadBufferSize:  4096,
		WriteBufferSize: 4096,
		Subprotocols:    subprotocols,
		CheckOrigin:     checkWSOrigin,
	}
	conn, err := upgrader.Upgrade(w, r, options.ResponseHeader)
	if err != nil {
		return nil, err
	}
	return &gorillaWebsocketConn{conn: conn}, nil
}

func checkWSOrigin(r *http.Request) bool {
	return allowedWSOrigin(r.Header.Get("Origin"))
}

type gorillaWebsocketConn struct {
	conn    *gorilla.Conn
	writeMu sync.Mutex
}

func (c *gorillaWebsocketConn) NextReader() (int, io.Reader, error) {
	mt, r, err := c.conn.NextReader()
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) ||
			gorilla.IsCloseError(err,
				gorilla.CloseNormalClosure,
				gorilla.CloseGoingAway,
				gorilla.CloseNoStatusReceived,
				gorilla.CloseAbnormalClosure,
			) {
			return 0, nil, transport.ErrWebsocketClosed
		}
		return 0, nil, err
	}
	return mt, r, nil
}

func (c *gorillaWebsocketConn) WriteJSON(v any) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	return c.conn.WriteJSON(v)
}

func (c *gorillaWebsocketConn) WriteClose(closeCode int, message string) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_ = c.conn.WriteControl(
		gorilla.CloseMessage,
		gorilla.FormatCloseMessage(closeCode, message),
		time.Now().Add(5*time.Second),
	)
	return c.conn.Close()
}

func (c *gorillaWebsocketConn) Close() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.conn.Close()
}

func (c *gorillaWebsocketConn) Subprotocol() string {
	if sp := c.conn.Subprotocol(); sp != "" {
		return sp
	}
	return "graphql-transport-ws"
}

func (c *gorillaWebsocketConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *gorillaWebsocketConn) SetReadLimit(limit int64) {
	c.conn.SetReadLimit(limit)
}

func (g *gateway) sockets(w http.ResponseWriter, r *http.Request) {
	g.gqlServer().ServeHTTP(w, r)
}

func (g *gateway) wsInit(ctx context.Context, initPayload transport.InitPayload) (context.Context, *transport.InitPayload, error) {
	rawAuth := asString(initPayload["Authorization"])
	if rawAuth == "" {
		rawAuth = asString(initPayload["authorization"])
	}
	if rawAuth != "" {
		if claims, err := g.authenticateToken(ctx, rawAuth); err == nil && claims != nil {
			ctx = context.WithValue(ctx, claimsKey{}, claims)
		}
	}
	if tp := asString(initPayload["traceparent"]); tp != "" {
		ctx = context.WithValue(ctx, traceKey{}, tp)
		ctx = obs.ExtractTraceparent(ctx, tp)
	}
	return ctx, nil, nil
}

func (g *gateway) execSubscription(ctx context.Context, oc *graphql.OperationContext) graphql.ResponseHandler {
	subErr := func(gqlErr *gqlerror.Error) graphql.ResponseHandler {
		transport.AddSubscriptionError(ctx, gqlErr)
		return func(context.Context) *graphql.Response { return nil }
	}

	claims, _ := ctx.Value(claimsKey{}).(*auth.Claims)
	fields := graphql.CollectFields(oc, oc.Operation.SelectionSet, []string{"Subscription"})
	if len(fields) == 0 {
		return subErr(&gqlerror.Error{
			Message:    "subscription field required",
			Extensions: map[string]any{"code": "VALIDATION_FAILED"},
		})
	}
	cf := fields[0]
	if !allowed(cf.Name, claims) {
		code := "UNAUTHENTICATED"
		if claims != nil {
			code = "FORBIDDEN"
		}
		return subErr(&gqlerror.Error{
			Message:    code,
			Path:       ast.Path{ast.PathName(cf.Alias)},
			Extensions: map[string]any{"code": code},
		})
	}

	var fieldType *ast.Type
	if subDef := g.schema.Types["Subscription"]; subDef != nil {
		if fd := subDef.Fields.ForName(cf.Name); fd != nil {
			fieldType = fd.Type
		}
	}

	projectEvent := func(callCtx context.Context, payload any) *graphql.Response {
		projected, ok := g.projectValue(callCtx, oc, fieldType, cf.Selections, payload, ast.Path{ast.PathName(cf.Alias)})
		if !ok {
			return &graphql.Response{
				Data:   json.RawMessage("null"),
				Errors: graphql.GetErrors(callCtx),
			}
		}
		raw, err := json.Marshal(map[string]any{cf.Alias: projected})
		if err != nil {
			slog.Error("marshal subscription event", "field", cf.Name, "err", err)
			return &graphql.Response{
				Errors: gqlerror.List{{
					Message:    "internal server error",
					Extensions: map[string]any{"code": "INTERNAL"},
				}},
			}
		}
		return &graphql.Response{Data: raw}
	}

	args := cf.ArgumentMap(oc.Variables)
	actor := g.actorOf(claims)

	switch cf.Name {
	case "runEvents":
		runID := asString(args["runId"])
		if _, err := g.checkScopedRun(ctx, claims, actor, runID); err != nil {
			ge := graphqlErr(err)
			ge.Path = ast.Path{ast.PathName(cf.Alias)}
			return subErr(ge)
		}
		if g.runs == nil {
			return subErr(&gqlerror.Error{
				Message:    "run service unavailable",
				Path:       ast.Path{ast.PathName(cf.Alias)},
				Extensions: map[string]any{"code": "INTERNAL"},
			})
		}
		stream, err := g.runs.WatchRun(ctx, &secflowv1.WatchRunRequest{
			Actor:    actor,
			RunId:    runID,
			AfterSeq: asInt64(args["afterSeq"], 0),
		})
		if err != nil {
			ge := graphqlErr(err)
			ge.Path = ast.Path{ast.PathName(cf.Alias)}
			return subErr(ge)
		}
		return func(callCtx context.Context) *graphql.Response {
			if callCtx.Err() != nil {
				return nil
			}
			msg, recvErr := stream.Recv()
			if recvErr != nil {
				return nil
			}
			ev := msg.GetEvent()
			if ev == nil {
				return nil
			}
			return projectEvent(callCtx, eventMap(ev))
		}

	case "pluginRegistryEvents":
		if g.plugs == nil {
			return subErr(&gqlerror.Error{
				Message:    "plugin registry unavailable",
				Path:       ast.Path{ast.PathName(cf.Alias)},
				Extensions: map[string]any{"code": "INTERNAL"},
			})
		}
		stream, err := g.plugs.WatchPlugins(ctx, &secflowv1.WatchPluginsRequest{Actor: actor})
		if err != nil {
			ge := graphqlErr(err)
			ge.Path = ast.Path{ast.PathName(cf.Alias)}
			return subErr(ge)
		}
		return func(callCtx context.Context) *graphql.Response {
			if callCtx.Err() != nil {
				return nil
			}
			msg, recvErr := stream.Recv()
			if recvErr != nil {
				return nil
			}
			ev := msg.GetEvent()
			if ev == nil {
				return nil
			}
			payload := map[string]any{
				"eventType":  first(trimEnum(ev.GetEventType().String(), "PLUGIN_REGISTRY_EVENT_TYPE_"), "REGISTERED"),
				"plugin":     pluginMap(ev.GetPlugin()),
				"occurredAt": stamp(ev.GetOccurredAt()),
			}
			return projectEvent(callCtx, payload)
		}

	case "webhookInspectorEvents":
		channelKey := asString(args["channelKey"])
		initial, ch, unsubscribe := g.subscribeInspector(channelKey)
		stopAfter := context.AfterFunc(ctx, unsubscribe)
		idx := 0
		return func(callCtx context.Context) *graphql.Response {
			if idx < len(initial) {
				if callCtx.Err() != nil {
					stopAfter()
					unsubscribe()
					return nil
				}
				item := initial[idx]
				idx++
				return projectEvent(callCtx, item)
			}
			select {
			case <-callCtx.Done():
				stopAfter()
				unsubscribe()
				return nil
			case item, ok := <-ch:
				if !ok {
					stopAfter()
					unsubscribe()
					return nil
				}
				return projectEvent(callCtx, item)
			}
		}

	default:
		return subErr(&gqlerror.Error{
			Message:    "unknown subscription field",
			Path:       ast.Path{ast.PathName(cf.Alias)},
			Extensions: map[string]any{"code": "VALIDATION_FAILED"},
		})
	}
}
