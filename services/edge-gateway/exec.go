package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/99designs/gqlgen/graphql"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/extension"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/99designs/gqlgen/graphql/introspection"
	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/gqlerror"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	secflowv1 "github.com/secflow/secflow/packages/proto/gen/go/secflow/v1"
	"github.com/secflow/secflow/services/internal/auth"
	"github.com/secflow/secflow/services/internal/obs"
	"github.com/secflow/secflow/services/internal/oidc"
)

type claimsKey struct{}
type authErrKey struct{}
type httpStatusHookKey struct{}

type gatewayExecSchema struct {
	gw *gateway
}

func (e *gatewayExecSchema) Schema() *ast.Schema {
	return e.gw.schema
}

func (e *gatewayExecSchema) Complexity(_ context.Context, _, _ string, _ int, _ map[string]any) (int, bool) {
	return 0, false
}

func (e *gatewayExecSchema) Exec(ctx context.Context) graphql.ResponseHandler {
	oc := graphql.GetOperationContext(ctx)
	if oc == nil || oc.Operation == nil {
		return graphql.OneShot(&graphql.Response{
			Errors: gqlerror.List{{
				Message:    "operation not found",
				Extensions: map[string]any{"code": "VALIDATION_FAILED"},
			}},
		})
	}
	if oc.Operation.Operation == ast.Subscription {
		return e.gw.execSubscription(ctx, oc)
	}
	done := false
	return func(respCtx context.Context) *graphql.Response {
		if done {
			return nil
		}
		done = true
		return e.gw.execOperation(respCtx, oc)
	}
}

type statusHookWriter struct {
	http.ResponseWriter
	status      int
	override    int
	wroteHeader bool
}

func (w *statusHookWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.status = code
}

func (w *statusHookWriter) SetOverride(code int) {
	if !w.wroteHeader && code != 0 {
		w.override = code
	}
}

func (w *statusHookWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.wroteHeader = true
		code := w.status
		if w.override != 0 {
			code = w.override
		}
		if code == 0 {
			code = http.StatusOK
		}
		w.ResponseWriter.WriteHeader(code)
	}
	return w.ResponseWriter.Write(p)
}

func (w *statusHookWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (g *gateway) gqlServer() *handler.Server {
	g.gqlOnce.Do(func() {
		srv := handler.New(&gatewayExecSchema{gw: g})
		srv.AddTransport(transport.Options{})
		srv.AddTransport(transport.POST{
			UseGrapQLResponseJsonByDefault: true,
		})
		srv.AddTransport(transport.Websocket{
			Implementation:        gorillaWebsocketImpl{},
			InitFunc:              g.wsInit,
			KeepAlivePingInterval: 15 * time.Second,
		})
		srv.Use(extension.FixedComplexityLimit(2000))
		if !strings.EqualFold(os.Getenv("DISABLE_INTROSPECTION"), "true") {
			srv.Use(extension.Introspection{})
		}
		srv.SetErrorPresenter(func(ctx context.Context, err error) *gqlerror.Error {
			var gqlErr *gqlerror.Error
			if errors.As(err, &gqlErr) {
				if gqlErr.Extensions == nil {
					gqlErr.Extensions = map[string]any{"code": "VALIDATION_FAILED"}
				}
				return gqlErr
			}
			slog.Error("graphql error", "err", err)
			return &gqlerror.Error{
				Message:    "internal server error",
				Path:       graphql.GetPath(ctx),
				Extensions: map[string]any{"code": "INTERNAL"},
			}
		})
		srv.SetRecoverFunc(func(ctx context.Context, recovered any) error {
			slog.Error("graphql panic recovered", "panic", recovered)
			return &gqlerror.Error{
				Message:    "internal server error",
				Path:       graphql.GetPath(ctx),
				Extensions: map[string]any{"code": "INTERNAL"},
			}
		})
		srv.AroundResponses(func(ctx context.Context, next graphql.ResponseHandler) *graphql.Response {
			resp := next(ctx)
			if resp != nil && len(resp.Errors) > 0 && isEmptyGraphQLData(resp.Data) {
				if sw, ok := ctx.Value(httpStatusHookKey{}).(*statusHookWriter); ok && sw != nil {
					if code := authHTTPStatus(resp.Errors[0]); code != 0 {
						sw.SetOverride(code)
					}
				}
			}
			return resp
		})
		g.gqlSrv = srv
	})
	return g.gqlSrv
}

func (g *gateway) graphql(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if tp := r.Header.Get("traceparent"); tp != "" {
		ctx = context.WithValue(ctx, traceKey{}, tp)
		if obs.TraceIDFromContext(ctx) == "" {
			ctx = obs.ExtractTraceparent(ctx, tp)
		}
	}
	claims, authErr := g.bearer(r.WithContext(ctx))
	subject := "anon"
	if claims != nil && claims.Subject != "" {
		subject = claims.Subject
	}
	if g.limited(ctx, subject) {
		writeErr(w, http.StatusTooManyRequests, "RATE_LIMITED", "rate limit exceeded")
		return
	}
	if strings.Contains(strings.ToLower(r.Header.Get("Upgrade")), "websocket") {
		g.sockets(w, r.WithContext(ctx))
		return
	}
	sw := &statusHookWriter{ResponseWriter: w}
	ctx = context.WithValue(ctx, claimsKey{}, claims)
	ctx = context.WithValue(ctx, authErrKey{}, authErr)
	ctx = context.WithValue(ctx, httpStatusHookKey{}, sw)

	req := r.WithContext(ctx)
	if req.Method == http.MethodPost && strings.TrimSpace(req.Header.Get("Content-Type")) == "" {
		req = req.Clone(ctx)
		req.Header.Set("Content-Type", "application/json")
	}
	req.Body = http.MaxBytesReader(sw, req.Body, 1<<20)
	g.gqlServer().ServeHTTP(sw, req)
}

func (g *gateway) execOperation(ctx context.Context, oc *graphql.OperationContext) *graphql.Response {
	claims, _ := ctx.Value(claimsKey{}).(*auth.Claims)
	authErr, _ := ctx.Value(authErrKey{}).(error)

	rootType := "Query"
	if oc.Operation.Operation == ast.Mutation {
		rootType = "Mutation"
	}
	rootDef := g.schema.Types[rootType]
	fields := graphql.CollectFields(oc, oc.Operation.SelectionSet, []string{rootType})
	data := make(map[string]any, len(fields))
	nullRoot := false

	for _, cf := range fields {
		fieldPath := ast.Path{ast.PathName(cf.Alias)}
		if cf.Name == "__typename" {
			data[cf.Alias] = rootType
			continue
		}
		if rootType == "Query" && cf.Name == "__schema" {
			if oc.DisableIntrospection {
				graphql.AddError(ctx, &gqlerror.Error{
					Message:    "introspection is disabled",
					Path:       fieldPath,
					Extensions: map[string]any{"code": "FORBIDDEN"},
				})
				nullRoot = true
				continue
			}
			data[cf.Alias] = g.projectIntrospectionSchema(oc, cf.Selections)
			continue
		}
		if rootType == "Query" && cf.Name == "__type" {
			if oc.DisableIntrospection {
				graphql.AddError(ctx, &gqlerror.Error{
					Message:    "introspection is disabled",
					Path:       fieldPath,
					Extensions: map[string]any{"code": "FORBIDDEN"},
				})
				data[cf.Alias] = nil
				continue
			}
			args := cf.ArgumentMap(oc.Variables)
			def := g.schema.Types[asString(args["name"])]
			if def == nil {
				data[cf.Alias] = nil
				continue
			}
			data[cf.Alias] = g.projectIntrospectionType(oc, introspection.WrapTypeFromDef(g.schema, def), cf.Selections)
			continue
		}

		var fieldDef *ast.FieldDefinition
		if rootDef != nil {
			fieldDef = rootDef.Fields.ForName(cf.Name)
		}
		isNonNull := fieldDef != nil && fieldDef.Type != nil && fieldDef.Type.NonNull

		if !allowed(cf.Name, claims) {
			code := "UNAUTHENTICATED"
			if authErr == nil && claims != nil {
				code = "FORBIDDEN"
			}
			graphql.AddError(ctx, &gqlerror.Error{
				Message:    code,
				Path:       fieldPath,
				Extensions: map[string]any{"code": code},
			})
			if isNonNull {
				nullRoot = true
			} else {
				data[cf.Alias] = nil
			}
			continue
		}

		args := cf.ArgumentMap(oc.Variables)
		val, err := g.resolve(ctx, claims, cf.Name, args)
		if err != nil {
			ge := graphqlErr(err)
			ge.Path = fieldPath
			graphql.AddError(ctx, ge)
			if isNonNull {
				nullRoot = true
			} else {
				data[cf.Alias] = nil
			}
			continue
		}

		var fieldType *ast.Type
		if fieldDef != nil {
			fieldType = fieldDef.Type
		}
		projected, ok := g.projectValue(ctx, oc, fieldType, cf.Selections, val, fieldPath)
		if !ok {
			if isNonNull {
				nullRoot = true
			} else {
				data[cf.Alias] = nil
			}
			continue
		}
		data[cf.Alias] = projected
	}

	resp := &graphql.Response{
		Errors: graphql.GetErrors(ctx),
	}
	if nullRoot {
		resp.Data = json.RawMessage("null")
		return resp
	}
	raw, err := json.Marshal(data)
	if err != nil {
		slog.Error("marshal graphql response", "err", err)
		resp.Errors = append(resp.Errors, &gqlerror.Error{
			Message:    "internal server error",
			Extensions: map[string]any{"code": "INTERNAL"},
		})
		resp.Data = json.RawMessage("null")
		return resp
	}
	resp.Data = raw
	return resp
}

func (g *gateway) projectValue(ctx context.Context, oc *graphql.OperationContext, t *ast.Type, sel ast.SelectionSet, val any, path ast.Path) (any, bool) {
	if t == nil {
		return val, true
	}
	if t.NonNull {
		if isNilValue(val) {
			graphql.AddError(ctx, &gqlerror.Error{
				Message:    "cannot return null for non-nullable field",
				Path:       path,
				Extensions: map[string]any{"code": "INTERNAL"},
			})
			return nil, false
		}
		inner := *t
		inner.NonNull = false
		return g.projectValue(ctx, oc, &inner, sel, val, path)
	}
	if isNilValue(val) {
		return nil, true
	}
	if t.Elem != nil {
		items := asList(val)
		out := make([]any, 0, len(items))
		for i, item := range items {
			elemPath := append(slices.Clone(path), ast.PathIndex(i))
			projected, ok := g.projectValue(ctx, oc, t.Elem, sel, item, elemPath)
			if !ok {
				if t.Elem.NonNull {
					return nil, false
				}
				projected = nil
			}
			out = append(out, projected)
		}
		return out, true
	}
	def := g.schema.Types[t.NamedType]
	if def == nil || (def.Kind != ast.Object && def.Kind != ast.Interface && def.Kind != ast.Union) {
		return val, true
	}
	src, ok := val.(map[string]any)
	if !ok || src == nil {
		graphql.AddError(ctx, &gqlerror.Error{
			Message:    "unexpected non-object value",
			Path:       path,
			Extensions: map[string]any{"code": "INTERNAL"},
		})
		return nil, false
	}
	typeName := def.Name
	if explicit, ok := src["__typename"].(string); ok && explicit != "" {
		typeName = explicit
	}
	collected := graphql.CollectFields(oc, sel, []string{typeName})
	out := make(map[string]any, len(collected))
	for _, cf := range collected {
		if cf.Name == "__typename" {
			out[cf.Alias] = typeName
			continue
		}
		child := def.Fields.ForName(cf.Name)
		if child == nil {
			continue
		}
		childPath := append(slices.Clone(path), ast.PathName(cf.Alias))
		projected, ok := g.projectValue(ctx, oc, child.Type, cf.Selections, src[cf.Name], childPath)
		if !ok {
			if child.Type != nil && child.Type.NonNull {
				return nil, false
			}
			out[cf.Alias] = nil
			continue
		}
		out[cf.Alias] = projected
	}
	return out, true
}

func (g *gateway) projectIntrospectionSchema(oc *graphql.OperationContext, sel ast.SelectionSet) map[string]any {
	s := introspection.WrapSchema(g.schema)
	fields := graphql.CollectFields(oc, sel, []string{"__Schema"})
	out := make(map[string]any, len(fields))
	for _, cf := range fields {
		switch cf.Name {
		case "__typename":
			out[cf.Alias] = "__Schema"
		case "description":
			out[cf.Alias] = s.Description()
		case "types":
			all := s.Types()
			items := make([]any, 0, len(all))
			for i := range all {
				items = append(items, g.projectIntrospectionType(oc, &all[i], cf.Selections))
			}
			out[cf.Alias] = items
		case "queryType":
			out[cf.Alias] = g.projectIntrospectionType(oc, s.QueryType(), cf.Selections)
		case "mutationType":
			out[cf.Alias] = g.projectIntrospectionType(oc, s.MutationType(), cf.Selections)
		case "subscriptionType":
			out[cf.Alias] = g.projectIntrospectionType(oc, s.SubscriptionType(), cf.Selections)
		case "directives":
			dirs := s.Directives()
			items := make([]any, 0, len(dirs))
			for i := range dirs {
				items = append(items, g.projectIntrospectionDirective(oc, &dirs[i], cf.Selections))
			}
			out[cf.Alias] = items
		}
	}
	return out
}

func (g *gateway) projectIntrospectionType(oc *graphql.OperationContext, t *introspection.Type, sel ast.SelectionSet) any {
	if t == nil {
		return nil
	}
	fields := graphql.CollectFields(oc, sel, []string{"__Type"})
	out := make(map[string]any, len(fields))
	for _, cf := range fields {
		switch cf.Name {
		case "__typename":
			out[cf.Alias] = "__Type"
		case "kind":
			out[cf.Alias] = t.Kind()
		case "name":
			out[cf.Alias] = t.Name()
		case "description":
			out[cf.Alias] = t.Description()
		case "specifiedByURL":
			out[cf.Alias] = t.SpecifiedByURL()
		case "isOneOf":
			out[cf.Alias] = t.IsOneOf()
		case "fields":
			args := cf.ArgumentMap(oc.Variables)
			list := t.Fields(asBool(args["includeDeprecated"]))
			if list == nil {
				out[cf.Alias] = nil
				continue
			}
			items := make([]any, 0, len(list))
			for i := range list {
				items = append(items, g.projectIntrospectionField(oc, &list[i], cf.Selections))
			}
			out[cf.Alias] = items
		case "interfaces":
			list := t.Interfaces()
			if list == nil {
				out[cf.Alias] = nil
				continue
			}
			items := make([]any, 0, len(list))
			for i := range list {
				items = append(items, g.projectIntrospectionType(oc, &list[i], cf.Selections))
			}
			out[cf.Alias] = items
		case "possibleTypes":
			list := t.PossibleTypes()
			if list == nil {
				out[cf.Alias] = nil
				continue
			}
			items := make([]any, 0, len(list))
			for i := range list {
				items = append(items, g.projectIntrospectionType(oc, &list[i], cf.Selections))
			}
			out[cf.Alias] = items
		case "enumValues":
			args := cf.ArgumentMap(oc.Variables)
			list := t.EnumValues(asBool(args["includeDeprecated"]))
			if list == nil {
				out[cf.Alias] = nil
				continue
			}
			items := make([]any, 0, len(list))
			for i := range list {
				items = append(items, g.projectIntrospectionEnumValue(oc, &list[i], cf.Selections))
			}
			out[cf.Alias] = items
		case "inputFields":
			args := cf.ArgumentMap(oc.Variables)
			list := t.VisibleInputFields(asBool(args["includeDeprecated"]))
			if list == nil {
				out[cf.Alias] = nil
				continue
			}
			items := make([]any, 0, len(list))
			for i := range list {
				items = append(items, g.projectIntrospectionInputValue(oc, &list[i], cf.Selections))
			}
			out[cf.Alias] = items
		case "ofType":
			out[cf.Alias] = g.projectIntrospectionType(oc, t.OfType(), cf.Selections)
		}
	}
	return out
}

func (g *gateway) projectIntrospectionField(oc *graphql.OperationContext, f *introspection.Field, sel ast.SelectionSet) any {
	if f == nil {
		return nil
	}
	fields := graphql.CollectFields(oc, sel, []string{"__Field"})
	out := make(map[string]any, len(fields))
	for _, cf := range fields {
		switch cf.Name {
		case "__typename":
			out[cf.Alias] = "__Field"
		case "name":
			out[cf.Alias] = f.Name
		case "description":
			out[cf.Alias] = f.Description()
		case "args":
			args := cf.ArgumentMap(oc.Variables)
			list := f.VisibleArgs(asBool(args["includeDeprecated"]))
			items := make([]any, 0, len(list))
			for i := range list {
				items = append(items, g.projectIntrospectionInputValue(oc, &list[i], cf.Selections))
			}
			out[cf.Alias] = items
		case "type":
			out[cf.Alias] = g.projectIntrospectionType(oc, f.Type, cf.Selections)
		case "isDeprecated":
			out[cf.Alias] = f.IsDeprecated()
		case "deprecationReason":
			out[cf.Alias] = f.DeprecationReason()
		}
	}
	return out
}

func (g *gateway) projectIntrospectionInputValue(oc *graphql.OperationContext, iv *introspection.InputValue, sel ast.SelectionSet) any {
	if iv == nil {
		return nil
	}
	fields := graphql.CollectFields(oc, sel, []string{"__InputValue"})
	out := make(map[string]any, len(fields))
	for _, cf := range fields {
		switch cf.Name {
		case "__typename":
			out[cf.Alias] = "__InputValue"
		case "name":
			out[cf.Alias] = iv.Name
		case "description":
			out[cf.Alias] = iv.Description()
		case "type":
			out[cf.Alias] = g.projectIntrospectionType(oc, iv.Type, cf.Selections)
		case "defaultValue":
			out[cf.Alias] = iv.DefaultValue
		case "isDeprecated":
			out[cf.Alias] = iv.IsDeprecated()
		case "deprecationReason":
			out[cf.Alias] = iv.DeprecationReason()
		}
	}
	return out
}

func (g *gateway) projectIntrospectionEnumValue(oc *graphql.OperationContext, ev *introspection.EnumValue, sel ast.SelectionSet) any {
	if ev == nil {
		return nil
	}
	fields := graphql.CollectFields(oc, sel, []string{"__EnumValue"})
	out := make(map[string]any, len(fields))
	for _, cf := range fields {
		switch cf.Name {
		case "__typename":
			out[cf.Alias] = "__EnumValue"
		case "name":
			out[cf.Alias] = ev.Name
		case "description":
			out[cf.Alias] = ev.Description()
		case "isDeprecated":
			out[cf.Alias] = ev.IsDeprecated()
		case "deprecationReason":
			out[cf.Alias] = ev.DeprecationReason()
		}
	}
	return out
}

func (g *gateway) projectIntrospectionDirective(oc *graphql.OperationContext, d *introspection.Directive, sel ast.SelectionSet) any {
	if d == nil {
		return nil
	}
	fields := graphql.CollectFields(oc, sel, []string{"__Directive"})
	out := make(map[string]any, len(fields))
	for _, cf := range fields {
		switch cf.Name {
		case "__typename":
			out[cf.Alias] = "__Directive"
		case "name":
			out[cf.Alias] = d.Name
		case "description":
			out[cf.Alias] = d.Description()
		case "locations":
			out[cf.Alias] = stringList(d.Locations)
		case "args":
			args := cf.ArgumentMap(oc.Variables)
			list := d.VisibleArgs(asBool(args["includeDeprecated"]))
			items := make([]any, 0, len(list))
			for i := range list {
				items = append(items, g.projectIntrospectionInputValue(oc, &list[i], cf.Selections))
			}
			out[cf.Alias] = items
		case "isRepeatable":
			out[cf.Alias] = d.IsRepeatable
		}
	}
	return out
}

func isNilValue(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface:
		return rv.IsNil()
	default:
		return false
	}
}

func isEmptyGraphQLData(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" || s == "{}" {
		return true
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return false
	}
	for _, v := range m {
		if v != nil {
			return false
		}
	}
	return true
}

func authHTTPStatus(err *gqlerror.Error) int {
	if err == nil || err.Extensions == nil {
		return 0
	}
	code, _ := err.Extensions["code"].(string)
	switch code {
	case "UNAUTHENTICATED":
		return http.StatusUnauthorized
	case "FORBIDDEN", "SECRET_SCOPE_DENIED", "ALLOWLIST_DENIED":
		return http.StatusForbidden
	default:
		return 0
	}
}

func (g *gateway) bearer(r *http.Request) (*auth.Claims, error) {
	return g.authenticateToken(r.Context(), r.Header.Get("Authorization"))
}

func (g *gateway) authenticateToken(ctx context.Context, authHeader string) (*auth.Claims, error) {
	h := strings.TrimSpace(authHeader)
	if h == "" {
		return nil, status.Error(codes.Unauthenticated, "UNAUTHENTICATED")
	}
	token := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	if token == "" || token == h && strings.Contains(h, " ") {
		return nil, status.Error(codes.Unauthenticated, "UNAUTHENTICATED")
	}
	if strings.HasPrefix(token, "sf_") {
		return g.verifyScopedToken(ctx, token)
	}
	if strings.EqualFold(os.Getenv("AUTH_MODE"), "oidc") {
		if claims, err := g.oidcBearer(ctx, token); err == nil {
			return claims, nil
		}
		return g.verifyScopedToken(ctx, token)
	}
	if claims, err := auth.Verify(g.secret, token); err == nil {
		return &claims, nil
	}
	return g.verifyScopedToken(ctx, token)
}

func (g *gateway) verifyScopedToken(ctx context.Context, token string) (*auth.Claims, error) {
	if g.secs == nil || token == "" {
		return nil, status.Error(codes.Unauthenticated, "UNAUTHENTICATED")
	}
	verCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	resp, err := g.secs.VerifyScopedToken(verCtx, &secflowv1.VerifyScopedTokenRequest{PlaintextToken: token})
	if err != nil || !resp.GetValid() || resp.GetActor() == nil {
		return nil, status.Error(codes.Unauthenticated, "UNAUTHENTICATED")
	}
	actor := resp.GetActor()
	return &auth.Claims{
		Subject: actor.GetSubject(),
		Email:   actor.GetEmail(),
		Role:    roleNameFromProto(actor.GetRole()),
		Scopes:  append([]string(nil), actor.GetScopes()...),
		Wf:      actor.GetScopedWorkflowId(),
	}, nil
}

func (g *gateway) oidcBearer(ctx context.Context, token string) (*auth.Claims, error) {
	rawURL := os.Getenv("OIDC_JWKS_URL")
	if rawURL == "" {
		return nil, status.Error(codes.Unauthenticated, "UNAUTHENTICATED")
	}
	g.mu.Lock()
	keys := g.jwks
	fresh := g.jwksAt.Add(10*time.Minute).After(time.Now()) && len(keys) > 0
	g.mu.Unlock()
	if !fresh {
		reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "UNAUTHENTICATED")
		}
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "UNAUTHENTICATED")
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if readErr != nil || resp.StatusCode >= 300 {
			return nil, status.Error(codes.Unauthenticated, "UNAUTHENTICATED")
		}
		parsed, err := oidc.ParseJWKS(body)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "UNAUTHENTICATED")
		}
		g.mu.Lock()
		g.jwks = parsed
		g.jwksAt = time.Now()
		keys = parsed
		g.mu.Unlock()
	}
	id, err := oidc.Verify(token, keys)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "UNAUTHENTICATED")
	}
	return &auth.Claims{Subject: id.Subject, Email: id.Email, Role: strings.ToLower(id.Role)}, nil
}

func hasScope(c *auth.Claims, scope string) bool {
	if c == nil {
		return false
	}
	for _, item := range c.Scopes {
		if item == scope {
			return true
		}
	}
	return false
}

func allowed(field string, c *auth.Claims) bool {
	if field == "login" || field == "__typename" || field == "__schema" || field == "__type" {
		return true
	}
	if c == nil {
		return false
	}
	rank := roleRank(c.Role)

	switch field {
	case "me":
		return true
	// Owner-only (never scoped tokens)
	case "scopedTokens", "createScopedToken", "revokeScopedToken",
		"registerMcpConnection", "updateMcpConnection", "deleteMcpConnection", "testMcpConnection",
		"approvePluginInstallation",
		"setPluginInstallationEnabled", "deletePluginInstallation":
		return rank >= 3
	// Editor+ only (never scoped tokens); non-DECLARATIVE installPlugin/updatePluginInstallation further gated to OWNER in resolver
	case "secrets", "createSecret", "deleteSecret",
		"saveWorkflow", "createWorkflow", "updateWorkflow", "deleteWorkflow",
		"publishTemplate", "rerunFromNode", "cancelRun",
		"installPlugin", "updatePluginInstallation",
		"testDeclarativePlugin", "saveNode", "updateSavedNode", "deleteSavedNode":
		return rank >= 2
	// Viewer+ only (never scoped tokens)
	case "mcpConnections", "mcpConnectionTools",
		"aiAuditLogs", "webhookInspectorDeliveries", "webhookInspectorEvents",
		"generateCiConfig", "catalogs", "aiProviderStatus",
		"pluginRegistryEvents", "pluginInstallationEvents",
		"pluginInstallations", "pluginInstallation", "pluginPresets",
		"declarativePluginBlueprints", "savedNodes":
		return rank >= 1
	// Run start
	case "startRun":
		return rank >= 2 || hasScope(c, "ci:startRun") || hasScope(c, "mcp:run")
	// Template clone
	case "cloneTemplate":
		return rank >= 2 || hasScope(c, "mcp:write")
	// Preview & workflow validation (viewer+, mcp:read) per docs/contracts/README.md §5.1
	case "validateWorkflow", "generateWorkflow", "generateWorkflowFromText":
		return rank >= 1 || hasScope(c, "mcp:read")
	// Run and artifact reads (viewer+, ci:readRun, mcp:read)
	case "run", "runs", "findings", "submission", "sbom", "aiReport", "readableReport", "runEvents":
		return rank >= 1 || hasScope(c, "ci:readRun") || hasScope(c, "mcp:read")
	// Catalog/workflow/plugin/envelope reads (viewer+, mcp:read)
	case "workflows", "workflow", "templates", "template", "plugins", "plugin",
		"nodePayload", "nodeRunPayload":
		return rank >= 1 || hasScope(c, "mcp:read")
	default:
		return false
	}
}

func roleRank(role string) int {
	switch strings.ToLower(role) {
	case "owner":
		return 3
	case "editor":
		return 2
	case "viewer":
		return 1
	default:
		return 0
	}
}

func graphqlErr(err error) *gqlerror.Error {
	st, ok := status.FromError(err)
	code := "INTERNAL"
	msg := "internal server error"
	if ok {
		switch st.Code() {
		case codes.Unauthenticated:
			code = "UNAUTHENTICATED"
			msg = "authentication required"
		case codes.PermissionDenied:
			code = "FORBIDDEN"
			msg = "forbidden"
			if strings.Contains(st.Message(), "SECRET_SCOPE_DENIED") {
				code = "SECRET_SCOPE_DENIED"
				msg = "secret scope denied"
			} else if strings.Contains(st.Message(), "ALLOWLIST") {
				code = "ALLOWLIST_DENIED"
				msg = "repository or endpoint not allowlisted"
			}
		case codes.NotFound:
			code = "NOT_FOUND"
			msg = "resource not found"
		case codes.Aborted, codes.AlreadyExists:
			code = "CONFLICT"
			msg = "conflict"
		case codes.InvalidArgument:
			code = "VALIDATION_FAILED"
			msg = strings.TrimSpace(st.Message())
			if msg == "" {
				msg = "validation failed"
			}
		case codes.FailedPrecondition:
			lowMsg := strings.ToLower(st.Message())
			if strings.Contains(st.Message(), "DENYLIST_BLOCKED") ||
				strings.Contains(lowMsg, "denylist") ||
				strings.Contains(lowMsg, "blocked") {
				code = "DENYLIST_BLOCKED"
				msg = "operation blocked by policy"
			} else {
				code = "FAILED_PRECONDITION"
				msg = "precondition failed"
			}
		case codes.ResourceExhausted:
			code = "RATE_LIMITED"
			msg = "rate limit or capacity exceeded"
		default:
			slog.Error("graphql backend error", "grpc_code", st.Code().String(), "err", err)
		}
	} else {
		slog.Error("graphql internal error", "err", err)
	}
	return &gqlerror.Error{Message: msg, Extensions: map[string]any{"code": code}}
}

func writeGQL(w http.ResponseWriter, statusCode int, data any, errs gqlerror.List) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	body := map[string]any{}
	if data != nil {
		body["data"] = data
	}
	if len(errs) > 0 {
		items := make([]map[string]any, 0, len(errs))
		for _, err := range errs {
			items = append(items, map[string]any{"message": err.Message, "extensions": err.Extensions})
		}
		body["errors"] = items
	}
	_ = json.NewEncoder(w).Encode(body)
}

func writeErr(w http.ResponseWriter, statusCode int, code, msg string) {
	writeGQL(w, statusCode, nil, gqlerror.List{{Message: msg, Extensions: map[string]any{"code": code}}})
}
