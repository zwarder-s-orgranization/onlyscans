// Package paramschema checks node params against node-params.schema.json.
package paramschema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
)

type doc struct {
	Defs map[string]schema `json:"$defs"`
}

type rawDoc struct {
	Defs map[string]json.RawMessage `json:"$defs"`
}

type schema struct {
	Ref                  string            `json:"$ref"`
	Type                 any               `json:"type"`
	Required             []string          `json:"required"`
	AdditionalProperties any               `json:"additionalProperties"`
	Properties           map[string]schema `json:"properties"`
	Enum                 []any             `json:"enum"`
	MinLength            *int              `json:"minLength"`
	MaxLength            *int              `json:"maxLength"`
	Format               string            `json:"format"`
	MinItems             *int              `json:"minItems"`
	Minimum              *float64          `json:"minimum"`
	Maximum              *float64          `json:"maximum"`
	Items                *schema           `json:"items"`
}

var (
	mu      sync.RWMutex
	loaded  doc
	rawDefs map[string]json.RawMessage
)

// reset clears the cached schema document (used in tests).
func reset() {
	mu.Lock()
	loaded = doc{}
	rawDefs = nil
	mu.Unlock()
}

// Load reads the canonical schema. Later calls replace the previous document safely.
func Load(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read param schema %s: %w", path, err)
	}
	var next doc
	if err := json.Unmarshal(raw, &next); err != nil {
		return fmt.Errorf("parse param schema %s: %w", path, err)
	}
	if len(next.Defs) == 0 {
		return fmt.Errorf("param schema %s contains no $defs", path)
	}
	var nextRaw rawDoc
	if err := json.Unmarshal(raw, &nextRaw); err != nil {
		return fmt.Errorf("parse raw param schema %s: %w", path, err)
	}
	mu.Lock()
	loaded = next
	rawDefs = nextRaw.Defs
	mu.Unlock()
	return nil
}

// LoadDefault searches the repo and the container path.
func LoadDefault() error {
	if p := os.Getenv("PARAMS_SCHEMA"); p != "" {
		return Load(p)
	}
	candidates := []string{"/node-params.schema.json"}
	dir, err := os.Getwd()
	if err == nil {
		for {
			candidates = append(candidates, filepath.Join(dir, "packages", "contracts", "schemas", "node-params.schema.json"))
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	var last error
	for _, path := range candidates {
		if err := Load(path); err == nil {
			return nil
		} else {
			last = err
		}
	}
	if last == nil {
		return errors.New("node-params.schema.json not found")
	}
	return last
}

// RawDef returns the JSON Schema definition for a built-in plugin from $defs.
// When the definition references shared #/$defs/* helpers, those helpers are
// embedded under "$defs" so the returned schema is self-contained.
func RawDef(pluginID string) ([]byte, bool) {
	mu.RLock()
	defs := rawDefs
	mu.RUnlock()
	if len(defs) == 0 {
		if err := LoadDefault(); err != nil {
			return nil, false
		}
		mu.RLock()
		defs = rawDefs
		mu.RUnlock()
		if len(defs) == 0 {
			return nil, false
		}
	}
	raw, ok := defs[pluginID]
	if !ok || len(raw) == 0 {
		return nil, false
	}
	if !bytes.Contains(raw, []byte("#/$defs/")) {
		return slices.Clone(raw), true
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return slices.Clone(raw), true
	}
	shared := make(map[string]json.RawMessage)
	for name, def := range defs {
		if !strings.Contains(name, ".") {
			shared[name] = def
		}
	}
	if len(shared) > 0 {
		if encoded, err := json.Marshal(shared); err == nil {
			obj["$defs"] = encoded
		}
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return slices.Clone(raw), true
	}
	return out, true
}

// Check validates params for a built-in plugin. Fails closed if the schema cannot be loaded.
// External plugins not defined in $defs pass through once the schema is loaded.
func Check(plugin string, params map[string]any) error {
	mu.RLock()
	d := loaded
	mu.RUnlock()
	if len(d.Defs) == 0 {
		if err := LoadDefault(); err != nil {
			return fmt.Errorf("param schema unavailable: %w", err)
		}
		mu.RLock()
		d = loaded
		mu.RUnlock()
		if len(d.Defs) == 0 {
			return errors.New("param schema unavailable: empty definitions")
		}
	}
	def, ok := d.Defs[plugin]
	if !ok {
		return nil
	}
	return validate(d.Defs, plugin, params, def)
}

func validate(defs map[string]schema, path string, value any, sch schema) error {
	if sch.Ref != "" {
		name := strings.TrimPrefix(sch.Ref, "#/$defs/")
		target, ok := defs[name]
		if !ok {
			return fmt.Errorf("%s: unknown ref %s", path, sch.Ref)
		}
		sch = target
	}
	types := typeNames(sch.Type)
	if len(types) == 0 {
		types = []string{"object"}
	}
	matched := false
	var last error
	for _, kind := range types {
		if err := checkKind(defs, path, value, kind, sch); err != nil {
			last = err
			continue
		}
		matched = true
		break
	}
	if !matched {
		if last != nil {
			return last
		}
		return fmt.Errorf("%s: неверный тип", path)
	}
	return nil
}

func checkKind(defs map[string]schema, path string, value any, kind string, sch schema) error {
	switch kind {
	case "object":
		obj, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: ожидается объект", path)
		}
		for _, key := range sch.Required {
			if _, ok := obj[key]; !ok {
				return fmt.Errorf("%s: нет поля %s", path, key)
			}
		}
		allowExtra := true
		if sch.AdditionalProperties != nil {
			if b, ok := sch.AdditionalProperties.(bool); ok {
				allowExtra = b
			}
		}
		for key, child := range obj {
			prop, ok := sch.Properties[key]
			if !ok {
				if !allowExtra {
					return fmt.Errorf("%s: лишнее поле %s", path, key)
				}
				continue
			}
			if err := validate(defs, path+"."+key, child, prop); err != nil {
				return err
			}
		}
	case "string":
		s, ok := value.(string)
		if !ok {
			return fmt.Errorf("%s: ожидается строка", path)
		}
		if sch.MinLength != nil && len(s) < *sch.MinLength {
			return fmt.Errorf("%s: строка короче %d", path, *sch.MinLength)
		}
		if sch.MaxLength != nil && len(s) > *sch.MaxLength {
			return fmt.Errorf("%s: строка длиннее %d", path, *sch.MaxLength)
		}
		if sch.Format == "email" && !validEmail(s) {
			return fmt.Errorf("%s: не email", path)
		}
		if err := inEnum(path, s, sch.Enum); err != nil {
			return err
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("%s: ожидается boolean", path)
		}
	case "integer", "number":
		n, ok := number(value)
		if !ok {
			return fmt.Errorf("%s: ожидается число", path)
		}
		if kind == "integer" && n != float64(int64(n)) {
			return fmt.Errorf("%s: ожидается целое", path)
		}
		if sch.Minimum != nil && n < *sch.Minimum {
			return fmt.Errorf("%s: меньше минимума", path)
		}
		if sch.Maximum != nil && n > *sch.Maximum {
			return fmt.Errorf("%s: больше максимума", path)
		}
	case "array":
		items, ok := value.([]any)
		if !ok {
			return fmt.Errorf("%s: ожидается массив", path)
		}
		if sch.MinItems != nil && len(items) < *sch.MinItems {
			return fmt.Errorf("%s: массив короче %d", path, *sch.MinItems)
		}
		if sch.Items != nil {
			for i, item := range items {
				if err := validate(defs, fmt.Sprintf("%s[%d]", path, i), item, *sch.Items); err != nil {
					return err
				}
			}
		}
	default:
		return fmt.Errorf("%s: неподдерживаемый тип %s", path, kind)
	}
	return nil
}

func typeNames(v any) []string {
	switch t := v.(type) {
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []any:
		var out []string
		for _, item := range t {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func validEmail(s string) bool {
	if strings.ContainsAny(s, " \r\n\t") {
		return false
	}
	at := strings.Index(s, "@")
	if at <= 0 {
		return false
	}
	host := s[at+1:]
	return strings.Contains(host, ".") && !strings.HasPrefix(host, ".") && !strings.HasSuffix(host, ".")
}

func inEnum(path string, value string, enum []any) error {
	if len(enum) == 0 {
		return nil
	}
	for _, item := range enum {
		if fmt.Sprint(item) == value {
			return nil
		}
	}
	return fmt.Errorf("%s: значение вне enum", path)
}

func number(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	default:
		return 0, false
	}
}
