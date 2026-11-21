package config

import (
	"fmt"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

// CurrentSchemaVersion is the configuration schema this binary accepts.
const CurrentSchemaVersion = 1

// Stable schema error identifiers.
const (
	// ErrorUnknownField marks a YAML key the configuration does not define.
	ErrorUnknownField = "config.schema.unknown_field"
	// ErrorTypeMismatch marks a value whose YAML shape does not match.
	ErrorTypeMismatch = "config.schema.type_mismatch"
	// ErrorInvalidDocument marks input that is not a single YAML document.
	ErrorInvalidDocument = "config.schema.invalid_document"
	// ErrorVersionUnsupported marks a schema version this binary does not know.
	ErrorVersionUnsupported = "config.schema.version_unsupported"
)

// SchemaError is a configuration schema rejection with a stable ID and a
// field path.
type SchemaError struct {
	// ID is the stable error identifier.
	ID string
	// Path is the dotted/indexed field path.
	Path string
	// Message is the human-readable explanation.
	Message string
}

func (e *SchemaError) Error() string {
	if e.Path == "" {
		return e.ID + ": " + e.Message
	}
	return e.ID + " at " + e.Path + ": " + e.Message
}

// checkStrict rejects unknown YAML keys before decoding. Go's decoder ignores
// unknown keys by default, which would silently drop a misspelled security
// setting; a typo must fail instead.
func checkStrict(data []byte, typ reflect.Type) error {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return &SchemaError{ID: ErrorInvalidDocument, Message: err.Error()}
	}
	if len(root.Content) == 0 {
		return &SchemaError{ID: ErrorInvalidDocument, Message: "empty document"}
	}
	return walk(typ, root.Content[0], "")
}

func walk(typ reflect.Type, node *yaml.Node, path string) error {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	switch typ.Kind() {
	case reflect.Struct:
		return walkStruct(typ, node, path)
	case reflect.Slice, reflect.Array:
		return walkSlice(typ.Elem(), node, path)
	default:
		return nil
	}
}

func walkStruct(typ reflect.Type, node *yaml.Node, path string) error {
	if node.Kind != yaml.MappingNode {
		return &SchemaError{ID: ErrorTypeMismatch, Path: path, Message: "expected an object"}
	}
	fields := yamlFields(typ)
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i].Value
		value := node.Content[i+1]
		field, ok := fields[key]
		if !ok {
			return &SchemaError{
				ID:      ErrorUnknownField,
				Path:    joinPath(path, key),
				Message: fmt.Sprintf("unknown field %q", key),
			}
		}
		if err := walk(field, value, joinPath(path, key)); err != nil {
			return err
		}
	}
	return nil
}

func walkSlice(elem reflect.Type, node *yaml.Node, path string) error {
	if node.Kind != yaml.SequenceNode {
		return &SchemaError{ID: ErrorTypeMismatch, Path: path, Message: "expected an array"}
	}
	for i, item := range node.Content {
		if err := walk(elem, item, fmt.Sprintf("%s[%d]", path, i)); err != nil {
			return err
		}
	}
	return nil
}

func yamlFields(typ reflect.Type) map[string]reflect.Type {
	out := make(map[string]reflect.Type, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.PkgPath != "" {
			continue
		}
		tag := field.Tag.Get("yaml")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name == "" {
			continue
		}
		out[name] = field.Type
	}
	return out
}

func joinPath(base, key string) string {
	if base == "" {
		return key
	}
	return base + "." + key
}
