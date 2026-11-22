package federation

import (
	"crypto"
	"fmt"
	"reflect"
	"slices"
	"testing"
)

// TestConstructorConfigClonesCopyEverySlice walks, by reflection, each
// configuration a constructor here copies, so a field added later can't
// be left out of its clone: with every slice and map reachable from it
// filled, clone must return an equal value that shares none of them.
// Any other reference the constructor would keep, a pointer or an
// interface, fails the test until it is copied too, or listed here as a
// collaborator. A nil slice or map stays nil.
func TestConstructorConfigClonesCopyEverySlice(t *testing.T) {
	t.Run("AutomaticRegistrationConfig", func(t *testing.T) {
		checkCloneCopiesEverySlice(t, AutomaticRegistrationConfig.clone)
	})
	t.Run("Config", func(t *testing.T) { checkCloneCopiesEverySlice(t, Config.clone) })
	t.Run("SelfIssueConfig", func(t *testing.T) { checkCloneCopiesEverySlice(t, SelfIssueConfig.clone) })
	t.Run("SelfIssueDependencies", func(t *testing.T) {
		checkCloneCopiesEverySlice(t, SelfIssueDependencies.clone, reflect.TypeFor[crypto.Signer](), reflect.TypeFor[Clock]())
	})
}

// checkCloneCopiesEverySlice fails t unless clone copies every slice and
// map reachable from a T, keeping nil ones nil, and every pointer or
// interface it keeps has a type collaborators lists.
func checkCloneCopiesEverySlice[T any](t *testing.T, clone func(T) T, collaborators ...reflect.Type) {
	t.Helper()
	var filled T
	fillReferences(reflect.ValueOf(&filled).Elem())
	copied := clone(filled)
	if !reflect.DeepEqual(copied, filled) {
		t.Fatalf("clone() = %+v, want a value equal to %+v", copied, filled)
	}
	name := reflect.TypeFor[T]().Name()
	for _, path := range sharedReferences(name, reflect.ValueOf(filled), reflect.ValueOf(copied), collaborators) {
		t.Errorf("clone() shares %s with the %s it copies", path, name)
	}
	var zero T
	if got := clone(zero); !reflect.DeepEqual(got, zero) {
		t.Errorf("clone() of the zero %s = %+v, want it unchanged, its nil slices still nil", name, got)
	}
}

// fillReferences gives every slice and map reachable from v through
// exported fields one element of its own, recursively, so a copy that
// misses one still shares it.
func fillReferences(v reflect.Value) {
	switch v.Kind() {
	case reflect.Struct:
		for i := range v.NumField() {
			if v.Type().Field(i).IsExported() {
				fillReferences(v.Field(i))
			}
		}
	case reflect.Array:
		for i := range v.Len() {
			fillReferences(v.Index(i))
		}
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), 1, 1))
		fillReferences(v.Index(0))
	case reflect.Map:
		value := reflect.New(v.Type().Elem()).Elem()
		fillReferences(value)
		v.Set(reflect.MakeMapWithSize(v.Type(), 1))
		v.SetMapIndex(reflect.New(v.Type().Key()).Elem(), value)
	}
}

// sharedReferences returns the path of every slice or map reachable from
// orig through exported fields that copied shares with it, and of every
// pointer, interface or channel whose type kept doesn't list.
func sharedReferences(path string, orig, copied reflect.Value, kept []reflect.Type) []string {
	switch orig.Kind() {
	case reflect.Struct:
		return sharedFieldReferences(path, orig, copied, kept)
	case reflect.Array, reflect.Slice:
		return sharedElementReferences(path, orig, copied, kept)
	case reflect.Map:
		return sharedMapReferences(path, orig, copied, kept)
	case reflect.Pointer, reflect.Interface, reflect.Chan, reflect.UnsafePointer:
		if !slices.Contains(kept, orig.Type()) {
			return []string{path + " (" + orig.Type().String() + ")"}
		}
	}
	return nil
}

func sharedFieldReferences(path string, orig, copied reflect.Value, kept []reflect.Type) []string {
	var shared []string
	for i := range orig.NumField() {
		if field := orig.Type().Field(i); field.IsExported() {
			shared = append(shared, sharedReferences(path+"."+field.Name, orig.Field(i), copied.Field(i), kept)...)
		}
	}
	return shared
}

func sharedElementReferences(path string, orig, copied reflect.Value, kept []reflect.Type) []string {
	var shared []string
	if orig.Kind() == reflect.Slice && orig.Len() > 0 && orig.Pointer() == copied.Pointer() {
		shared = append(shared, path)
	}
	for i := range min(orig.Len(), copied.Len()) {
		shared = append(shared, sharedReferences(fmt.Sprintf("%s[%d]", path, i), orig.Index(i), copied.Index(i), kept)...)
	}
	return shared
}

func sharedMapReferences(path string, orig, copied reflect.Value, kept []reflect.Type) []string {
	var shared []string
	if orig.Len() > 0 && orig.Pointer() == copied.Pointer() {
		shared = append(shared, path)
	}
	for entry := orig.MapRange(); entry.Next(); {
		if value := copied.MapIndex(entry.Key()); value.IsValid() {
			shared = append(shared, sharedReferences(fmt.Sprintf("%s[%q]", path, entry.Key()), entry.Value(), value, kept)...)
		}
	}
	return shared
}
