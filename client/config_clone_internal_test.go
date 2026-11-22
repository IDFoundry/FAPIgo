package client

import (
	"fmt"
	"reflect"
	"testing"
)

// TestConfigCloneCopiesEverySlice walks Config by reflection, so a field
// added later can't be left out of clone: with every slice and map
// reachable from it filled, clone must return an equal Config that
// shares none of them. Config holds no pointer or interface; one added
// fails the test until clone copies what it refers to. A nil slice stays
// nil.
func TestConfigCloneCopiesEverySlice(t *testing.T) {
	var cfg Config
	fillReferences(reflect.ValueOf(&cfg).Elem())
	copied := cfg.clone()
	if !reflect.DeepEqual(copied, cfg) {
		t.Fatalf("clone() = %+v, want a Config equal to %+v", copied, cfg)
	}
	for _, path := range sharedReferences("Config", reflect.ValueOf(cfg), reflect.ValueOf(copied)) {
		t.Errorf("clone() shares %s with the Config it copies", path)
	}
	if zero := (Config{}).clone(); !reflect.DeepEqual(zero, Config{}) {
		t.Errorf("(Config{}).clone() = %+v, want the zero Config, its nil slices still nil", zero)
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
// pointer, interface or channel.
func sharedReferences(path string, orig, copied reflect.Value) []string {
	switch orig.Kind() {
	case reflect.Struct:
		return sharedFieldReferences(path, orig, copied)
	case reflect.Array, reflect.Slice:
		return sharedElementReferences(path, orig, copied)
	case reflect.Map:
		return sharedMapReferences(path, orig, copied)
	case reflect.Pointer, reflect.Interface, reflect.Chan, reflect.UnsafePointer:
		return []string{path + " (" + orig.Type().String() + ")"}
	}
	return nil
}

func sharedFieldReferences(path string, orig, copied reflect.Value) []string {
	var shared []string
	for i := range orig.NumField() {
		if field := orig.Type().Field(i); field.IsExported() {
			shared = append(shared, sharedReferences(path+"."+field.Name, orig.Field(i), copied.Field(i))...)
		}
	}
	return shared
}

func sharedElementReferences(path string, orig, copied reflect.Value) []string {
	var shared []string
	if orig.Kind() == reflect.Slice && orig.Len() > 0 && orig.Pointer() == copied.Pointer() {
		shared = append(shared, path)
	}
	for i := range min(orig.Len(), copied.Len()) {
		shared = append(shared, sharedReferences(fmt.Sprintf("%s[%d]", path, i), orig.Index(i), copied.Index(i))...)
	}
	return shared
}

func sharedMapReferences(path string, orig, copied reflect.Value) []string {
	var shared []string
	if orig.Len() > 0 && orig.Pointer() == copied.Pointer() {
		shared = append(shared, path)
	}
	for entry := orig.MapRange(); entry.Next(); {
		if value := copied.MapIndex(entry.Key()); value.IsValid() {
			shared = append(shared, sharedReferences(fmt.Sprintf("%s[%v]", path, entry.Key()), entry.Value(), value)...)
		}
	}
	return shared
}
