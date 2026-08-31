package main

import (
	"github.com/idfoundry/fapigo/server"
)

// formValue returns the first value of name in form, or "" if absent.
func formValue(form server.FormRequest, name string) string {
	for _, p := range form.Parameters {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}
