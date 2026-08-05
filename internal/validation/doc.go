// Package validation implements shared strict-parsing and input-validation
// helpers (bounded string/size checks, allow-listed character sets,
// redirect URI matching, scope syntax, and similar low-level checks used
// across role packages).
//
// It holds only generic, policy-free validation primitives. FAPI-specific
// or role-specific validation rules (e.g. what makes an authorization
// request valid for a given server's policy) stay in the package that
// owns that policy.
package validation
