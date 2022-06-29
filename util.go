package authz

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"strings"
)

func buildStackString(stack []string) string {
	s := ""
	for _, r := range stack {
		s = fmt.Sprintf("%s --> %s", s, r)
	}
	return strings.TrimPrefix(s, " --> ")
}

func dedupSlice(slice []string) []string {
	set := map[string]struct{}{}
	for _, s := range slice {
		set[s] = struct{}{}
	}
	dedup := []string{}
	for k := range set {
		dedup = append(dedup, k)
	}
	return dedup
}

func sliceFromSet(set map[string]struct{}) []string {
	slice := []string{}
	for k := range set {
		slice = append(slice, k)
	}
	return slice
}

func joinSets(ss ...map[string]struct{}) map[string]struct{} {
	new := map[string]struct{}{}
	for _, set := range ss {
		for k, v := range set {
			new[k] = v
		}
	}
	return new
}

func copySet(original map[string]struct{}) map[string]struct{} {
	new := map[string]struct{}{}
	for k, v := range original {
		new[k] = v
	}
	return new
}

func getRealSizeOf(v interface{}) (int, error) {
	b := new(bytes.Buffer)
	if err := gob.NewEncoder(b).Encode(v); err != nil {
		return 0, err
	}
	return b.Len(), nil
}
