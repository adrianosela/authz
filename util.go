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

func getRealSizeOf(v interface{}) (int, error) {
	b := new(bytes.Buffer)
	if err := gob.NewEncoder(b).Encode(v); err != nil {
		return 0, err
	}
	return b.Len(), nil
}
