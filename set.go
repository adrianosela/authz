package authz

type set map[string]struct{}

func newSet(ss ...string) set {
	return make(set).add(ss...)
}

func (s set) has(e string) bool {
	_, ok := s[e]
	return ok
}

func (s set) add(ss ...string) set {
	for _, e := range ss {
		s[e] = struct{}{}
	}
	return s
}

func (s set) join(ss set) set {
	for k := range ss {
		s[k] = struct{}{}
	}
	return s
}

func (s set) copy() set {
	return newSet().join(s)
}
