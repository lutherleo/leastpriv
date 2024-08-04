package engine

// Tri is a three-valued truth value. Maybe arises when a condition depends on
// a context key whose value is unknown (for example a key CloudTrail does
// not record), so the engine can report "allowed if the unknown values
// satisfy the condition" instead of guessing.
type Tri uint8

// Truth values, ordered so that AND is min and OR is max.
const (
	No Tri = iota
	Maybe
	Yes
)

func (t Tri) String() string {
	switch t {
	case Yes:
		return "yes"
	case Maybe:
		return "maybe"
	default:
		return "no"
	}
}

func and(a, b Tri) Tri {
	if a < b {
		return a
	}
	return b
}

func or(a, b Tri) Tri {
	if a > b {
		return a
	}
	return b
}

func not(a Tri) Tri {
	switch a {
	case Yes:
		return No
	case No:
		return Yes
	default:
		return Maybe
	}
}

func triOf(b bool) Tri {
	if b {
		return Yes
	}
	return No
}
