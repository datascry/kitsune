// arena/slide — sliding-tile puzzle gate: slide the 8-puzzle (3x3) into order (KeyCAPTCHA / 15-puzzle family).
// NOVEL server-observed tell: an OPTIMAL plan — a solver computes the minimum move sequence (server-verified via
// BFS) while a human wanders (more moves); plus superhuman speed (solving faster than a human can slide the tiles).

package arena

import "encoding/json"

// Slide is the PUBLIC challenge — the scrambled board is shown; the goal (1..8 with the blank last) is implicit.
type Slide struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Level  string `json:"level"`
	Board  []int  `json:"board"` // 9 ints row-major, 0 = blank
	Size   int    `json:"size"`
	Prompt string `json:"prompt"`
}

// slideOptimalFloor: matching the EXACT minimum move count on a scramble whose optimal is at least this many moves
// is superhuman planning (a human wanders / backtracks). Below it, an easy scramble could be solved optimally by
// chance, so the optimal prong is not trusted (the speed prong still applies).
const slideOptimalFloor = 8

// slidePerMoveMs: the minimum a human needs per deliberate tile slide; a whole solve (age) under nMoves * this is
// superhuman (an instant computed submission).
const slidePerMoveMs = 350

var slideGoal = []int{1, 2, 3, 4, 5, 6, 7, 8, 0}

func slideParams(lv Level) (scramble int) {
	switch lv {
	case LevelEasy:
		return 12
	case LevelHard:
		return 40
	default:
		return 22
	}
}

func slideNeighbors(p int) []int {
	r, c := p/3, p%3
	var out []int
	if r > 0 {
		out = append(out, p-3)
	}
	if r < 2 {
		out = append(out, p+3)
	}
	if c > 0 {
		out = append(out, p-1)
	}
	if c < 2 {
		out = append(out, p+1)
	}
	return out
}

func blankOf(b []int) int {
	for i, v := range b {
		if v == 0 {
			return i
		}
	}
	return -1
}

func slideKey(b []int) string {
	s := make([]byte, len(b))
	for i, v := range b {
		s[i] = byte('0' + v)
	}
	return string(s)
}

// MintSlide scrambles the board by K random non-undoing moves (so it is always solvable); returns the answer (the
// scrambled board + its BFS-optimal solution length).
func MintSlide(lv Level) (Slide, string) {
	k := slideParams(lv)
	b := append([]int{}, slideGoal...)
	prev := -1
	for i := 0; i < k; i++ {
		bl := blankOf(b)
		var choices []int
		for _, n := range slideNeighbors(bl) {
			if n != prev {
				choices = append(choices, n)
			}
		}
		pick := choices[randInt(int64(len(choices)))]
		b[bl], b[pick] = b[pick], b[bl]
		prev = bl
	}
	s := Slide{
		ID: randHex(16), Kind: "slide", Level: string(lv), Board: b, Size: 3,
		Prompt: "Slide the tiles into order (1-8, blank last). Click a tile next to the blank to slide it.",
	}
	ans, _ := json.Marshal(map[string]any{"board": b, "optimal": slideOptimal(b)})
	return s, string(ans)
}

// slideOptimal returns the BFS shortest solution length from board to the goal (tractable for the 8-puzzle).
func slideOptimal(start []int) int {
	goalKey := slideKey(slideGoal)
	if slideKey(start) == goalKey {
		return 0
	}
	type node struct {
		b []int
		d int
	}
	visited := map[string]bool{slideKey(start): true}
	queue := []node{{append([]int{}, start...), 0}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, n := range slideNeighbors(blankOf(cur.b)) {
			nb := append([]int{}, cur.b...)
			bl := blankOf(nb)
			nb[bl], nb[n] = nb[n], nb[bl]
			k := slideKey(nb)
			if visited[k] {
				continue
			}
			if k == goalKey {
				return cur.d + 1
			}
			visited[k] = true
			queue = append(queue, node{nb, cur.d + 1})
		}
	}
	return -1
}

// CheckSlide replays the moves (each a clicked tile index that must be adjacent to the blank) from the scrambled
// board; pass if the board reaches the goal. Returns the move count and the optimal length (the plan-length tell).
func CheckSlide(expected string, moves []int) (pass bool, nMoves, optimal int) {
	var a struct {
		Board   []int `json:"board"`
		Optimal int   `json:"optimal"`
	}
	if err := json.Unmarshal([]byte(expected), &a); err != nil || len(a.Board) != 9 {
		return false, 0, 0
	}
	b := append([]int{}, a.Board...)
	for _, m := range moves {
		if m < 0 || m > 8 {
			return false, len(moves), a.Optimal
		}
		bl := blankOf(b)
		adj := false
		for _, n := range slideNeighbors(bl) {
			if n == m {
				adj = true
				break
			}
		}
		if !adj {
			return false, len(moves), a.Optimal
		}
		b[bl], b[m] = b[m], b[bl]
	}
	return slideKey(b) == slideKey(slideGoal), len(moves), a.Optimal
}
