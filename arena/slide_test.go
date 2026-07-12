// arena/slide_test — tests for the sliding-tile gate: mint solvability, BFS-optimal length, and move replay.
// Confirms the optimal plan solves + reports optimal==nMoves, a wandering plan solves with more moves, illegal fails.

package arena

import (
	"encoding/json"
	"testing"
)

// bfsSolution returns an optimal move sequence (clicked tile indices) from board to goal — the "bot" solver.
func bfsSolution(start []int) []int {
	if slideKey(start) == slideKey(slideGoal) {
		return nil
	}
	type node struct {
		b    []int
		path []int
	}
	visited := map[string]bool{slideKey(start): true}
	queue := []node{{append([]int{}, start...), nil}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		bl := blankOf(cur.b)
		for _, n := range slideNeighbors(bl) {
			nb := append([]int{}, cur.b...)
			nb[bl], nb[n] = nb[n], nb[bl]
			k := slideKey(nb)
			if visited[k] {
				continue
			}
			path := append(append([]int{}, cur.path...), n) // the move is the clicked tile index n
			if k == slideKey(slideGoal) {
				return path
			}
			visited[k] = true
			queue = append(queue, node{nb, path})
		}
	}
	return nil
}

func TestMintSlide(t *testing.T) {
	for _, lv := range []Level{LevelEasy, LevelMedium, LevelHard} {
		s, ans := MintSlide(lv)
		if s.Kind != "slide" || s.ID == "" || len(s.Board) != 9 || s.Size != 3 {
			t.Fatalf("%s: bad shape %+v", lv, s.Kind)
		}
		var a struct {
			Board   []int
			Optimal int
		}
		if err := json.Unmarshal([]byte(ans), &a); err != nil || len(a.Board) != 9 {
			t.Fatalf("%s: answer not a board", lv)
		}
		// the scramble is solvable and its optimal length matches an independent BFS solve
		sol := bfsSolution(a.Board)
		if len(sol) != a.Optimal {
			t.Errorf("%s: optimal %d != bfs %d", lv, a.Optimal, len(sol))
		}
	}
}

func TestCheckSlide(t *testing.T) {
	_, ans := MintSlide(LevelMedium)
	var a struct {
		Board   []int
		Optimal int
	}
	_ = json.Unmarshal([]byte(ans), &a)

	// the optimal (bot) plan solves, with nMoves == optimal
	opt := bfsSolution(a.Board)
	if pass, n, o := CheckSlide(ans, opt); !pass || n != o {
		t.Errorf("optimal plan: pass=%v n=%v optimal=%v (want pass, n==optimal)", pass, n, o)
	}
	// a wandering plan (optimal + a there-and-back detour) solves with MORE moves than optimal
	wander := append([]int{}, opt...)
	// prepend a legal round-trip from the scramble: slide a neighbour then slide it back
	bl := blankOf(a.Board)
	nb := slideNeighbors(bl)[0]
	wander = append([]int{nb, bl}, wander...)
	if pass, n, o := CheckSlide(ans, wander); !pass || n <= o {
		t.Errorf("wandering plan: pass=%v n=%v optimal=%v (want pass, n>optimal)", pass, n, o)
	}
	// an illegal move (not adjacent to the blank) fails; empty target fails
	if pass, _, _ := CheckSlide(ans, []int{blankOf(a.Board)}); pass {
		t.Error("clicking the blank itself must fail")
	}
	if pass, _, _ := CheckSlide("", opt); pass {
		t.Error("empty target must fail")
	}
}
