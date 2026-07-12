// arena/count — counting gate: "how many <colour> circles?" (a prevalent wild captcha style). REUSED tell family
// (solve-speed, not a new one): a bot CV-counts the shapes instantly, while a human must visually scan every shape
// to count the target colour — a correct answer faster than a human can scan the whole scene is automation.

package arena

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"strconv"
)

// Count is the PUBLIC challenge — the rendered scene + the target colour name are sent; the count is secret (the
// client must actually count).
type Count struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Level  string `json:"level"`
	Image  string `json:"image"`
	Prompt string `json:"prompt"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
}

// countPerShapeMs: a human needs to look at each shape to count the target colour; a whole solve (age) under
// totalShapes * this is superhuman (an instant CV count). The load-bearing, FP-safe prong.
const countPerShapeMs = 220

var countColors = []struct {
	name string
	c    color.RGBA
}{
	{"red", color.RGBA{200, 50, 50, 255}},
	{"green", color.RGBA{50, 160, 70, 255}},
	{"blue", color.RGBA{55, 95, 210, 255}},
	{"orange", color.RGBA{225, 145, 35, 255}},
	{"purple", color.RGBA{150, 65, 190, 255}},
}

func countParams(lv Level) (nShapes int) {
	switch lv {
	case LevelEasy:
		return 6
	case LevelHard:
		return 12
	default:
		return 9
	}
}

// MintCount renders M coloured disks + returns the answer (the count of the target colour + the total shape count).
func MintCount(lv Level) (Count, string) {
	const w, h = 300, 180
	m := countParams(lv)
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{246, 246, 249, 255})
		}
	}
	type disk struct {
		x, y, r, col int
	}
	var disks []disk
	for len(disks) < m {
		x := 20 + int(randInt(w-40))
		y := 20 + int(randInt(h-40))
		r := 13 + int(randInt(5))
		ok := true
		for _, d := range disks {
			if (x-d.x)*(x-d.x)+(y-d.y)*(y-d.y) < (r+d.r+8)*(r+d.r+8) {
				ok = false
				break
			}
		}
		if ok {
			disks = append(disks, disk{x, y, r, int(randInt(int64(len(countColors))))})
		}
	}
	// pick a target colour that appears at least twice (a non-trivial count)
	counts := make([]int, len(countColors))
	for _, d := range disks {
		counts[d.col]++
	}
	target := 0
	for tries := 0; tries < 40; tries++ {
		t := int(randInt(int64(len(countColors))))
		if counts[t] >= 2 {
			target = t
			break
		}
		target = t
	}
	for _, d := range disks {
		c := countColors[d.col].c
		for y := d.y - d.r; y <= d.y+d.r; y++ {
			for x := d.x - d.r; x <= d.x+d.r; x++ {
				if x >= 0 && x < w && y >= 0 && y < h && (x-d.x)*(x-d.x)+(y-d.y)*(y-d.y) <= d.r*d.r {
					img.Set(x, y, c)
				}
			}
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	cc := Count{
		ID: randHex(16), Kind: "count", Level: string(lv),
		Image:  "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()),
		Prompt: "How many " + countColors[target].name + " circles are there?", Width: w, Height: h,
	}
	ans, _ := json.Marshal(map[string]int{"answer": counts[target], "total": m})
	return cc, string(ans)
}

// CheckCount reports whether the guessed count matches, and the total shape count (for the superhuman-scan floor).
func CheckCount(expected string, guess int) (pass bool, total int) {
	var a struct {
		Answer int `json:"answer"`
		Total  int `json:"total"`
	}
	if err := json.Unmarshal([]byte(expected), &a); err != nil {
		return false, 0
	}
	return guess == a.Answer, a.Total
}

// parseCountGuess parses the client's typed number (tolerant of surrounding whitespace); -1 if not a number.
func parseCountGuess(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return -1
	}
	return n
}
