// arena/spatial — 3D spatial-reasoning CAPTCHA (Arkose/FunCaptcha family): a grid of isometric cubes at random
// orientations; the client selects every cube whose TOP face is the target colour. Procedural, owned, zero-license.

package arena

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
	"sort"
)

var cubeColors = []struct {
	name string
	c    color.RGBA
}{
	{"red", color.RGBA{220, 50, 50, 255}},
	{"green", color.RGBA{50, 170, 70, 255}},
	{"blue", color.RGBA{60, 90, 220, 255}},
	{"yellow", color.RGBA{225, 195, 40, 255}},
	{"orange", color.RGBA{235, 140, 40, 255}},
	{"purple", color.RGBA{150, 70, 200, 255}},
}

func shade(c color.RGBA, f float64) color.RGBA {
	return color.RGBA{uint8(float64(c.R) * f), uint8(float64(c.G) * f), uint8(float64(c.B) * f), 255}
}

// fillQuad scanline-fills a convex quad (4 vertices, in order) on the tile.
func fillQuad(img *image.RGBA, pts [4][2]int, c color.RGBA) {
	minY, maxY := pts[0][1], pts[0][1]
	for _, p := range pts {
		if p[1] < minY {
			minY = p[1]
		}
		if p[1] > maxY {
			maxY = p[1]
		}
	}
	b := img.Bounds()
	for y := minY; y <= maxY; y++ {
		var xs []int
		for i := 0; i < 4; i++ {
			a, d := pts[i], pts[(i+1)%4]
			if (a[1] <= y && d[1] > y) || (d[1] <= y && a[1] > y) {
				xs = append(xs, a[0]+(d[0]-a[0])*(y-a[1])/(d[1]-a[1]))
			}
		}
		if len(xs) >= 2 {
			sort.Ints(xs)
			for x := xs[0]; x <= xs[len(xs)-1]; x++ {
				if x >= b.Min.X && x < b.Max.X && y >= b.Min.Y && y < b.Max.Y {
					img.Set(x, y, c)
				}
			}
		}
	}
}

// renderCube draws an isometric cube (top diamond + left + right faces, shaded for depth) on a 64×64 tile, with
// per-level speckle noise. The TOP face carries topColor; the sides are distractor colours. Returns a PNG data URI.
func renderCube(topColor, leftColor, rightColor color.RGBA, lv Level) string {
	const sz = 64
	img := image.NewRGBA(image.Rect(0, 0, sz, sz))
	for i := 0; i < len(img.Pix); i += 4 {
		img.Pix[i], img.Pix[i+1], img.Pix[i+2], img.Pix[i+3] = 250, 250, 250, 255
	}
	cx, cy, w, h := 32, 36, 18, 10
	top := [4][2]int{{cx, cy - 2*h}, {cx + w, cy - h}, {cx, cy}, {cx - w, cy - h}}
	right := [4][2]int{{cx + w, cy - h}, {cx, cy}, {cx, cy + 2*h}, {cx + w, cy + h}}
	left := [4][2]int{{cx - w, cy - h}, {cx, cy}, {cx, cy + 2*h}, {cx - w, cy + h}}
	fillQuad(img, left, shade(leftColor, 0.62))
	fillQuad(img, right, shade(rightColor, 0.82))
	fillQuad(img, top, topColor)
	// edge outlines for a crisp cube
	edge := color.RGBA{40, 40, 40, 255}
	for _, q := range [][4][2]int{top, left, right} {
		for i := 0; i < 4; i++ {
			drawLine(img, q[i][0], q[i][1], q[(i+1)%4][0], q[(i+1)%4][1], edge)
		}
	}
	var noise int
	switch lv {
	case LevelEasy:
		noise = 20
	case LevelHard:
		noise = 120
	default:
		noise = 60
	}
	for i := 0; i < noise; i++ {
		img.Set(int(randInt(sz)), int(randInt(sz)), noiseGrey())
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
}

// SpatialTile is one cube image in the grid.
type SpatialTile struct {
	Image string `json:"image"`
}

// Spatial is the public challenge — the answer (matching tile indices) is NEVER included.
type Spatial struct {
	ID     string        `json:"id"`
	Kind   string        `json:"kind"`
	Level  string        `json:"level"`
	Prompt string        `json:"prompt"`
	Tiles  []SpatialTile `json:"tiles"`
}

func spatialGridN(lv Level) int {
	if lv == LevelEasy {
		return 6
	}
	return 9
}

// MintSpatial builds a grid of cubes at random orientations + the answer (sorted, comma-joined matching indices).
func MintSpatial(lv Level) (Spatial, string) {
	n := spatialGridN(lv)
	nc := int64(len(cubeColors))
	target := int(randInt(nc))
	tiles := make([]SpatialTile, n)
	var answer []int
	for i := 0; i < n; i++ {
		topIdx := int(randInt(nc))
		li := (topIdx + 1 + int(randInt(2))) % len(cubeColors)
		ri := (topIdx + 3 + int(randInt(2))) % len(cubeColors)
		tiles[i] = SpatialTile{Image: renderCube(cubeColors[topIdx].c, cubeColors[li].c, cubeColors[ri].c, lv)}
		if topIdx == target {
			answer = append(answer, i)
		}
	}
	if len(answer) == 0 { // guarantee at least one match so the task is solvable
		i := int(randInt(int64(n)))
		li := (target + 1) % len(cubeColors)
		ri := (target + 3) % len(cubeColors)
		tiles[i] = SpatialTile{Image: renderCube(cubeColors[target].c, cubeColors[li].c, cubeColors[ri].c, lv)}
		answer = []int{i}
	}
	sort.Ints(answer)
	prompt := "Select every cube with the " + cubeColors[target].name + " face on top."
	return Spatial{ID: randHex(16), Kind: "spatial", Level: string(lv), Prompt: prompt, Tiles: tiles}, joinInts(answer)
}

// CheckSpatial reports whether the submitted tile-index set matches the expected (order-independent, de-duped).
func CheckSpatial(expected string, selected []int) bool {
	return expected != "" && normInts(selected) == expected
}

func normInts(xs []int) string {
	seen := map[int]bool{}
	var uniq []int
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			uniq = append(uniq, x)
		}
	}
	return joinInts(uniq) // joinInts sorts
}
