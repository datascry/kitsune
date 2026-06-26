// arena/doodle — render Quick, Draw! doodle tiles for the image-select gate (Google Quick Draw, CC BY 4.0).
// A "select every <category>" grid of hand-drawn sketches — open polylines that need real CV, not a heuristic.

// The second public image source for the image-select family (the first is emoji — see emoji.go). Quick,
// Draw! doodles are crowd-sourced 20-second sketches: open, wobbly polylines with huge intra-class variance,
// so a radial-shape classifier cannot read them and even a template matcher struggles — it takes a real
// CV/VLM. A small, de-identified sample (stroke vectors only, see assets/quickdraw.ndjson +
// quickdraw.ATTRIBUTION.txt) is vendored under CC BY 4.0. Strokes are simplified to a 0-255 grid; we scale
// them onto the tile and stroke the polylines.

package arena

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"strings"
)

//go:embed assets/quickdraw.ndjson
var quickdrawNDJSON []byte

// qdDrawing is one doodle: G is the category group (animal/food/vehicle), D the strokes — each stroke is
// [xs, ys] (two equal-length coordinate lists on a 0-255 grid).
type qdDrawing struct {
	G string    `json:"g"`
	D [][][]int `json:"d"`
}

var (
	doodlesByGroup   = map[string][]qdDrawing{}
	doodleGroupOrder = []string{"animal", "food", "vehicle"}
	doodleNoun       = map[string]string{"animal": "animal", "food": "food item", "vehicle": "vehicle"}
)

func init() {
	for _, line := range strings.Split(string(quickdrawNDJSON), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var d qdDrawing
		if json.Unmarshal([]byte(line), &d) == nil && len(d.D) > 0 {
			doodlesByGroup[d.G] = append(doodlesByGroup[d.G], d)
		}
	}
}

func randDoodleGroup() string { return doodleGroupOrder[randInt(int64(len(doodleGroupOrder)))] }

func randDoodleFrom(group string) qdDrawing {
	ds := doodlesByGroup[group]
	return ds[randInt(int64(len(ds)))]
}

// rasterDoodle strokes a doodle's polylines onto a 64×64 white tile (noise per level), as a base64 PNG data
// URI — the answer is the sketch's CATEGORY, readable only by recognising the drawing.
func rasterDoodle(dr qdDrawing, noise int) string {
	const sz, pad = 64, 6
	img := image.NewRGBA(image.Rect(0, 0, sz, sz))
	draw.Draw(img, img.Bounds(), image.NewUniform(color.White), image.Point{}, draw.Src)
	ink := color.RGBA{40, 40, 40, 255}
	scale := float64(sz-2*pad) / 255.0
	at := func(v int) int { return pad + int(float64(v)*scale) }
	for _, stroke := range dr.D {
		if len(stroke) < 2 {
			continue
		}
		xs, ys := stroke[0], stroke[1]
		for i := 1; i < len(xs) && i < len(ys); i++ {
			drawLine(img, at(xs[i-1]), at(ys[i-1]), at(xs[i]), at(ys[i]), ink)
		}
	}
	for i := 0; i < noise; i++ {
		img.Set(int(randInt(sz)), int(randInt(sz)), noiseGrey())
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
}
