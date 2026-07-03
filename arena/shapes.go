// arena/shapes — procedurally-rendered geometric-shape tiles for the image-select gate (OWNED, zero-license).
// A "select every <shape>" grid of in-code shapes — a distinct visual domain from emoji glyphs and QuickDraw sketches.

package arena

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/draw"
	"image/png"
)

// shapeOrder is the stable shape-category list (deterministic iteration, enumerated by /arena/catalog); shapeNoun
// maps each to its prompt noun. A THIRD image-select source alongside emoji (glyphs) and doodle (sketches): the
// visual domain is procedural geometry, so a classifier tuned on one domain still faces a fresh one here.
var (
	shapeOrder = []string{"circle", "square", "triangle", "diamond"}
	shapeNoun  = map[string]string{"circle": "circle", "square": "square", "triangle": "triangle", "diamond": "diamond"}
)

// randShapeCategory returns a uniformly-random shape category from the stable order.
func randShapeCategory() string { return shapeOrder[randInt(int64(len(shapeOrder)))] }

// rasterShape renders one geometric shape centred on a 64×64 white tile (noise per level) as a base64 PNG data URI.
// OWNED + generated in-code (zero-license): the answer is the shape's CATEGORY, read only by recognising the form
// (not its markup). Per-tile centre/size/tone jitter so tiles of one shape are not pixel-identical.
func rasterShape(shape string, noise int) string {
	const sz = 64
	img := image.NewRGBA(image.Rect(0, 0, sz, sz))
	draw.Draw(img, img.Bounds(), image.NewUniform(color.White), image.Point{}, draw.Src)
	cx, cy := sz/2+int(randInt(9))-4, sz/2+int(randInt(9))-4 // slight off-centre jitter
	r := 20 + int(randInt(6))                               // radius 20..25
	tone := uint8(20 + randInt(60))
	col := color.RGBA{tone, tone, tone, 255}
	for y := 0; y < sz; y++ {
		for x := 0; x < sz; x++ {
			if shapeContains(shape, x-cx, y-cy, r) {
				img.Set(x, y, col)
			}
		}
	}
	for i := 0; i < noise; i++ {
		img.Set(int(randInt(sz)), int(randInt(sz)), noiseGrey())
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
}

// shapeContains reports whether the offset (dx,dy) from the shape centre falls inside the shape of radius r.
func shapeContains(shape string, dx, dy, r int) bool {
	switch shape {
	case "circle":
		return dx*dx+dy*dy <= r*r
	case "square":
		s := r - 3
		return dx >= -s && dx <= s && dy >= -s && dy <= s
	case "diamond":
		return abs(dx)+abs(dy) <= r
	case "triangle": // apex at dy=-r, base at dy=+r; half-width grows linearly apex→base
		if dy < -r || dy > r {
			return false
		}
		halfW := (dy + r) * r / (2 * r)
		return dx >= -halfW && dx <= halfW
	}
	return false
}
