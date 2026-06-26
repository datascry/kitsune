// evaders/arena-solver/cv — beat the HARDENED image-select gate with real computer vision (no markup).
// Decodes each raster tile and classifies the shape from pixels — the red side keeping pace with the gate.

// When the gate rasterized its tiles, the markup-parse cheat died — so the evader has to actually SEE the
// shape. classifyTilePNG decodes the PNG, isolates the fill pixels (the noise speckle is lighter, so a
// luminance threshold drops it), and reads a rotation-invariant radial signature about the centroid: a
// circle's boundary radius is near-constant; a polygon's has one peak per corner (triangle 3, square 4,
// star 5). This is genuine CV, not parsing — and it still gets the solver convicted by the detector, which
// is the whole point: the gate arms race is unwinnable; coherence is the durable layer.

package main

import (
	"bytes"
	"encoding/base64"
	"image/png"
	"math"
	"strings"
)

// classifyTilePNG decodes a data:image/png tile and names its shape (circle/square/triangle/star) from pixels.
func classifyTilePNG(dataURI string) string {
	i := strings.Index(dataURI, ",")
	if i < 0 {
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(dataURI[i+1:])
	if err != nil {
		return ""
	}
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		return ""
	}
	b := img.Bounds()
	var sx, sy, n float64
	type px struct{ x, y int }
	var fill []px
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			r, g, bl, _ := img.At(x, y).RGBA()
			lum := (r>>8 + g>>8 + bl>>8) / 3
			if lum < 120 { // fill (~85) is dark; the noise speckle (~150) and background (255) drop out
				sx += float64(x)
				sy += float64(y)
				n++
				fill = append(fill, px{x, y})
			}
		}
	}
	if n < 20 {
		return ""
	}
	cx, cy := sx/n, sy/n

	const bins = 72
	maxr := make([]float64, bins)
	for _, p := range fill {
		dx, dy := float64(p.x)-cx, float64(p.y)-cy
		r := math.Hypot(dx, dy)
		bi := int((math.Atan2(dy, dx)+math.Pi)/(2*math.Pi)*float64(bins)) % bins
		if bi < 0 {
			bi += bins
		}
		if r > maxr[bi] {
			maxr[bi] = r
		}
	}
	var sum float64
	for _, r := range maxr {
		sum += r
	}
	mean := sum / float64(bins)
	if mean == 0 {
		return ""
	}
	var ss float64
	for _, r := range maxr {
		ss += (r - mean) * (r - mean)
	}
	if math.Sqrt(ss/float64(bins))/mean < 0.07 { // near-constant radius ⇒ a circle
		return "circle"
	}
	// Count angular peaks (corners/points): a bin that locally exceeds its neighbours and the mean.
	peaks := 0
	for i := 0; i < bins; i++ {
		r := maxr[i]
		if r > mean*1.05 && r >= maxr[(i-1+bins)%bins] && r > maxr[(i+1)%bins] {
			peaks++
		}
	}
	switch {
	case peaks >= 5:
		return "star"
	case peaks == 4:
		return "square"
	case peaks <= 3:
		return "triangle"
	default:
		return "square"
	}
}
