// evaders/arena-solver/cv_test — the CV classifier reads a filled shape from pixels (rotation-invariant).
// Draws known shapes to PNG data URIs and asserts classifyTilePNG names them — the raster evasion, proven.

package main

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
	"math"
	"testing"
)

// drawShape renders a filled shape (rotated by theta) to a data:image/png URI, mirroring the gate's tiles.
func drawShape(shape string, theta float64) string {
	const sz = 60
	cx, cy := 29.5, 29.5
	img := image.NewRGBA(image.Rect(0, 0, sz, sz))
	for y := 0; y < sz; y++ {
		for x := 0; x < sz; x++ {
			img.Set(x, y, color.White)
		}
	}
	fill := color.RGBA{85, 85, 85, 255}
	sin, cos := math.Sin(-theta), math.Cos(-theta)
	tri := [][2]float64{{0, -22}, {20, 18}, {-20, 18}}
	star := make([][2]float64, 0, 10)
	for i := 0; i < 10; i++ {
		r := 22.0
		if i%2 == 1 {
			r = 9
		}
		a := -math.Pi/2 + float64(i)*math.Pi/5
		star = append(star, [2]float64{r * math.Cos(a), r * math.Sin(a)})
	}
	inPoly := func(px, py float64, poly [][2]float64) bool {
		in := false
		for i, j := 0, len(poly)-1; i < len(poly); j, i = i, i+1 {
			if (poly[i][1] > py) != (poly[j][1] > py) &&
				px < (poly[j][0]-poly[i][0])*(py-poly[i][1])/(poly[j][1]-poly[i][1])+poly[i][0] {
				in = !in
			}
		}
		return in
	}
	for y := 0; y < sz; y++ {
		for x := 0; x < sz; x++ {
			dx, dy := float64(x)-cx, float64(y)-cy
			rx, ry := dx*cos-dy*sin, dx*sin+dy*cos
			var inside bool
			switch shape {
			case "circle":
				inside = rx*rx+ry*ry <= 22*22
			case "square":
				inside = math.Abs(rx) <= 18 && math.Abs(ry) <= 18
			case "triangle":
				inside = inPoly(rx, ry, tri)
			case "star":
				inside = inPoly(rx, ry, star)
			}
			if inside {
				img.Set(x, y, fill)
			}
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
}

func TestClassifyTilePNG(t *testing.T) {
	for _, shape := range []string{"circle", "square", "triangle", "star"} {
		for _, theta := range []float64{0, 0.6, 1.4, 2.5} { // rotation-invariance
			if got := classifyTilePNG(drawShape(shape, theta)); got != shape {
				t.Fatalf("classifyTilePNG(%s @ %.1f) = %q", shape, theta, got)
			}
		}
	}
}
