// arena/raster — render the text CAPTCHA to a DISTORTED RASTER PNG (not SVG), so the answer is not in markup.
// Closes the "vector captcha leaks its answer to a parser" shortcut: solving the raster gate now needs OCR.

// The first version rendered the code as SVG <text> elements — a browserless solver read the characters
// straight out of the markup (no OCR). A real text CAPTCHA is a raster image with distortion. This renders
// the code with an embedded TrueType font, applies a per-column sine warp, and adds noise — producing a PNG
// whose pixels (not markup) carry the answer. A simple parser can no longer read it; an attacker needs real
// OCR. (The deeper point still stands: even OCR-hardened CAPTCHAs fall to ML/solver-farms — coherence, not
// the challenge, is the durable signal. This just makes the arena FAITHFULLY hard instead of trivially easy.)

package arena

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"

	"golang.org/x/image/font"
	"golang.org/x/image/font/gofont/goregular"
	"golang.org/x/image/font/opentype"
	"golang.org/x/image/math/fixed"
)

var captchaFace font.Face

func init() {
	f, err := opentype.Parse(goregular.TTF)
	if err != nil {
		return
	}
	captchaFace, _ = opentype.NewFace(f, &opentype.FaceOptions{Size: 34, DPI: 72, Hinting: font.HintingFull})
}

// rasterText renders code as a distorted-text PNG (warped + noisy), returned as a base64 data URI. The
// plaintext answer exists only as pixels — there is no <text> element to parse.
func rasterText(code string) string {
	w, h := 30*len(code)+30, 64
	base := image.NewRGBA(image.Rect(0, 0, w, h))
	draw.Draw(base, base.Bounds(), image.NewUniform(color.White), image.Point{}, draw.Src)
	if captchaFace != nil {
		d := &font.Drawer{Dst: base, Src: image.NewUniform(color.RGBA{40, 40, 40, 255}), Face: captchaFace}
		x := 16
		for _, ch := range code {
			d.Dot = fixed.P(x, 46+int(randInt(11))-5) // per-character vertical jitter
			d.DrawString(string(ch))
			x += 27 + int(randInt(9)) - 4 // jittered advance
		}
	}
	// Per-column vertical sine warp — defeats naive segmentation/OCR and any markup reading.
	amp := 4.0 + float64(randInt(3))
	freq := 0.04 + float64(randInt(4))/100.0
	phase := float64(randInt(628)) / 100.0
	out := image.NewRGBA(base.Bounds())
	draw.Draw(out, out.Bounds(), image.NewUniform(color.White), image.Point{}, draw.Src)
	for x := 0; x < w; x++ {
		shift := int(amp * math.Sin(float64(x)*freq+phase))
		for y := 0; y < h; y++ {
			sy := y + shift
			if sy >= 0 && sy < h {
				out.Set(x, y, base.At(x, sy))
			}
		}
	}
	// Noise: a few strokes + speckle so background subtraction is harder.
	grey := color.RGBA{150, 150, 150, 255}
	for i := 0; i < 2; i++ {
		x0, y0, x1, y1 := int(randInt(int64(w))), int(randInt(int64(h))), int(randInt(int64(w))), int(randInt(int64(h)))
		drawLine(out, x0, y0, x1, y1, grey)
	}
	for i := 0; i < 70; i++ {
		out.Set(int(randInt(int64(w))), int(randInt(int64(h))), grey)
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, out)
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
}

// rasterShape renders one owned primitive shape as a rotated, noisy PNG tile — so an unlabelled tile must be
// CLASSIFIED from pixels (computer vision), not read from SVG markup. (Honest limit: four primitives are still
// CV-tractable; a production image-select uses a photo/ML set we will not reproduce. This kills the trivial
// markup-parse cheat, which is the shortcut that mattered.)
func rasterShape(shape string) string {
	const sz = 60
	cx, cy := 29.5, 29.5
	theta := float64(randInt(360)) * math.Pi / 180.0
	img := image.NewRGBA(image.Rect(0, 0, sz, sz))
	draw.Draw(img, img.Bounds(), image.NewUniform(color.White), image.Point{}, draw.Src)
	fill := color.RGBA{85, 85, 85, 255}
	poly := shapePolygon(shape)
	sin, cos := math.Sin(-theta), math.Cos(-theta)
	for y := 0; y < sz; y++ {
		for x := 0; x < sz; x++ {
			dx, dy := float64(x)-cx, float64(y)-cy
			rx, ry := dx*cos-dy*sin, dx*sin+dy*cos // un-rotate the sample point
			var inside bool
			switch shape {
			case "circle":
				inside = rx*rx+ry*ry <= 22*22
			case "square":
				inside = math.Abs(rx) <= 18 && math.Abs(ry) <= 18
			default:
				inside = pointInPolygon(rx, ry, poly)
			}
			if inside {
				img.Set(x, y, fill)
			}
		}
	}
	grey := color.RGBA{150, 150, 150, 255}
	for i := 0; i < 45; i++ {
		img.Set(int(randInt(sz)), int(randInt(sz)), grey)
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
}

type pt struct{ x, y float64 }

// shapePolygon returns the vertices (centred at the origin) of triangle/star; circle/square are tested directly.
func shapePolygon(shape string) []pt {
	switch shape {
	case "triangle":
		return []pt{{0, -22}, {20, 18}, {-20, 18}}
	case "star":
		var p []pt
		for i := 0; i < 10; i++ {
			r := 22.0
			if i%2 == 1 {
				r = 9.0
			}
			a := -math.Pi/2 + float64(i)*math.Pi/5
			p = append(p, pt{r * math.Cos(a), r * math.Sin(a)})
		}
		return p
	}
	return nil
}

// pointInPolygon is a standard ray-cast (even-odd) test.
func pointInPolygon(x, y float64, poly []pt) bool {
	in := false
	n := len(poly)
	for i, j := 0, n-1; i < n; j, i = i, i+1 {
		if (poly[i].y > y) != (poly[j].y > y) &&
			x < (poly[j].x-poly[i].x)*(y-poly[i].y)/(poly[j].y-poly[i].y)+poly[i].x {
			in = !in
		}
	}
	return in
}

// drawLine plots a simple Bresenham line (noise stroke).
func drawLine(img *image.RGBA, x0, y0, x1, y1 int, c color.Color) {
	dx, dy := abs(x1-x0), -abs(y1-y0)
	sx, sy := sign(x1-x0), sign(y1-y0)
	err := dx + dy
	for {
		img.Set(x0, y0, c)
		if x0 == x1 && y0 == y1 {
			return
		}
		e2 := 2 * err
		if e2 >= dy {
			err += dy
			x0 += sx
		}
		if e2 <= dx {
			err += dx
			y0 += sy
		}
	}
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func sign(n int) int {
	switch {
	case n > 0:
		return 1
	case n < 0:
		return -1
	default:
		return 0
	}
}
