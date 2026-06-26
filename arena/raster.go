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
// plaintext answer exists only as pixels — there is no <text> element to parse. The difficulty knobs scale
// the warp amplitude, the noise density and the stroke count (a harder level is heavier to OCR).
func rasterText(code string, k textKnobs) string {
	w, h := 30*len(code)+30, 64
	base := image.NewRGBA(image.Rect(0, 0, w, h))
	draw.Draw(base, base.Bounds(), image.NewUniform(color.White), image.Point{}, draw.Src)
	if captchaFace != nil {
		d := &font.Drawer{Dst: base, Src: image.NewUniform(color.RGBA{40, 40, 40, 255}), Face: captchaFace}
		x := 16
		for _, ch := range code {
			// Per-glyph colour variation (a different dark tone per char) defeats single-threshold binarization.
			tone := uint8(20 + randInt(60))
			d.Src = image.NewUniform(color.RGBA{tone, tone, tone, 255})
			d.Dot = fixed.P(x, 46+int(randInt(13))-6) // per-character vertical jitter
			d.DrawString(string(ch))
			// Overlap shaves the advance so glyphs touch/overlap at harder levels — kills per-glyph segmentation.
			x += 27 + int(randInt(9)) - 4 - k.Overlap
		}
	}
	// 2D sine warp (vertical per-column + horizontal per-row) — defeats segmentation/OCR and any markup reading.
	amp := k.WarpAmp + float64(randInt(3))
	freq := 0.04 + float64(randInt(4))/100.0
	phase := float64(randInt(628)) / 100.0
	hAmp := k.HWarp
	hFreq := 0.05 + float64(randInt(4))/100.0
	hPhase := float64(randInt(628)) / 100.0
	out := image.NewRGBA(base.Bounds())
	draw.Draw(out, out.Bounds(), image.NewUniform(color.White), image.Point{}, draw.Src)
	for x := 0; x < w; x++ {
		shift := int(amp * math.Sin(float64(x)*freq+phase))
		for y := 0; y < h; y++ {
			sx := x + int(hAmp*math.Sin(float64(y)*hFreq+hPhase))
			sy := y + shift
			if sx >= 0 && sx < w && sy >= 0 && sy < h {
				out.Set(x, y, base.At(sx, sy))
			}
		}
	}
	// Interference: straight strokes + curved (Bezier) lines crossing the glyphs (count scales with difficulty).
	for i := 0; i < k.Lines; i++ {
		x0, y0, x1, y1 := int(randInt(int64(w))), int(randInt(int64(h))), int(randInt(int64(w))), int(randInt(int64(h)))
		drawLine(out, x0, y0, x1, y1, noiseGrey())
	}
	for i := 0; i < k.Curves; i++ {
		drawCurve(out,
			int(randInt(int64(w/3))), int(randInt(int64(h))),
			int(randInt(int64(w))), int(randInt(int64(h))),
			w-1-int(randInt(int64(w/3))), int(randInt(int64(h))),
			noiseGrey())
	}
	// Grey-varied speckle so background subtraction / denoising is harder (count scales with difficulty).
	for i := 0; i < k.Speckle; i++ {
		out.Set(int(randInt(int64(w))), int(randInt(int64(h))), noiseGrey())
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, out)
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
}

// noiseGrey returns a random mid-grey so speckle/lines vary in tone (a single threshold can't strip them).
func noiseGrey() color.RGBA {
	v := uint8(110 + randInt(90))
	return color.RGBA{v, v, v, 255}
}

// drawCurve plots a quadratic Bézier (p0→ctrl→p1) by sampling — a curved interference line, harder to remove
// than a straight stroke (it follows the text's own curvature). Sampled densely enough to be continuous.
func drawCurve(img *image.RGBA, x0, y0, cx, cy, x1, y1 int, c color.Color) {
	const steps = 60
	px, py := x0, y0
	for i := 1; i <= steps; i++ {
		t := float64(i) / steps
		mt := 1 - t
		x := int(mt*mt*float64(x0) + 2*mt*t*float64(cx) + t*t*float64(x1))
		y := int(mt*mt*float64(y0) + 2*mt*t*float64(cy) + t*t*float64(y1))
		drawLine(img, px, py, x, y, c)
		px, py = x, y
	}
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
