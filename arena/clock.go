// arena/clock — analog-clock CAPTCHA: render a clock face at a random time; the answer is the time the hands show.
// Procedural + owned (zero-license). A distinct visual-reasoning task (read analog hands) beyond glyph OCR.

package arena

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
	"math"
	"strconv"
	"strings"
)

func drawCircleOutline(img *image.RGBA, cx, cy, r int, c color.Color) {
	for deg := 0; deg < 720; deg++ {
		a := float64(deg) * math.Pi / 360
		img.Set(cx+int(float64(r)*math.Cos(a)), cy+int(float64(r)*math.Sin(a)), c)
	}
}

// thickLine draws a line thickened by half-width hw (for clock hands).
func thickLine(img *image.RGBA, x0, y0, x1, y1, hw int, c color.Color) {
	for dx := -hw; dx <= hw; dx++ {
		for dy := -hw; dy <= hw; dy++ {
			drawLine(img, x0+dx, y0+dy, x1+dx, y1+dy, c)
		}
	}
}

// renderClock draws an analog clock showing hour:minute as a PNG data URI (per-level speckle noise).
func renderClock(hour, minute int, lv Level) string {
	const sz = 100
	img := image.NewRGBA(image.Rect(0, 0, sz, sz))
	for i := 0; i < len(img.Pix); i += 4 {
		img.Pix[i], img.Pix[i+1], img.Pix[i+2], img.Pix[i+3] = 250, 250, 250, 255
	}
	cx, cy, r := 50, 50, 42
	ink := color.RGBA{30, 30, 30, 255}
	drawCircleOutline(img, cx, cy, r, ink)
	for h := 0; h < 12; h++ { // hour ticks
		a := float64(h) * 30 * math.Pi / 180
		drawLine(img, cx+int(float64(r-6)*math.Sin(a)), cy-int(float64(r-6)*math.Cos(a)),
			cx+int(float64(r-1)*math.Sin(a)), cy-int(float64(r-1)*math.Cos(a)), ink)
	}
	ha := (float64(hour%12) + float64(minute)/60) * 30 * math.Pi / 180 // hour hand moves between ticks
	ma := float64(minute) * 6 * math.Pi / 180
	thickLine(img, cx, cy, cx+int(float64(r)*0.5*math.Sin(ha)), cy-int(float64(r)*0.5*math.Cos(ha)), 1, ink)
	thickLine(img, cx, cy, cx+int(float64(r)*0.78*math.Sin(ma)), cy-int(float64(r)*0.78*math.Cos(ma)), 0, ink)
	for dx := -2; dx <= 2; dx++ { // center hub
		for dy := -2; dy <= 2; dy++ {
			img.Set(cx+dx, cy+dy, ink)
		}
	}
	var noise int
	switch lv {
	case LevelEasy:
		noise = 15
	case LevelHard:
		noise = 150
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

// mintClock renders a clock at a random time (minute a multiple of 5) + returns the canonical answer "H:MM".
func mintClock(lv Level) (string, string) {
	hour := int(randInt(12)) + 1   // 1..12
	minute := int(randInt(12)) * 5 // 0,5,...,55
	return renderClock(hour, minute, lv), normClock(strconv.Itoa(hour) + ":" + pad2(minute))
}

func pad2(n int) string {
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

// normClock canonicalises a time answer to "H:MM" (hour without a leading zero, minute 2-digit), accepting ":" or
// "." separators, so "03:45", "3.45" and "3:45" all match. A malformed input is returned as-is (won't match).
func normClock(s string) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), ".", ":")
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return s
	}
	h, e1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	m, e2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if e1 != nil || e2 != nil {
		return s
	}
	return strconv.Itoa(h) + ":" + pad2(m)
}
