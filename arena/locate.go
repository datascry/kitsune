// arena/locate — point-localization gate: click the CENTER of the named target among distractors on a free canvas
// (hCaptcha "click the center of X" / AWS WAF family). NOVEL server-observed tell: a CV solver computes the target
// centroid and clicks it PIXEL-PERFECT (distance ~ 0), while a human's aim spreads tens of px; plus superhuman
// speed. The target center is rendered into the PNG and kept SERVER-SIDE (not in the payload — a real CV task).

package arena

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
)

// Locate is the PUBLIC challenge — only the rendered image + the target COLOUR name are sent; the target centre is
// secret (the client must locate it visually / by CV, then click its centre).
type Locate struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Level  string `json:"level"`
	Image  string `json:"image"`
	Prompt string `json:"prompt"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
}

const (
	locateRadius       = 34  // acceptance radius (px): a human click anywhere near the target centre passes
	localizePixelFloor = 2.5 // a click within this of the EXACT centroid is a computed (CV) click, not human aim
	localizeFloorMs    = 500 // a whole solve faster than this is superhuman (visual-locate + aim time)
)

var locateColors = []struct {
	name string
	c    color.RGBA
}{
	{"red", color.RGBA{200, 40, 40, 255}},
	{"green", color.RGBA{40, 160, 60, 255}},
	{"blue", color.RGBA{50, 90, 210, 255}},
	{"orange", color.RGBA{230, 140, 30, 255}},
	{"purple", color.RGBA{150, 60, 190, 255}},
}

func locateParams(lv Level) (nDistract, noise int) {
	switch lv {
	case LevelEasy:
		return 2, 40
	case LevelHard:
		return 5, 220
	default:
		return 3, 110
	}
}

// MintLocate renders distractor disks + one target-coloured disk at a SECRET centre; returns the answer (the
// target centre) referenced by verify.
func MintLocate(lv Level) (Locate, string) {
	const w, h = 300, 200
	nD, noise := locateParams(lv)
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	draw.Draw(img, img.Bounds(), image.NewUniform(color.RGBA{245, 245, 248, 255}), image.Point{}, draw.Src)

	ti := int(randInt(int64(len(locateColors))))
	target := locateColors[ti]
	type disk struct {
		x, y, r int
		c       color.RGBA
	}
	var disks []disk
	place := func(c color.RGBA) (int, int) {
		for tries := 0; tries < 60; tries++ {
			x := 30 + int(randInt(w-60))
			y := 30 + int(randInt(h-60))
			r := 18 + int(randInt(8))
			ok := true
			for _, d := range disks {
				dx, dy := x-d.x, y-d.y
				if dx*dx+dy*dy < (r+d.r+10)*(r+d.r+10) {
					ok = false
					break
				}
			}
			if ok {
				disks = append(disks, disk{x, y, r, c})
				return x, y
			}
		}
		x, y, r := 30+int(randInt(w-60)), 30+int(randInt(h-60)), 20
		disks = append(disks, disk{x, y, r, c})
		return x, y
	}
	cx, cy := place(target.c) // the target first (its centre is the secret answer)
	for i := 0; i < nD; i++ {
		place(locateColors[(ti+1+i)%len(locateColors)].c) // distinct-ish distractor colours
	}
	for _, d := range disks {
		for y := d.y - d.r; y <= d.y+d.r; y++ {
			for x := d.x - d.r; x <= d.x+d.r; x++ {
				if x >= 0 && x < w && y >= 0 && y < h {
					ddx, ddy := x-d.x, y-d.y
					if ddx*ddx+ddy*ddy <= d.r*d.r {
						img.Set(x, y, d.c)
					}
				}
			}
		}
	}
	for i := 0; i < noise; i++ {
		img.Set(int(randInt(w)), int(randInt(h)), noiseGrey())
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	l := Locate{
		ID: randHex(16), Kind: "locate", Level: string(lv),
		Image:  "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()),
		Prompt: "Click the center of the " + target.name + " circle.", Width: w, Height: h,
	}
	ans, _ := json.Marshal(map[string]int{"cx": cx, "cy": cy})
	return l, string(ans)
}

// CheckLocate reports whether the click is within locateRadius of the true centre, and the click distance (the
// pixel-perfect tell — a distance far below human aim variance is a computed centroid click).
func CheckLocate(expected string, clickX, clickY int) (pass bool, dist float64) {
	var a struct {
		CX int `json:"cx"`
		CY int `json:"cy"`
	}
	if err := json.Unmarshal([]byte(expected), &a); err != nil {
		return false, 1e9
	}
	dx, dy := float64(clickX-a.CX), float64(clickY-a.CY)
	dist = math.Sqrt(dx*dx + dy*dy)
	return dist <= locateRadius, dist
}
