// arena/spotdiff — spot-the-difference gate: two near-identical panels differ in K spots; click the differences
// (a prevalent wild captcha style). NOVEL angle: a bot solves by PIXEL-DIFFING the two panels, so it clicks the
// EXACT centroid of each changed region (dist ~ 0) and finds all K instantly; a human eyeballs (approximate clicks)
// and needs seconds per difference. Server-observed tells: pixel-perfect diff clicks OR superhuman scan speed.

package arena

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"math"
)

// SpotDiff is the PUBLIC challenge — one image with two panels is sent; the K difference centres are secret (the
// client must FIND them by comparing the panels).
type SpotDiff struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Level  string `json:"level"`
	Image  string `json:"image"`
	Count  int    `json:"count"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
	Prompt string `json:"prompt"`
}

const (
	spotHitRadius  = 24   // a click within this of a difference centre counts as finding it (generous for humans)
	spotPixelFloor = 3.0  // a click within this of the EXACT centroid is an image-diff (pixel-perfect) click
	spotPerDiffMs  = 1200 // ms a human needs to scan the two panels for one difference
	spotPanelW     = 140
	spotPanelGap   = 24
	spotPanelH     = 170
)

var spotColors = []color.RGBA{
	{200, 60, 60, 255}, {60, 150, 70, 255}, {60, 100, 210, 255},
	{220, 150, 40, 255}, {150, 70, 190, 255}, {70, 180, 190, 255},
}

func spotParams(lv Level) (nShapes, nDiff int) {
	switch lv {
	case LevelEasy:
		return 5, 2
	case LevelHard:
		return 9, 4
	default:
		return 7, 3
	}
}

// MintSpotDiff renders two panels of coloured disks, identical except K disks recoloured on the RIGHT panel; returns
// the answer (the K difference centres, in full-image coords on the right panel).
func MintSpotDiff(lv Level) (SpotDiff, string) {
	nShapes, nDiff := spotParams(lv)
	w := spotPanelW*2 + spotPanelGap
	img := image.NewRGBA(image.Rect(0, 0, w, spotPanelH))
	for y := 0; y < spotPanelH; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{246, 246, 249, 255})
		}
	}
	type disk struct {
		x, y, r, col int
	}
	var disks []disk
	for len(disks) < nShapes {
		x := 18 + int(randInt(int64(spotPanelW-36)))
		y := 18 + int(randInt(int64(spotPanelH-36)))
		r := 12 + int(randInt(6))
		ok := true
		for _, d := range disks {
			if (x-d.x)*(x-d.x)+(y-d.y)*(y-d.y) < (r+d.r+8)*(r+d.r+8) {
				ok = false
				break
			}
		}
		if ok {
			disks = append(disks, disk{x, y, r, int(randInt(int64(len(spotColors))))})
		}
	}
	// choose K disks to recolour on the right panel
	diff := map[int]bool{}
	for len(diff) < nDiff {
		diff[int(randInt(int64(len(disks))))] = true
	}
	drawDisk := func(cx, cy, r int, c color.RGBA) {
		for y := cy - r; y <= cy+r; y++ {
			for x := cx - r; x <= cx+r; x++ {
				if x >= 0 && x < w && y >= 0 && y < spotPanelH && (x-cx)*(x-cx)+(y-cy)*(y-cy) <= r*r {
					img.Set(x, y, c)
				}
			}
		}
	}
	rightOff := spotPanelW + spotPanelGap
	var centres [][2]int
	for i, d := range disks {
		drawDisk(d.x, d.y, d.r, spotColors[d.col]) // left panel (original)
		rc := spotColors[d.col]
		if diff[i] {
			rc = spotColors[(d.col+1+int(randInt(int64(len(spotColors)-1))))%len(spotColors)] // a different colour
			centres = append(centres, [2]int{d.x + rightOff, d.y})
		}
		drawDisk(d.x+rightOff, d.y, d.r, rc) // right panel (K recoloured)
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	s := SpotDiff{
		ID: randHex(16), Kind: "spotdiff", Level: string(lv),
		Image: "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()),
		Count: nDiff, Width: w, Height: spotPanelH,
		Prompt: "The two panels differ. Click each difference on the right panel.",
	}
	ans, _ := json.Marshal(centres)
	return s, string(ans)
}

// CheckSpotDiff greedily matches each click to an unmatched difference centre within the hit radius; pass if all K
// are found. Returns whether EVERY matched click was pixel-perfect (an image-diff click) and the difference count.
func CheckSpotDiff(expected string, clicks [][2]float64) (pass, allExact bool, n int) {
	var centres [][2]int
	if err := json.Unmarshal([]byte(expected), &centres); err != nil || len(centres) == 0 {
		return false, false, 0
	}
	n = len(centres)
	used := make([]bool, len(clicks))
	found := 0
	allExact = true
	for _, c := range centres {
		bestI, bestD := -1, math.Inf(1)
		for i, k := range clicks {
			if used[i] {
				continue
			}
			d := math.Hypot(k[0]-float64(c[0]), k[1]-float64(c[1]))
			if d < bestD {
				bestD, bestI = d, i
			}
		}
		if bestI >= 0 && bestD <= spotHitRadius {
			used[bestI] = true
			found++
			if bestD > spotPixelFloor {
				allExact = false
			}
		} else {
			allExact = false
		}
	}
	return found == n, allExact && found == n, n
}
