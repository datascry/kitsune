// arena/match — orientation-match gate: click the candidate arrow FACING THE SAME WAY as the reference (Arkose
// "faces the same way" / hCaptcha "which go together" family). A RELATIONAL task — you must compare the reference
// against each candidate, not classify one tile. NOVEL server-observed tell: solving faster than a human can scan a
// reference + N candidates (age < a per-tile floor). Per-tile jitter defeats a pixel-hash match, forcing real
// orientation reasoning; the matching tile shares the reference ORIENTATION, not its exact pixels.

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

// MatchTile is one candidate arrow (rendered PNG); the client clicks the one matching the reference orientation.
type MatchTile struct {
	Index int    `json:"index"`
	Image string `json:"image"`
}

// Match is the PUBLIC challenge — the reference + candidate images are sent; the matching INDEX is secret (the
// client must reason about orientation, not read markup).
type Match struct {
	ID        string      `json:"id"`
	Kind      string      `json:"kind"`
	Level     string      `json:"level"`
	Reference string      `json:"reference"`
	Tiles     []MatchTile `json:"tiles"`
	Prompt    string      `json:"prompt"`
}

// matchPerTileMs: the minimum a human needs to look at the reference and one candidate to compare orientation. A
// whole solve (age) under (N+1) * this is superhuman — the load-bearing, FP-safe prong.
const matchPerTileMs = 250

func matchParams(lv Level) (nTiles, noise int) {
	switch lv {
	case LevelEasy:
		return 4, 30
	case LevelHard:
		return 6, 160
	default:
		return 5, 90
	}
}

// rasterArrow renders a triangular arrow pointing at thetaDeg (0 = up, clockwise) on a 64x64 tile as a base64 PNG.
// Per-tile centre/tone jitter + noise so the matching candidate is NOT pixel-identical to the reference (a
// hash-match shortcut fails; the orientation is the only shared invariant).
func rasterArrow(thetaDeg float64, noise int) string {
	const sz = 64
	img := image.NewRGBA(image.Rect(0, 0, sz, sz))
	draw.Draw(img, img.Bounds(), image.NewUniform(color.White), image.Point{}, draw.Src)
	cx, cy := sz/2+int(randInt(7))-3, sz/2+int(randInt(7))-3
	r := 22 + int(randInt(5))
	tone := uint8(20 + randInt(50))
	col := color.RGBA{tone, tone, tone, 255}
	th := thetaDeg * math.Pi / 180
	sin, cos := math.Sin(th), math.Cos(th)
	for y := 0; y < sz; y++ {
		for x := 0; x < sz; x++ {
			dx, dy := float64(x-cx), float64(y-cy)
			// rotate the SAMPLE point by -theta, then test the upward-pointing triangle (apex at dy=-r)
			rx := dx*cos + dy*sin
			ry := -dx*sin + dy*cos
			if shapeContains("triangle", int(math.Round(rx)), int(math.Round(ry)), r) {
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

// MintMatch renders a reference arrow + N candidates at DISTINCT orientations, exactly one matching the reference;
// returns the answer (the matching candidate index).
func MintMatch(lv Level) (Match, string) {
	n, noise := matchParams(lv)
	// 12 distinct orientations (every 30 deg); pick the reference + n-1 distinct others
	angles := []float64{0, 30, 60, 90, 120, 150, 180, 210, 240, 270, 300, 330}
	for i := len(angles) - 1; i > 0; i-- { // shuffle
		j := int(randInt(int64(i + 1)))
		angles[i], angles[j] = angles[j], angles[i]
	}
	refAngle := angles[0]
	others := angles[1:n] // n-1 distinct non-reference angles
	answer := int(randInt(int64(n)))
	tiles := make([]MatchTile, n)
	oi := 0
	for i := 0; i < n; i++ {
		ang := refAngle
		if i != answer {
			ang = others[oi]
			oi++
		}
		tiles[i] = MatchTile{Index: i, Image: rasterArrow(ang, noise)}
	}
	m := Match{
		ID: randHex(16), Kind: "match", Level: string(lv),
		Reference: rasterArrow(refAngle, noise), Tiles: tiles,
		Prompt: "Click the arrow that points the same way as the reference.",
	}
	ans, _ := json.Marshal(map[string]int{"answer": answer, "n": n})
	return m, string(ans)
}

// CheckMatch reports whether the clicked candidate is the one matching the reference orientation.
func CheckMatch(expected string, clicked int) bool {
	var a struct {
		Answer int `json:"answer"`
	}
	if err := json.Unmarshal([]byte(expected), &a); err != nil {
		return false
	}
	return clicked == a.Answer
}

// matchFloorFor returns the superhuman-speed floor (ms) for this challenge: (N+1) * matchPerTileMs — the time to
// look at the reference plus each of the N candidates. Zero if the answer is unparseable (no anomaly then).
func matchFloorFor(expected string) int {
	var a struct {
		N int `json:"n"`
	}
	if err := json.Unmarshal([]byte(expected), &a); err != nil || a.N == 0 {
		return 0
	}
	return (a.N + 1) * matchPerTileMs
}
