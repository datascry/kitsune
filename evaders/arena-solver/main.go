// evaders/arena-solver — a browserless solver that beats every arena CAPTCHA gate (OWNED gates only).
// Proves each gate is solvable headlessly (the finding) while the detector still convicts the no-JS solver.

// The red side of the arena: no browser, just HTTP + parsing. It solves the text, math, honeypot,
// image-select, rotate and slider gates against Kitsune's OWN arena (via the edge/detector relay), measuring
// cost. The point is the dual verdict from the red angle — every challenge falls to a script, yet a script
// has no coherent browser fingerprint, so the detector reads it as a bot regardless. ETHICS: the target host
// is allow-list-checked to Kitsune's own edge/detector; this never touches a third-party challenge.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// ownTargets is the evader's own ethics gate (mirrors harness/allowlist.py): only Kitsune's edge/detector.
var ownTargets = map[string]bool{"edge": true, "detector": true, "localhost": true, "127.0.0.1": true}

type captcha struct {
	Kind   string   `json:"kind"`
	ID     string   `json:"id"`
	Prompt string   `json:"prompt"`
	Image  string   `json:"image"`
	Field  string   `json:"field"`
	Tiles  []string `json:"tiles"`
	Angle  int      `json:"angle"`
}

type slider struct {
	Kind   string `json:"kind"`
	ID     string `json:"id"`
	GapX   int    `json:"gap_x"`
	TrackW int    `json:"track_w"`
	PieceW int    `json:"piece_w"`
}

func main() {
	// Target the detector relay over HTTP (the /arena/* routes live on the detector). Plain HTTP avoids
	// trusting the edge's self-signed TLS — and the gate-solving (the red-side point) is identical either way.
	base := os.Getenv("KITSUNE_DETECTOR")
	if base == "" {
		base = "http://detector:8080"
	}
	base = strings.TrimSuffix(base, "/")
	u, err := url.Parse(base)
	if err != nil || !ownTargets[u.Hostname()] {
		fmt.Fprintf(os.Stderr, "refusing target %q — arena-solver only ever hits Kitsune's own detector\n", base)
		os.Exit(2)
	}

	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Timeout: 30 * time.Second}

	families := []struct {
		name string
		fn   func(*http.Client, string) (bool, int64, error)
	}{
		{"text", solveText},
		{"math", solveMath2},
		{"honeypot", solveHoneypot},
		{"image-select", solveImageSelect},
		{"rotate", solveRotate},
		{"slider", solveSlider},
	}
	allOK := true
	for _, f := range families {
		ok, ms, err := f.fn(c, base)
		status := "PASSED"
		if !ok || err != nil {
			status = "FAILED"
			allOK = false
		}
		extra := ""
		if err != nil {
			extra = " (" + err.Error() + ")"
		}
		fmt.Printf("%-13s gate %s in %4d ms%s\n", f.name, status, ms, extra)
	}
	fmt.Println("note: every gate falls to a browserless solver — but the detector convicts this no-JS client.")
	if !allOK {
		os.Exit(1)
	}
}

func getCaptcha(c *http.Client, base, kind string) (*captcha, error) {
	r, err := c.Get(base + "/arena/captcha?kind=" + kind)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	var cap captcha
	if err := json.NewDecoder(r.Body).Decode(&cap); err != nil {
		return nil, err
	}
	return &cap, nil
}

func verifyCaptcha(c *http.Client, base string, body map[string]any) (bool, error) {
	b, _ := json.Marshal(body)
	r, err := c.Post(base+"/arena/captcha/verify", "application/json", bytes.NewReader(b))
	if err != nil {
		return false, err
	}
	defer r.Body.Close()
	var out struct {
		OK bool `json:"ok"`
	}
	_ = json.NewDecoder(r.Body).Decode(&out)
	return out.OK, nil
}

func timed(fn func() (bool, error)) (bool, int64, error) {
	t0 := time.Now()
	ok, err := fn()
	return ok, time.Since(t0).Milliseconds(), err
}

func solveText(c *http.Client, base string) (bool, int64, error) {
	return timed(func() (bool, error) {
		cap, err := getCaptcha(c, base, "text")
		if err != nil {
			return false, err
		}
		return verifyCaptcha(c, base, map[string]any{"kind": "text", "id": cap.ID, "answer": extractSVGText(cap.Image)})
	})
}

func solveMath2(c *http.Client, base string) (bool, int64, error) {
	return timed(func() (bool, error) {
		cap, err := getCaptcha(c, base, "math")
		if err != nil {
			return false, err
		}
		return verifyCaptcha(c, base, map[string]any{"kind": "math", "id": cap.ID, "answer": solveMath(cap.Prompt)})
	})
}

func solveHoneypot(c *http.Client, base string) (bool, int64, error) {
	return timed(func() (bool, error) {
		cap, err := getCaptcha(c, base, "honeypot")
		if err != nil {
			return false, err
		}
		return verifyCaptcha(c, base, map[string]any{"kind": "honeypot", "id": cap.ID, "answer": ""})
	})
}

func solveImageSelect(c *http.Client, base string) (bool, int64, error) {
	return timed(func() (bool, error) {
		cap, err := getCaptcha(c, base, "image-select")
		if err != nil {
			return false, err
		}
		target := targetShape(cap.Prompt)
		var idx []string
		for i, tile := range cap.Tiles {
			if classifyTile(tile) == target {
				idx = append(idx, strconv.Itoa(i))
			}
		}
		return verifyCaptcha(c, base, map[string]any{"kind": "image-select", "id": cap.ID, "answer": strings.Join(idx, ",")})
	})
}

func solveRotate(c *http.Client, base string) (bool, int64, error) {
	return timed(func() (bool, error) {
		cap, err := getCaptcha(c, base, "rotate")
		if err != nil {
			return false, err
		}
		// the target is always upright; a script submits 0 directly (the finding: no trajectory check).
		return verifyCaptcha(c, base, map[string]any{"kind": "rotate", "id": cap.ID, "answer": "0"})
	})
}

func solveSlider(c *http.Client, base string) (bool, int64, error) {
	return timed(func() (bool, error) {
		r, err := c.Get(base + "/arena/slider")
		if err != nil {
			return false, err
		}
		var s slider
		_ = json.NewDecoder(r.Body).Decode(&s)
		r.Body.Close()
		// Synthesize a HUMAN-LIKE drag: smoothstep easing + jitter ⇒ variable velocity that clears the gate's
		// velocity-CV floor (a naive constant-velocity glide would be rejected — that is the slider's tell).
		traj := make([]map[string]float64, 0, 24)
		for i := 0; i <= 24; i++ {
			f := float64(i) / 24
			eased := f * f * (3 - 2*f)
			x := eased*float64(s.GapX) + math.Sin(f*9)*1.5
			traj = append(traj, map[string]float64{"t": f * 420, "x": x})
		}
		traj[len(traj)-1]["x"] = float64(s.GapX)
		body, _ := json.Marshal(map[string]any{"id": s.ID, "x": float64(s.GapX), "trajectory": traj})
		vr, err := c.Post(base+"/arena/slider/verify", "application/json", bytes.NewReader(body))
		if err != nil {
			return false, err
		}
		defer vr.Body.Close()
		var out struct {
			OK bool `json:"ok"`
		}
		_ = json.NewDecoder(vr.Body).Decode(&out)
		return out.OK, nil
	})
}
