// arena/slider_test — assert the slider gate fits-the-gap + behavioural checks (human drag passes, bot fails).
// Guards the trajectory discriminator (teleport / constant-velocity glide are rejected) + single-use.

package arena

import (
	"bytes"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
)

// humanDrag builds a plausible variable-velocity drag from 0 to gapX over ~400ms (ease-in/out, jitter).
func humanDrag(gapX int) []SliderPoint {
	pts := make([]SliderPoint, 0, 24)
	n := 24
	for i := 0; i <= n; i++ {
		f := float64(i) / float64(n)
		eased := f * f * (3 - 2*f)                       // smoothstep: accelerate then settle (variable velocity)
		x := eased*float64(gapX) + math.Sin(f*9)*1.5     // small jitter
		pts = append(pts, SliderPoint{T: f * 400, X: x}) // ~400ms total
	}
	pts[len(pts)-1].X = float64(gapX)
	return pts
}

// linearDrag is a constant-velocity robotic glide (uniform velocity → should be rejected).
func linearDrag(gapX int) []SliderPoint {
	pts := make([]SliderPoint, 0, 24)
	for i := 0; i <= 24; i++ {
		f := float64(i) / 24
		pts = append(pts, SliderPoint{T: f * 400, X: f * float64(gapX)})
	}
	return pts
}

func TestCheckSliderHumanVsBot(t *testing.T) {
	gap := 180
	if ok, why := CheckSlider(gap, float64(gap), humanDrag(gap)); !ok {
		t.Fatalf("a human-like drag was rejected: %s", why)
	}
	if ok, _ := CheckSlider(gap, float64(gap), linearDrag(gap)); ok {
		t.Fatal("a constant-velocity (uniform) drag was accepted")
	}
	if ok, _ := CheckSlider(gap, float64(gap), []SliderPoint{{T: 0, X: 0}, {T: 1, X: float64(gap)}}); ok {
		t.Fatal("a teleport (2-point, 1ms) drag was accepted")
	}
	if ok, _ := CheckSlider(gap, float64(gap-40), humanDrag(gap)); ok {
		t.Fatal("a drag that missed the gap was accepted")
	}
}

func TestSliderHTTPFlow(t *testing.T) {
	srv := httptest.NewServer(NewMux([]byte("test-secret-32-bytes-long-padxxx")))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/arena/slider")
	if err != nil {
		t.Fatal(err)
	}
	var s Slider
	_ = json.NewDecoder(resp.Body).Decode(&s)
	resp.Body.Close()
	if s.Kind != "slider" || s.GapX == 0 {
		t.Fatalf("bad slider challenge %+v", s)
	}
	verify := func(traj []SliderPoint) map[string]any {
		body, _ := json.Marshal(map[string]any{"id": s.ID, "x": float64(s.GapX), "trajectory": traj})
		r, err := http.Post(srv.URL+"/arena/slider/verify", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(r.Body).Decode(&out)
		return out
	}
	if verify(humanDrag(s.GapX))["ok"] != true {
		t.Fatal("human drag did not pass the slider gate")
	}
	// single-use: the id is consumed even on a pass, so re-verifying fails.
	if verify(humanDrag(s.GapX))["ok"] != false {
		t.Fatal("a consumed slider id was accepted again")
	}
}
