// arena/emoji — render categorised emoji glyph tiles for the image-select gate (Noto Emoji, OFL 1.1).
// A "select every <category>" grid of real glyphs — needs CV/semantics, not a radial shape classifier.

// The image-select gate used four synthetic shapes (circle/square/triangle/star) a radial-signature
// classifier could read. This swaps in monochrome emoji glyphs from the bundled Noto Emoji font (SIL Open
// Font License 1.1 — see assets/OFL.txt), grouped by the Unicode category taxonomy (animals / food /
// vehicles). A "select every animal" grid of recognisable glyphs is a faithful reCAPTCHA-v2-style task that
// a shape classifier cannot solve — it forces a real CV/VLM solver. Single-codepoint emoji only (no
// variation selectors / ZWJ sequences) so the simple font.Drawer renders each glyph.

package arena

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"image"
	"image/color"
	"image/draw"
	"image/png"

	"golang.org/x/image/font"
	"golang.org/x/image/font/opentype"
	"golang.org/x/image/math/fixed"
)

//go:embed assets/NotoEmoji.ttf
var notoEmojiTTF []byte

var emojiFace font.Face

func init() {
	if f, err := opentype.Parse(notoEmojiTTF); err == nil {
		emojiFace, _ = opentype.NewFace(f, &opentype.FaceOptions{Size: 46, DPI: 72, Hinting: font.HintingFull})
	}
}

// emojiCatOrder is the stable category list (deterministic iteration); emojiCategories maps each to its
// glyph pool and the human prompt noun.
var emojiCatOrder = []string{"animal", "food", "vehicle"}

var emojiCategories = map[string]struct {
	noun   string
	glyphs []string
}{
	"animal":  {"animal", []string{"🐘", "🐅", "🦊", "🐢", "🐬", "🦉", "🐝", "🐌", "🦋", "🐙"}},
	"food":    {"food item", []string{"🍕", "🍔", "🍎", "🍌", "🍩", "🌮", "🍇", "🥐", "🍒", "🌽"}},
	"vehicle": {"vehicle", []string{"🚗", "🚌", "🚲", "🚂", "🚁", "🚜", "⛵", "🚀", "🚕", "🛴"}},
}

// rasterEmoji renders one emoji glyph centred on a 64×64 white tile (noise per level) as a base64 PNG data
// URI — the answer is the glyph's CATEGORY, readable only by recognising the image (not its markup).
func rasterEmoji(glyph string, noise int) string {
	const sz = 64
	img := image.NewRGBA(image.Rect(0, 0, sz, sz))
	draw.Draw(img, img.Bounds(), image.NewUniform(color.White), image.Point{}, draw.Src)
	if emojiFace != nil {
		d := &font.Drawer{Dst: img, Src: image.NewUniform(color.RGBA{40, 40, 40, 255}), Face: emojiFace}
		adv := d.MeasureString(glyph).Round()
		d.Dot = fixed.P((sz-adv)/2, 48)
		d.DrawString(glyph)
	}
	for i := 0; i < noise; i++ {
		img.Set(int(randInt(sz)), int(randInt(sz)), noiseGrey())
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
}

// randEmojiCategory returns a uniformly-random category name from the stable order.
func randEmojiCategory() string {
	return emojiCatOrder[randInt(int64(len(emojiCatOrder)))]
}

// randEmojiFrom returns a random glyph from a category.
func randEmojiFrom(cat string) string {
	g := emojiCategories[cat].glyphs
	return g[randInt(int64(len(g)))]
}
