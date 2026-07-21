# Chancery brand assets

The mark is a **seal**: a broken ring forming a C, holding two bars that
narrow. A chancery is the office that keeps the seal, and the narrowing
bars are the property the product is built on — delegated authority can
only shrink.

## Files

| File | Use |
|---|---|
| `mark.svg` | the mark, 64×64 viewBox, purple tile |
| `mark-small.svg` | favicon variant: ring only, no inner bars (they merge below ~20px) |
| `mark-mono.svg` | single-colour tile via `currentColor`, for print and stickers |
| `lockup.svg` | mark + wordmark; the word uses `currentColor` so it works on any background |
| `mark-512.png` `mark-240.png` `mark-180.png` `mark-64.png` | raster mark; 240 is the Product Hunt thumbnail, 180 the apple-touch-icon |
| `favicon-32.png` `favicon-16.png` | raster favicons, rendered from `mark-small.svg` |
| `lockup-dark.png` | wordmark in light ink, for dark backgrounds |
| `lockup-light.png` | wordmark in dark ink, for light backgrounds |

PNGs have transparent backgrounds and are rendered from the SVGs with
Chromium, so they match the site exactly.

## Colour

Seal purple `#5e5ce6` on the tile, white on the ring. Page background in
product surfaces is `#0b0c0f`. When the tile sits on a light background
it needs no border — the purple carries enough contrast on its own.

## Rules

- Keep clear space of at least one quarter of the tile's width on all sides.
- Don't recolour the tile. If a single colour is required, use `mark-mono.svg`.
- Don't stretch: the tile is square and the lockup has a fixed ratio.
- Below roughly 20px use `mark-small.svg`; the inner bars stop resolving.
- The wordmark is Inter Semi-Bold at `-0.9` letter-spacing. The SVG carries
  a system-font fallback stack so it renders without Inter installed.

## Regenerating the PNGs

The rasterizer lives outside the repo. Any headless Chromium can do it:
render each SVG at the target size with a transparent background. The
sizes are listed in the table above.
