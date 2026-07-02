# scrub

Strip identifying metadata from files before you share them. Removes EXIF
(including GPS), XMP, IPTC/Photoshop, JPEG comments, PNG text/time chunks, and
the PDF Info dictionary + XMP stream — while keeping data that affects rendering.

## Usage

```text
scrub [FILES]... [-n] [-i] [-o OUTPUT]
```

```sh
scrub photo.jpg              # -> photo.clean.jpg  (original kept)
scrub -n leak.pdf            # dry run: list what would be removed
scrub -i a.jpg b.png         # overwrite files in place
scrub doc.pdf -o clean.pdf   # explicit output name (single input)
```

| Flag | Meaning |
|------|---------|
| `-n`, `--dry-run` | Report what would be removed; write nothing |
| `-i`, `--in-place` | Overwrite the original (atomic rename) |
| `-o`, `--output` | Output path; only valid with a single input |

Default (no `-i`/`-o`): write a cleaned copy to `<stem>.clean.<ext>` and keep
the original.

## Supported formats

JPEG, PNG, PDF — detected by **content (magic bytes), not file extension**.
Unrecognized formats are reported and skipped.

## What is removed vs kept

| Format | Removed | Kept (rendering) |
|--------|---------|------------------|
| JPEG | EXIF/GPS, XMP, IPTC/Photoshop, maker notes, thumbnails, comments (APP1, APP3–13, APP15, COM) | JFIF (APP0), ICC profile (APP2), Adobe transform (APP14) |
| PNG | `tEXt`, `zTXt`, `iTXt`, `tIME`, `eXIf` chunks | IHDR, PLTE, IDAT, IEND, gAMA, cHRM, sRGB, iCCP, tRNS, bKGD, pHYs, … |
| PDF | Info dictionary (author/title/producer/dates), XMP metadata stream | Page content, structure |

For JPEG, `scrub` also parses EXIF to flag **GPS location present** explicitly in
its report.

## How it works

`scrub` is a library (`scrub::strip`) plus a thin CLI. `strip` detects the
format by magic bytes and dispatches to a per-format stripper:

- **JPEG/PNG** use `img-parts` to filter application segments / ancillary chunks.
- **PDF** uses `lopdf`. Note: removing only the trailer reference to `/Info`
  leaves the orphaned object serialized in the file, so `scrub` deletes the
  actual `Info` and `Metadata` **objects**, not just the references.

The cleaned bytes are written atomically (temp sibling + rename), which matters
most for `-i` where it overwrites the only copy.

## Security notes

- Removes **container** metadata only. It does not touch watermarks, or
  information embedded in the pixels or the document text itself.
- A cleaned file re-scanned with `scrub -n` should report "already clean" — a
  quick way to verify.
- v0.1.

## See also

[workflows](workflows.md) — e.g. scrub → veil before publishing a leak.
