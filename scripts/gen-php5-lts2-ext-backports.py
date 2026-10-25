#!/usr/bin/env python3
"""Export the exif (CVE-2018-14883, CVE-2020-7064 max), bcmath (CVE-2019-11046)
and mbstring (CVE-2020-7060) backports, verbatim where the code is identical.

Applicability was checked per branch by reading the pristine sources; 5.6.40
already carries the CVE-2018-14883 guard, so that one is exported for 5.4/5.5.
"""
import difflib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def emit(branch, cve, name, subject, upstream, hunks):
    """hunks: list of (relpath, old, new). Writes one patch per CVE/branch."""
    chunks = []
    for rel, old, new in hunks:
        path = ROOT / f"php-{branch}" / rel
        text = path.read_text()
        if text.count(old) != 1:
            raise SystemExit(f"{branch}/{rel}: {text.count(old)} matches for {cve}")
        chunks.append("".join(difflib.unified_diff(
            text.splitlines(True), text.replace(old, new).splitlines(True),
            fromfile=f"a/{rel}", tofile=f"b/{rel}")))
    dest = ROOT / f"php-{branch}-patches/{cve}/{name}"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(f"Subject: [PATCH] {subject}\n"
                    f"Upstream: https://github.com/php/php-src/commit/{upstream}\n"
                    f"CVE: {cve}\n\n" + "".join(chunks))
    print(dest.relative_to(ROOT))


# --- CVE-2019-11046: isdigit() accepts bytes >= 0x80 on some platforms --------
for b in ("5.4", "5.5", "5.6"):
    emit(b, "CVE-2019-11046", "001-bcmath-ascii-digits-only.patch",
         "Fix bug #78878: only ASCII digits are digits in bc_str2num",
         "eb23c6008753b1cdc5359dead3a096dce46c9018",
         [("ext/bcmath/libbcmath/src/str2num.c",
           "  while (isdigit((int)*ptr)) ptr++, digits++;\t/* digits */\n"
           "  if (*ptr == '.') ptr++;\t\t\t/* decimal point */\n"
           "  while (isdigit((int)*ptr)) ptr++, strscale++;\t/* digits */\n",
           "  while (*ptr >= '0' && *ptr <= '9') ptr++, digits++;\t/* digits */\n"
           "  if (*ptr == '.') ptr++;\t\t\t/* decimal point */\n"
           "  while (*ptr >= '0' && *ptr <= '9') ptr++, strscale++;\t/* digits */\n")])

# --- CVE-2020-7064: exif_file_sections_add() over-allocation + short TIFF ----
EXIF_ALLOC_OLD = "\t\tsn = exif_file_sections_add(ImageInfo, marker, itemlen+1, NULL);\n"
EXIF_ALLOC_NEW = "\t\tsn = exif_file_sections_add(ImageInfo, marker, itemlen, NULL);\n"
TIFF_OLD = """	unsigned exif_value_2a, offset_of_ifd;

	/* set the thumbnail stuff to nothing so we can test to see if they get set up */
"""
TIFF_NEW = """	unsigned exif_value_2a, offset_of_ifd;

	if (length < 2) {
		exif_error_docref(NULL EXIFERR_CC, ImageInfo, E_WARNING, "Missing TIFF alignment marker");
		return;
	}

	/* set the thumbnail stuff to nothing so we can test to see if they get set up */
"""
for b in ("5.4", "5.5", "5.6"):
    emit(b, "CVE-2020-7064", "001-exif-short-tiff-and-section-size.patch",
         "Fixed bug #79282: guard a short TIFF header and stop over-allocating sections",
         "25238bdf6005b85ab844aa2b743b589dfce9f0d2",
         [("ext/exif/exif.c", TIFF_OLD, TIFF_NEW),
          ("ext/exif/exif.c", EXIF_ALLOC_OLD, EXIF_ALLOC_NEW)])

# --- CVE-2018-14883: integer overflow in exif_thumbnail_extract() -------------
THUMB_OLD = """	/* Check to make sure we are not going to go past the ExifLength */
	if ((ImageInfo->Thumbnail.offset + ImageInfo->Thumbnail.size) > length) {
"""
THUMB_NEW = """	/* Check to make sure we are not going to go past the ExifLength */
	if (ImageInfo->Thumbnail.size > length
		|| (ImageInfo->Thumbnail.offset + ImageInfo->Thumbnail.size) > length
		|| ImageInfo->Thumbnail.offset > length - ImageInfo->Thumbnail.size
	) {
"""
for b in ("5.4", "5.5"):
    emit(b, "CVE-2018-14883", "001-exif-thumbnail-bounds.patch",
         "Fix bug #76423: integer overflow in exif_thumbnail_extract",
         "1baeae42703f9b2ec21fff787146eeca08d45535",
         [("ext/exif/exif.c", THUMB_OLD, THUMB_NEW)])

# --- CVE-2020-7060: CP950 trail-byte range in mbfl_filt_conv_big5_wchar -------
BIG5_HELPER_OLD = """	{0xf70f,0xf848,0xc740,0xc8fe},
};

/*
 * Big5 => wchar
 */
"""
BIG5_HELPER_NEW = """	{0xf70f,0xf848,0xc740,0xc8fe},
};

static inline int is_in_cp950_pua(int c1, int c) {
	if ((c1 >= 0xfa && c1 <= 0xfe) || (c1 >= 0x8e && c1 <= 0xa0) ||
			(c1 >= 0x81 && c1 <= 0x8d) || (c1 >= 0xc7 && c1 <= 0xc8)) {
		return (c >=0x40 && c <= 0x7e) || (c >= 0xa1 && c <= 0xfe);
	}
	if (c1 == 0xc6) {
		return c >= 0xa1 && c <= 0xfe;
	}
	return 0;
}

/*
 * Big5 => wchar
 */
"""
BIG5_COND_OLD = """				if (w <= 0 && 
					(((c1 >= 0xfa && c1 <= 0xfe) || (c1 >= 0x8e && c1 <= 0xa0) ||
					  (c1 >= 0x81 && c1 <= 0x8d) ||(c1 >= 0xc7 && c1 <= 0xc8)) 
					 && ((c > 0x39 && c < 0x7f) || (c > 0xa0 && c < 0xff))) ||
					((c1 == 0xc6) && (c > 0xa0 && c < 0xff))) {
"""
BIG5_COND_NEW = """				if (w <= 0 && is_in_cp950_pua(c1, c)) {
"""
for b in ("5.4", "5.5", "5.6"):
    emit(b, "CVE-2020-7060", "001-mbstring-cp950-trail-range.patch",
         "Fix bug #79037: restrict CP950 PUA trail bytes to the table's range",
         "2bcbc95f033c31b00595ed39f79c3a99b4ed0501",
         [("ext/mbstring/libmbfl/filters/mbfilter_big5.c", BIG5_HELPER_OLD, BIG5_HELPER_NEW),
          ("ext/mbstring/libmbfl/filters/mbfilter_big5.c", BIG5_COND_OLD, BIG5_COND_NEW)])
