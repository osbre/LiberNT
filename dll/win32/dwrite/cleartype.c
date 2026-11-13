/*
 * PROJECT:     LiberNT DirectWrite
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     ClearType 3x1 textures from sixth-pixel samples
 * COPYRIGHT:   Copyright 2026 Ostap Brehin <osbre@protonmail.com>
 */

#define COBJMACROS

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "dwrite_private.h"

#define CLEARTYPE_SAMPLES 6
#define CLEARTYPE_MARGIN 2

static BOOL cleartype_face_has_table(IDWriteFontFace *fontface, UINT32 tag)
{
    const void *data;
    void *context;
    UINT32 size;
    BOOL exists = FALSE;

    if (SUCCEEDED(IDWriteFontFace_TryGetFontTable(fontface, tag, &data, &size, &context, &exists)) && exists)
        IDWriteFontFace_ReleaseFontTable(fontface, context);
    return exists;
}

BOOL cleartype_face_is_sampled(IDWriteFontFace *fontface)
{
    /* FIXME: fonts with hinting programs keep the tripled gray texture; Windows hints them with ClearType compatible widths */
    return cleartype_face_has_table(fontface, DWRITE_MAKE_OPENTYPE_TAG('g','l','y','f')) &&
            !cleartype_face_has_table(fontface, DWRITE_MAKE_OPENTYPE_TAG('f','p','g','m')) &&
            !cleartype_face_has_table(fontface, DWRITE_MAKE_OPENTYPE_TAG('p','r','e','p'));
}

DWRITE_RENDERING_MODE1 cleartype_sample_mode(DWRITE_RENDERING_MODE1 rendering_mode)
{
    return rendering_mode == DWRITE_RENDERING_MODE1_NATURAL_SYMMETRIC ? rendering_mode : DWRITE_RENDERING_MODE1_ALIASED;
}

static LONG floor_div(LONG value, LONG divisor)
{
    assert(divisor > 0);
    return value >= 0 ? value / divisor : -((-value + divisor - 1) / divisor);
}

void cleartype_samples_to_pixels(RECT *bbox)
{
    LONG left, right;

    if (IsRectEmpty(bbox))
        return;

    left = floor_div(floor_div(bbox->left - 2, 2), 3);
    right = floor_div(floor_div(bbox->right + 1, 2), 3) + 1;
    assert(left <= right);
    bbox->left = left;
    bbox->right = right;
}

BYTE *cleartype_alloc_samples(const RECT *bounds)
{
    return calloc((bounds->right - bounds->left) * CLEARTYPE_SAMPLES + 2 * CLEARTYPE_MARGIN,
            bounds->bottom - bounds->top);
}

void cleartype_add_glyph(BYTE *samples, const RECT *bounds, const POINT *origin, const RECT *bbox,
        const BYTE *src, int pitch, BOOL is_1bpp)
{
    int stride = (bounds->right - bounds->left) * CLEARTYPE_SAMPLES + 2 * CLEARTYPE_MARGIN;
    int x0 = (origin->x - bounds->left) * CLEARTYPE_SAMPLES + bbox->left + CLEARTYPE_MARGIN;
    int y0 = origin->y + bbox->top - bounds->top;
    int x, y;

    for (y = 0; y < bbox->bottom - bbox->top; y++, src += pitch)
    {
        BYTE *dst;

        if (y0 + y < 0 || y0 + y >= bounds->bottom - bounds->top)
            continue;
        dst = samples + (y0 + y) * stride;
        for (x = 0; x < bbox->right - bbox->left; x++)
        {
            BYTE value = is_1bpp ? ((src[x / 8] & (0x80 >> (x % 8))) ? 0xff : 0) : src[x];

            if (x0 + x < 0 || x0 + x >= stride)
                continue;
            if (value > dst[x0 + x])
                dst[x0 + x] = value;
        }
    }
}

void cleartype_filter(const BYTE *samples, const RECT *bounds, BYTE *bitmap)
{
    int width = (bounds->right - bounds->left) * 3;
    int stride = width * 2 + 2 * CLEARTYPE_MARGIN;
    int x, y, i;

    for (y = 0; y < bounds->bottom - bounds->top; y++)
    {
        const BYTE *row = samples + y * stride;

        for (x = 0; x < width; x++)
        {
            unsigned int sum = 0;

            for (i = 0; i < CLEARTYPE_SAMPLES; i++)
                sum += row[2 * x + i];
            bitmap[y * width + x] = (sum + CLEARTYPE_SAMPLES / 2) / CLEARTYPE_SAMPLES;
        }
    }
}
