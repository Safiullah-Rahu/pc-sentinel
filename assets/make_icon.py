"""Draws the PC Sentinel icon (glowing shield with a node network) -> sentinel.ico + sentinel-64.png + sentinel-256.png."""
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

OUT = Path(__file__).parent
S = 1024  # draw large, downsample for crisp edges


def shield(cx, cy, w, h):
    top = cy - h * 0.5
    pts = [(cx, top), (cx + w * 0.5, top + h * 0.14), (cx + w * 0.47, top + h * 0.52),
           (cx + w * 0.30, top + h * 0.80), (cx, top + h), (cx - w * 0.30, top + h * 0.80),
           (cx - w * 0.47, top + h * 0.52), (cx - w * 0.5, top + h * 0.14)]
    return pts


def draw():
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    # dark rounded tile
    tile = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    td = ImageDraw.Draw(tile)
    td.rounded_rectangle((40, 40, S - 40, S - 40), radius=210, fill=(7, 11, 22, 255), outline=(34, 211, 238, 90), width=10)
    img.alpha_composite(tile)

    cx, cy = S / 2, S / 2 + 10
    pts = shield(cx, cy, 600, 690)
    # glow layer
    glow = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow)
    gd.line(pts + [pts[0]], fill=(34, 211, 238, 255), width=46, joint="curve")
    glow = glow.filter(ImageFilter.GaussianBlur(28))
    img.alpha_composite(glow)
    # shield fill + crisp outline
    d = ImageDraw.Draw(img)
    d.polygon(pts, fill=(10, 26, 44, 255))
    d.line(pts + [pts[0]], fill=(103, 232, 249, 255), width=26, joint="curve")

    # node network inside the shield
    nodes = [(cx, cy - 150), (cx - 150, cy + 10), (cx + 150, cy + 10), (cx, cy + 170), (cx - 40, cy + 30)]
    links = [(0, 1), (0, 2), (1, 3), (2, 3), (1, 4), (2, 4), (4, 3), (0, 4)]
    net = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    nd = ImageDraw.Draw(net)
    for a, b in links:
        nd.line((nodes[a], nodes[b]), fill=(34, 211, 238, 200), width=14)
    for i, (x, y) in enumerate(nodes):
        r = 46 if i == 4 else 36
        col = (248, 113, 113, 255) if i == 3 else (240, 253, 255, 255)
        nd.ellipse((x - r, y - r, x + r, y + r), fill=col)
    nglow = net.filter(ImageFilter.GaussianBlur(18))
    img.alpha_composite(nglow)
    img.alpha_composite(net)
    return img


def main():
    big = draw()
    sizes = [16, 20, 24, 32, 40, 48, 64, 128, 256]
    big.resize((256, 256), Image.LANCZOS).save(OUT / "sentinel.ico", sizes=[(s, s) for s in sizes])
    big.resize((64, 64), Image.LANCZOS).save(OUT / "sentinel-64.png")
    big.resize((256, 256), Image.LANCZOS).save(OUT / "sentinel-256.png")
    print("icons written to", OUT)


if __name__ == "__main__":
    main()
