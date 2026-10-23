from PIL import Image, ImageDraw

SIZE = 256
img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
d = ImageDraw.Draw(img)

# вертикальный градиент (синий Win11)
top = (0x2E, 0x9B, 0xFF)
bot = (0x00, 0x67, 0xC0)
for y in range(SIZE):
    t = y / (SIZE - 1)
    r = int(top[0] + (bot[0] - top[0]) * t)
    g = int(top[1] + (bot[1] - top[1]) * t)
    b = int(top[2] + (bot[2] - top[2]) * t)
    d.line([(0, y), (SIZE, y)], fill=(r, g, b, 255))

# скруглённые углы
mask = Image.new("L", (SIZE, SIZE), 0)
ImageDraw.Draw(mask).rounded_rectangle([0, 0, SIZE - 1, SIZE - 1], radius=56, fill=255)
img.putalpha(mask)

d = ImageDraw.Draw(img)

# белая галочка + «пинг»-точка
pts = [(62, 138), (110, 186), (198, 88)]
d.line(pts, fill=(255, 255, 255, 255), width=36, joint="curve")
for (x, y) in pts:
    d.ellipse([x - 18, y - 18, x + 18, y + 18], fill=(255, 255, 255, 255))
# точка «пинг» справа вверху
d.ellipse([186, 46, 214, 74], fill=(255, 255, 255, 255))
d.arc([166, 26, 234, 94], start=20, end=110, fill=(255, 255, 255, 255), width=8)

img.save("app.ico", format="ICO", sizes=[(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)])
print("app.ico written")
