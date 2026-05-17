import os
import base64
from PIL import Image, ImageDraw

# Create directory
icon_dir = r"e:\Phishguard\phishguard\extension\icons"
os.makedirs(icon_dir, exist_ok=True)

# Generate a 48x48 dark shield icon
img = Image.new("RGBA", (48, 48), (0, 0, 0, 0))
draw = ImageDraw.Draw(img)

# Dark slate color matching the dashboard theme (#1e293b)
shield_color = (30, 41, 59, 255)
draw.polygon([(24, 4), (44, 12), (44, 28), (24, 44), (4, 28), (4, 12)], fill=shield_color)

# Save to disk
icon_path = os.path.join(icon_dir, "icon48.png")
img.save(icon_path)

# Print base64 string
with open(icon_path, "rb") as f:
    b64_string = base64.b64encode(f.read()).decode("utf-8")

print("\n--- BASE64 STRING ---")
print(b64_string)
