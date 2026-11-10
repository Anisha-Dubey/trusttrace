import zipfile
import xml.etree.ElementTree as ET
import re
from pathlib import Path

pptx_path = Path("nototpushongithub/TRUSTRACE_Hackathon_Pitch_Redesign_v2.pptx")

with zipfile.ZipFile(pptx_path, "r") as z:
    theme_xml = z.read("ppt/theme/theme1.xml").decode("utf-8", errors="ignore")
    colors = re.findall(r'srgbClr val="([0-9A-Fa-f]{6})"', theme_xml)
    fonts = re.findall(r'typeface="([^"]+)"', theme_xml)
    print("Theme colors:", sorted(list(set(colors))))
    print("Theme fonts:", sorted(list(set(fonts))))

    # Extract thumbnail to inspect
    if "docProps/thumbnail.jpeg" in z.namelist():
        thumb_data = z.read("docProps/thumbnail.jpeg")
        Path("nototpushongithub/thumbnail.jpeg").write_bytes(thumb_data)
        print("Wrote nototpushongithub/thumbnail.jpeg")

    all_slide_colors = set()
    for i in range(1, 15):
        sname = f"ppt/slides/slide{i}.xml"
        if sname in z.namelist():
            sxml = z.read(sname).decode("utf-8", errors="ignore")
            scolors = re.findall(r'srgbClr val="([0-9A-Fa-f]{6})"', sxml)
            all_slide_colors.update(scolors)
            stexts = re.findall(r"<a:t>([^<]+)</a:t>", sxml)
            sfonts = re.findall(r'typeface="([^"]+)"', sxml)
            print(f"\n--- SLIDE {i} ---")
            print("Fonts:", set(sfonts))
            print("Slide Colors:", set(scolors))
            print("Text sample:\n" + "\n".join(f"  - {t}" for t in stexts[:10]))

    print("\nAll Slide Colors:", sorted(list(all_slide_colors)))
