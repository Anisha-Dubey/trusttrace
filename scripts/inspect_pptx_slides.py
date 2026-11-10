import zipfile
import xml.etree.ElementTree as ET
import re
from pathlib import Path

pptx_path = Path("nototpushongithub/TRUSTRACE_Hackathon_Pitch_Redesign_v2.pptx")

with zipfile.ZipFile(pptx_path, "r") as z:
    for i in range(1, 11):
        sxml = z.read(f"ppt/slides/slide{i}.xml").decode("utf-8", errors="ignore")
        print(f"\n==================== SLIDE {i} ====================")
        # Parse XML tree
        root = ET.fromstring(sxml)
        ns = {"a": "http://schemas.openxmlformats.org/drawingml/2006/main",
              "p": "http://schemas.openxmlformats.org/presentationml/2006/main"}

        # Check background fill
        bg = root.find(".//p:bg", ns)
        bg_color = "default"
        if bg is not None:
            clr = bg.find(".//a:srgbClr", ns)
            if clr is not None:
                bg_color = clr.get("val")
        print(f"Background: #{bg_color}")

        # Extract paragraphs
        for sp in root.findall(".//p:sp", ns):
            txBody = sp.find("p:txBody", ns)
            if txBody is not None:
                p_texts = []
                for p in txBody.findall("a:p", ns):
                    runs = []
                    for r in p.findall("a:r", ns):
                        t = r.find("a:t", ns)
                        if t is not None and t.text:
                            runs.append(t.text)
                    if runs:
                        p_texts.append("".join(runs))
                if p_texts:
                    full_p = " \n ".join(p_texts)
                    # Get shape fill if any
                    spPr = sp.find("p:spPr", ns)
                    fill = "none"
                    if spPr is not None:
                        sclr = spPr.find(".//a:srgbClr", ns)
                        if sclr is not None:
                            fill = f"#{sclr.get('val')}"
                    print(f"  [Shape fill: {fill}]: {full_p}")
