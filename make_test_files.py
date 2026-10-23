#!/usr/bin/env python3
"""
SafeCheck harmless test kit.

Creates a folder "SafeCheck-TestKit" on your Desktop with FAKE files that only LOOK like
WhatsApp malware tricks. None of them contains any working code:
  - the .vbs/.js files contain only a comment line,
  - the "photo.jpg" only starts with the two letters "MZ" followed by plain text,
  - the ".lnk" inside the ZIP is plain text, not a real shortcut,
  - the ".apk" is a plain text file.
Double-clicking any of them does nothing harmful.

Then open SafeCheck > "Scan a Folder..." > choose the SafeCheck-TestKit folder.
When you're done, simply delete the SafeCheck-TestKit folder.
"""
import io
import os
import zipfile

NOTE = "SafeCheck harmless test file. It contains no code and does nothing."

desktop = os.path.join(os.path.expanduser("~"), "Desktop")
if not os.path.isdir(desktop):
    desktop = os.path.expanduser("~")
kit = os.path.join(desktop, "SafeCheck-TestKit")
os.makedirs(kit, exist_ok=True)


def write(name, data):
    path = os.path.join(kit, name)
    with open(path, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode("utf-8"))
    print("created:", path)


# 1) Double-extension "script" (comment only)
write("Bill_Payment.pdf.vbs", "' " + NOTE + "\r\n")
# 2) Scam-named APK (plain text)
write("RTO_E-Challan.apk", NOTE)
# 3) "Photo" whose first bytes look like a Windows program header (not runnable)
write("WhatsApp_Image_photo.jpg", b"MZ" + b"\r\n" + NOTE.encode())
# 4) Hidden right-to-left character in the name (harmless .txt)
write("report‮fdp.txt", NOTE)
# 5) ZIP hiding a fake "shortcut" whose text mentions powershell (not a real shortcut)
with zipfile.ZipFile(os.path.join(kit, "Wedding_Invitation.zip"), "w") as z:
    z.writestr("Wedding_Card.pdf.lnk", NOTE + " (test marker: powershell -w hidden)")
print("created:", os.path.join(kit, "Wedding_Invitation.zip"))
# 6) ZIP inside a ZIP hiding a fake script
inner = io.BytesIO()
with zipfile.ZipFile(inner, "w") as z:
    z.writestr("kyc_update.js", "// " + NOTE)
with zipfile.ZipFile(os.path.join(kit, "Bank_KYC_Documents.zip"), "w") as z:
    z.writestr("documents.zip", inner.getvalue())
    z.writestr("readme.txt", NOTE)
print("created:", os.path.join(kit, "Bank_KYC_Documents.zip"))
# 7) A normal file that should NOT be flagged
write("normal_notes.txt", "Just a normal text file. SafeCheck should not flag this one.")

print("\nDone. In SafeCheck click 'Scan a Folder...' and choose:\n  " + kit)
print("Expected: 6 High items, and normal_notes.txt NOT flagged.")
print("To clean up afterwards, just delete the SafeCheck-TestKit folder.")
