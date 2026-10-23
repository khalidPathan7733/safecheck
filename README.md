# SafeCheck Desktop v1.1.0 (Windows)

Read-only malware + "bridge" (remote access) checker. UI English me hai.
**Ye tool kabhi kuch delete, move, quarantine ya change nahi karta.** Har finding ke saath
"Why this matters" aur "How to remove it (manual steps)" dikhata hai, removal user khud karta hai.

## Kya-kya check karta hai

| Section | Kya dhoondhta hai |
|---|---|
| Files | Downloads, Desktop, WhatsApp Desktop folder: `.vbs/.js/.hta/.scr`, `photo.jpg.exe` jaisi double extension, hidden RTL character, document ke naam me chhupa program (MZ header), ZIP ke andar `.lnk`/script (nested ZIP bhi), password-protected ZIP, scam-naam wali APK (challan, wedding, KYC...), unsigned `.exe/.msi`, kahan se download hui (WhatsApp Web ya kahin aur) |
| Startup | Run/RunOnce registry, Startup folder, Winlogon Shell/Userinit hijack |
| Scheduled Tasks / Services | Hidden PowerShell, `-enc`, wscript/mshta, Temp/Downloads se chalne wale unsigned programs |
| Running Programs | wscript/cscript/mshta, fake `svchost.exe` (galat folder), look-alike naam (`scvhost.exe`), Temp/AppData ke unsigned programs |
| **Remote Access (Bridge)** | AnyDesk, UltraViewer, TeamViewer, RustDesk, VNC, ScreenConnect, NetSupport, known RATs: running hai ya nahi, **abhi internet se connected hai ya nahi**, recently installed, AnyDesk/TeamViewer ke **past incoming session logs**, Remote Desktop ON/active |
| Network | Suspicious program ke live connections, listening ports, proxy / PAC script, hosts file me bank/Google/antivirus redirect |
| Windows Protection | Defender real-time, definitions age, Tamper Protection, firewall, Defender ki past/active detections |
| WhatsApp | Linked Devices + Two-step verification ka manual checklist (PC se ye dikhta nahi) |

Buttons: Open File Location, Copy SHA-256, Look Up Hash Online (sirf hash, file upload nahi),
Scan File with Microsoft Defender (`-DisableRemediation` ke saath, koi action nahi), Export Report (HTML/JSON).

## .exe kaise banayein

### Option A: Apne Windows PC par (5 minute)
1. Python 3.12 (64-bit) install karo, aur install ke time **"Add python.exe to PATH"** tick karo.
2. Is folder ko kisi bhi jagah rakho, jaise `C:\safecheck`.
3. `build.bat` par double-click karo.
4. Ready exe yahan milegi: `dist\SafeCheckDesktop.exe`

> ⚠️ `build.bat` sab kuch `.venv` folder ke andar install karta hai. Isse aapke system Python ya doosre projects par koi asar nahi padta.

### Option B: GitHub Actions (Windows PC ki zaroorat nahi)
1. Ek naya **private** GitHub repo banao aur ye saari files push karo (`.github/workflows/` folder bhi).
2. Repo me **Actions** tab kholo, "Build SafeCheck Desktop" select karo aur **Run workflow** dabao.
3. 2-3 minute baad run kholo. **Artifacts** section me `SafeCheckDesktop.zip` hoga, uske andar exe milegi.

### Bina build ke test (Python se seedha)
```bat
python -m pip install psutil
python safecheck.py                          :: GUI
python safecheck.py --cli --folder C:\Users\you\Downloads
python safecheck.py --cli --file "C:\path\suspicious.zip" --html report.html
```

## Run karna
- Exe par right-click karo aur **"Run as administrator"** chuno. Admin ke bina services, sabhi processes aur sabhi connections poore nahi dikhte. App me "Restart as Administrator" button bhi hai.
- **Run Full Check** se poora scan hota hai. **Scan a Folder** / **Check a File** se sirf ek folder ya ek file check hoti hai.

## Zaroori warnings
- ⚠️ **Unsigned exe:** Pehli baar chalane par Windows SmartScreen "Windows protected your PC" dikhayega (More info > Run anyway). Kuch antivirus PyInstaller one-file exe par galti se false-positive bhi de sakte hain. Public release se pehle **code-signing certificate** (OV/EV) se sign karna zaroori hai, warna log security tool par hi shak karenge.
- ⚠️ **Defender ka apna action:** SafeCheck khud kuch nahi hatata. Lekin agar Microsoft Defender real-time protection on hai aur SafeCheck koi asli malware file padhta hai (hash ya ZIP check ke liye), to Defender apni taraf se use quarantine kar sakta hai. Ye Defender ka action hai, SafeCheck ka nahi.
- ⚠️ **Server par mat chalao:** Ye desktop tool hai. Isse apne production VPS (CloudPanel) par mat chalana.
- "No known red flags" ka matlab **"100% safe" nahi** hai. Ye rule-based checker hai, full antivirus nahi.
- Removal steps me diye `schtasks`, `sc config` aur `regedit` wale steps **sirf flagged entry** ke liye hain. Galat entry change karne se Windows kharab ho sakta hai.

## Tested
- Linux par file-rules test kiye gaye: double extension, RTL, disguised MZ, APK lure, ZIP > LNK, nested ZIP > VBS, corrupt ZIP. Saaf files (txt, clean zip) flag nahi hui. GUI bhi render karke check kiya gaya.
- Windows-specific hisse **abhi Windows par test nahi hue:** registry, PowerShell queries (tasks/services/Defender/signatures), MpCmdRun aur Mark-of-the-Web. Pehli baar ek Windows PC par chala kar results check kar lena.

## Changelog
- **1.0.1**: "path should be string ... not dict" crash fix kiya (Startup aur Running Programs checks ab poore chalte hain). 32-bit build par System32 redirect fix kiya. Microsoft ke built-in scheduled tasks ab sirf High red-flag par hi dikhte hain. Scan errors ab ek "Check" finding me poore dikhte hain. `build.bat` 32-bit Python par warning deta hai.
- **1.1.0**: "Show Demo Results" button add kiya. High-risk mile toh red alert banner aur popup aata hai, aur live bridge (AnyDesk/RDP connected) par "Wi-Fi band karo" warning dikhti hai. `make_test_files.py` harmless test kit add kiya. CLI me `--demo` flag add kiya.

## Detection kaise dikhta hai, test karo
1. **Demo:** app me **Show Demo Results** dabao. Sample bridge aur malware results `[DEMO]` tag ke saath dikhenge. PC par kuch scan ya change nahi hota.
2. **Asli file detection (harmless):** `python make_test_files.py` chalao. Desktop par `SafeCheck-TestKit` folder banega. Phir SafeCheck me **Scan a Folder...** se wo folder chuno. Expected result: 6 High items. Test ke baad folder delete kar do.
3. **Asli bridge detection:** Windows ka built-in **Quick Assist** app kholo (Start > "Quick Assist"), phir **Run Full Check** chalao. Wo "Remote access running: Microsoft Quick Assist" ki tarah dikhega. Test ke baad Quick Assist band kar dena.
