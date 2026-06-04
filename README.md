# TextCord

A minimalist text-based communicator focused on simplicity, performance, and control.

---

## 📦 Version

**Current version:** Beta 1.0.0  
**Previous:** Alpha 1.0.0

---

## 📌 About

TextCord is a lightweight communication system operating entirely in text mode.

Instead of modern graphical interfaces, it uses an ASCII-based UI with minimal CSS (black & white theme).  
The goal is to provide a fast, distraction-free, and fully controlled messaging environment.

---

## 🚀 What's new in Beta 1.0.0

- 📁 File upload support up to 30MB  
- 🔐 Fixed login logs system  
- 🧾 Account registration system:
  - can be enabled/disabled during installation  
- 🧍 Device registration + fingerprinting:
  - anti-spam protection  
  - prevents mass account creation  
- 🌐 Unified frontend name: **TextCord**
  - selectable domain suffix:
    - .pl
    - .org
    - .com
    - .local  

---

## 🚀 Core features

- Text-based communication system  
- ASCII UI (no images, no heavy frontend)  
- Minimal CSS (black & white theme)  
- User management system (including admin actions)  
- Simple installation (`./install.sh`)  
- HTTPS-only (no HTTP support)  
- WebRTC-based direct messaging (non-group)  
- Stable backend (no critical errors)  

---

## 🧪 Development history

### Prototype phase

#### prototype-0.1
- Initial working version  
- Manual IP connection  
- No SSL / DNS support  
- UI issues  
- No notifications  

#### prototype-1.0
- Fixed installation process  
- DNS & SSL working  
- Stable communicator  
- Improved reliability  

#### prototype-2.0
- Group chat system  
- Fixed notifications  
- Fixed account creation  

#### prototype-2.1
- Installer bug fixed  
- NGINX configuration fixed  

---

### Alpha phase

#### Alpha 1.0.0
- HTTPS-only (HTTP removed)  
- Simplified installation via `./install.sh`  
- WebRTC direct messaging  
- HSTS enforced  
- Security improvements  
- Stability improvements  

---

### Beta phase

#### Beta 1.0.0
- File upload system (up to 30MB)  
- Login logs fix  
- Toggleable account registration during install  
- Device registration + fingerprinting anti-spam system  
- Protection against mass account creation  
- Unified frontend name: TextCord  
- Domain suffix selection (.pl / .org / .com / .local)  

---

## 🔧 Tech concept

- Text-first interface (ASCII UI)  
- Minimal frontend  
- Backend-heavy architecture  
- Performance over visuals  
- Secure-by-default (HTTPS + HSTS)  
- Anti-abuse device tracking  

---

## 🧠 Purpose

This project was built as an experimental system to:

- learn communication systems  
- improve backend architecture  
- work with DNS / SSL / networking  
- explore minimalist UI design  

---

## ⚠️ Notes

- still a minimalist project (no GUI)  
- not production-ready yet  
- group WebRTC is still under development  

---

## 🔮 Next update (planned)

In the next frontend update:

- 🌍 UI language selection (multi-language support)
  - PL / EN / DE and more  
- 🔊 sound system updates:
  - new notification sounds  
  - assigning sounds to specific chats  
  - customizable audio alerts  

---

## 📄 Status

🚧 Beta stage (1.0.0)  
✔️ Core system stable  
⚠️ Ongoing improvements  

---

## 🔧 Installation

```bash
git clone https://github.com/Michalsonix/textcord.git
cd textcord
chmod +x install.sh
./install.sh


## 📜 License

This project is licensed under the GNU General Public License (GPL) — either version 3 of the License, or (at your option) any later version.

Copyright (c) 2026 Boogeyman (TextCord)

You are free to:
- use this software
- modify it
- distribute it
- use it commercially

Under the condition that:
- any distributed version must also remain open-source under the same license (GPL)
- source code must be provided when distributing modified versions
- the original author must be credited

No warranty is provided. The software is provided "as is".
