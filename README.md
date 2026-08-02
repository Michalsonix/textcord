# TextCord

A minimalist text-based communicator focused on simplicity, performance, and control.

---

## 📦 Version

**Current version:** 1.0.0 (Stable)
**Previous:** Beta 1.0.0

---

## 📌 About

TextCord is a lightweight communication system operating entirely in text mode.

Instead of modern graphical interfaces, it uses an ASCII-based UI with minimal CSS (black & white theme).
The goal is to provide a fast, distraction-free, and fully controlled messaging environment.

---

## 🚀 What's new in 1.0.0

* 🌍 UI language selection (multi-language support)

  * PL
  * EN
  * DE
  * More languages can be added

* 🔊 Custom audio alerts:

  * New notification sounds
  * Assigning sounds to specific chats
  * Customizable audio alerts

* 🔧 Fixed account creation issues

* 🛠 Fixed installer problems

* ⚡ TextCord Go Binary release:

  * Faster startup
  * Easier deployment
  * Improved performance

* 🚀 Moved from Beta stage to Stable version 1.0.0

---

## 🚀 Core features

* Text-based communication system
* ASCII UI (no images, no heavy frontend)
* Minimal CSS (black & white theme)
* User management system (including admin actions)
* Go Binary support
* Optional source installation
* HTTPS-only (no HTTP support)
* WebRTC-based direct messaging (non-group)
* Stable backend (no critical errors)

---

## 🧪 Development history

### Prototype phase

#### prototype-0.1

* Initial working version
* Manual IP connection
* No SSL / DNS support
* UI issues
* No notifications

#### prototype-1.0

* Fixed installation process
* DNS & SSL working
* Stable communicator
* Improved reliability

#### prototype-2.0

* Group chat system
* Fixed notifications
* Fixed account creation

#### prototype-2.1

* Installer bug fixed
* NGINX configuration fixed

---

### Alpha phase

#### Alpha 1.0.0

* HTTPS-only (HTTP removed)
* Simplified installation via `./install.sh`
* WebRTC direct messaging
* HSTS enforced
* Security improvements
* Stability improvements

---

### Beta phase

#### Beta 1.0.0

* File upload system (up to 30MB)
* Login logs fix
* Toggleable account registration during install
* Device registration + fingerprinting anti-spam system
* Protection against mass account creation
* Unified frontend name: TextCord
* Domain suffix selection (.pl / .org / .com / .local)

---

### Stable release

#### 1.0.0

* Multi-language support
* Custom audio alerts
* Fixed account creation system
* Fixed installer
* TextCord Go Binary release
* Stability improvements

---

## 🔧 Tech concept

* Text-first interface (ASCII UI)
* Minimal frontend
* Backend-heavy architecture
* Performance over visuals
* Secure-by-default (HTTPS + HSTS)
* Anti-abuse device tracking
* Native Go binary

---

## 🧠 Purpose

This project was built as an experimental system to:

* learn communication systems
* improve backend architecture
* work with DNS / SSL / networking
* explore minimalist UI design
* improve Go programming skills

---

## ⚠️ Notes

* still a minimalist project (no GUI)
* group WebRTC is still under development

---

## 🔮 Next update (planned)

Server-side terminal management system.

Planned features:

* 📟 Server command terminal
* 👤 Creating user accounts from server side
* 🚫 Blocking and unblocking accounts
* 🔐 Register system control
* ▶️ Enable / disable TextCord
* 🔄 Enable / disable autostart
* ⚙️ Additional server administration commands

---

## 📄 Status

✅ Stable release (1.0.0)
✔️ Core system stable
⚠️ Ongoing improvements

---

## 💻 Recommended Operating System

For the best compatibility and easiest installation process, **Debian** or **Ubuntu Server** is recommended.

Other Linux distributions may work, but they are not officially tested and may require additional configuration.

---

## 🔧 Installation

### Recommended installation (Go Binary)

```bash
sudo ./textcord-installer
```

---

### Build Binary Yourself

```bash
git clone https://github.com/Michalsonix/textcord.git
cd textcord
chmod +x build_binary.sh
./build_binary.sh
```

---

### Optional installation from source

```bash
git clone https://github.com/Michalsonix/textcord.git
cd textcord
chmod +x install.sh
./install.sh
```

---

## 📜 License

This project is licensed under the GNU General Public License (GPL) — either version 3 of the License, or (at your option) any later version.

Copyright (c) 2026 Boogeyman (TextCord)

You are free to:

* use this software
* modify it
* distribute it
* use it commercially

Under the condition that:

* any distributed version must also remain open-source under the same license (GPL)
* source code must be provided when distributing modified versions
* the original author must be credited

No warranty is provided. The software is provided "as is".
