# TextCord

Minimalist text-based communicator focused on simplicity, performance, and control.

---

## 📦 Version

**Current version:** Alpha 1.0.0

---

## 📌 About

TextCord is a lightweight communication system operating entirely in text mode.

Instead of modern graphical interfaces, it uses an ASCII-based UI with minimal CSS (black & white theme).
The goal is to provide a fast, distraction-free, and fully controlled messaging environment.

---

## 🚀 Features

* Text-based communication system
* ASCII UI (no images, no heavy frontend)
* Minimal CSS (black & white theme)
* User management system (including admin actions)
* Simplified installation process (`./install.sh`)
* HTTPS-only (no HTTP support)
* WebRTC-based direct messaging (non-group)
* Stable backend (no critical errors)

---

## 🧪 Development history

### Prototype phase

#### prototype-0.1

* Initial working version
* Required manual IP connection
* No SSL / DNS support
* UI issues and missing features
* No notifications

#### prototype-1.0

* Fixed installation process
* DNS & SSL fully working
* Stable application (no critical bugs)
* Functional text communicator
* Improved system reliability

#### prototype-2.0

* Group chat system
* Fixed notifications
* Fixed account creation

#### prototype-2.1

* Fixed installer bug
* Fixed NGINX configuration

---

### Alpha phase

#### Alpha 1.0.0

* Removed HTTP entirely (HTTPS required)
* Simplified installation via `./install.sh`
* WebRTC-based direct messaging (non-group)
* Fixed NGINX + HSTS configuration (HSTS enforced)
* Improved security model
* Improved overall system stability

---

## ⚙️ Tech concept

* Text-first interface (ASCII instead of images)
* Minimal frontend (CSS only where necessary)
* Backend-focused architecture
* Performance and simplicity over visuals
* Secure-by-default approach (HTTPS + HSTS)

---

## 🧠 Purpose

This project was built as a learning and experimental system to:

* Understand communication systems
* Improve backend architecture
* Work with networking, DNS, and SSL certificates
* Explore minimal interface design

---

## ⚠️ Notes

* This is a minimalist project — modern UI features are intentionally excluded
* Not production-ready yet
* Some features (e.g. WebRTC for groups) are still in development

---

## 📄 Status

🚧 Alpha stage (1.0.0)
✔️ Core functionality working
⚠️ Further improvements required before beta

---

## 🔧 Installation

```bash
git clone https://github.com/Michalsonix/textcord.git
cd textcord
chmod +x install.sh
./install.sh
```

---

## 📜 License

(To be defined)
