# PhoneUnlock 🔐

PhoneUnlock is a Windows authentication project that allows you to approve Windows sign-in requests from your phone.

The project combines a custom **Windows Credential Provider** with a **mobile web interface**, communicating through a local network server.

> ⚠️ **Early-stage project / MVP**
>
> PhoneUnlock is currently a development project and should **not be considered a production-ready authentication system**.

## ✨ How it works

1. Windows displays the PhoneUnlock Credential Provider on the login screen.
2. A login request is created with a unique challenge.
3. The request is sent to the PhoneUnlock server.
4. The paired phone receives the request.
5. You tap **Allow** or **Deny** on the phone.
6. The Credential Provider receives the result.
7. If approved, Windows continues the authentication process using the local account credentials.

```text
┌─────────────────────┐
│   Windows Login     │
│                     │
│ PhoneUnlock Provider│
└──────────┬──────────┘
           │
           │ HTTPS
           ▼
┌─────────────────────┐
│  PhoneUnlock Server │
│   Node.js / Express │
└──────────┬──────────┘
           │
           │ WebSocket
           ▼
┌─────────────────────┐
│    Android Phone    │
│                     │
│  Allow / Deny       │
└─────────────────────┘
```

## 🧩 Components

### Windows Credential Provider

A native C++ Windows Credential Provider responsible for integrating PhoneUnlock into the Windows sign-in UI.

It handles:

* Windows login UI integration
* Login request creation
* Challenge generation
* Communication with the local PhoneUnlock server
* Approval verification
* Credential serialization
* Windows authentication handoff

### Server

The backend is built with:

* Node.js
* Express
* WebSocket
* HTTPS

The server manages:

* Device pairing
* Authentication requests
* Phone connections
* Approval / denial responses
* Request expiration
* Authentication proofs

### Mobile Web App

The phone interface is a web application that can be opened directly in a mobile browser.

It allows the paired device to:

* Receive login requests
* View the requesting device
* Approve requests
* Deny requests

## 🔗 Pairing

PhoneUnlock uses a pairing system between a Windows PC and a phone.

The pairing process uses:

* A temporary pairing code
* A unique pair ID
* A randomly generated pair secret

The pair secret is used to authenticate requests between the paired devices.

## 🔐 Security

The project currently uses several security mechanisms, including:

* HTTPS communication
* Random pairing codes
* Random pair IDs
* Random pair secrets
* Bearer authentication for protected API endpoints
* HMAC-SHA256 approval proofs
* Login request expiration
* Single-use authentication requests
* Constant-time secret comparison

However, this is **not yet a hardened authentication system**.

Before using something like this outside a trusted development environment, additional security work would be required, including stronger device identity, secure secret storage, rate limiting, better recovery handling, and a more robust trust model.

## 📁 Project Structure

```text
PhoneUnlock/
│
├── server/
│   ├── index.js
│   ├── mobile.html
│   └── pair.html
│
├── windows-client/
│   ├── test-client.ps1
│   └── pair-client.ps1
│
└── credential-provider/
    └── PhoneUnlockCredentialProvider/
        ├── PhoneUnlockProvider.h
        ├── PhoneUnlockProvider.cpp
        ├── PhoneUnlockCredential.h
        ├── PhoneUnlockCredential.cpp
        ├── helpers.h
        ├── helpers.cpp
        ├── dllmain.cpp
        ├── PhoneUnlockCredentialProvider.def
        ├── PhoneUnlockCredentialProvider.vcxproj
        └── PhoneUnlockCredentialProvider.vcxproj.filters
```

## 🛠️ Requirements

### Windows

* Windows 10/11
* Visual Studio with C++ development tools
* Windows SDK
* Git
* Node.js

### Phone

* Android or another modern mobile browser
* Phone and PC connected to the same local network

## 🚀 Development Setup

### 1. Clone the repository

```powershell
git clone <repository-url>
cd PhoneUnlock
```

### 2. Install server dependencies

```powershell
cd server
npm install
```

### 3. Start the server

```powershell
node index.js
```

The server runs on:

```text
https://localhost:3000
```

For a phone connected to the same LAN, use the PC's local IP address:

```text
https://<PC-IP>:3000/mobile
```

### 4. Build the Credential Provider

Open the Visual Studio project:

```text
credential-provider/PhoneUnlockCredentialProvider/PhoneUnlockCredentialProvider.vcxproj
```

Build the project in:

```text
Release
x64
```

The resulting DLL can then be registered on the development machine.

> ⚠️ Installing a Credential Provider modifies Windows authentication behavior. Always keep a working administrator account available while developing and testing it.

## 🧪 Current Status

PhoneUnlock is currently under active development.

### Working

* [x] Node.js server
* [x] HTTPS communication
* [x] Mobile web interface
* [x] WebSocket communication
* [x] PC ↔ phone pairing
* [x] Pair secrets
* [x] Authentication request expiration
* [x] Single-use requests
* [x] HMAC-SHA256 approval proofs
* [x] Windows Credential Provider
* [x] Credential serialization

### In Development

* [ ] Hardened authentication model
* [ ] Persistent device management
* [ ] Better error handling
* [ ] Production-grade secret storage
* [ ] More robust recovery / fallback authentication
* [ ] Installer
* [ ] Better mobile UI
* [ ] Additional Windows authentication scenarios

## 📜 License

This project is licensed under the **Apache License 2.0**.

Copyright © 2026 Vojtěch Holčík.

See the [LICENSE](LICENSE) file for the full license text.

## 👤 Author

Created by **cicitek / Official_cicitek**.

PhoneUnlock is a personal experimental project focused on Windows authentication, native C++, networking, and mobile approval workflows.
