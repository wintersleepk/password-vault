# 🔐 CLI Password Vault

A secure command-line password manager written in **C** using **OpenSSL**, designed to help users safely store and manage passwords locally. Built for learning, security, and showing off some serious low-level skills.

---

## ✨ Features

- 🔐 User login and sign-up system
- 🔑 Passwords hashed with salted **SHA-256**
- 🧊 Vault entries encrypted using **AES-256-CBC**
- 🗃️ Vault stored per user in local encrypted file
- 🧽 Sensitive memory cleared with `OPENSSL_cleanse()`
- 🧵 CLI interface with interactive menus
- 🛡️ Password strength checker

---

## 🧠 Tech Stack

`C` • `OpenSSL` • `Linux` • `File I/O` • `Terminal UI`

---

## ⚙️ How to Build & Run

```bash
gcc -o vault main.c auth.c vault.c security.c  -lssl -lcrypto
./vault
