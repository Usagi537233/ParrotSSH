# ParrotSSH

**ParrotSSH** is a transparent SSH authentication proxy built with Go. Its core philosophy is simple: **If you don't repeat yourself, you don't get in.**

---

## 🛡️ The Defense Logic

In automated network attacks, scripts typically try passwords sequentially from a dictionary. **ParrotSSH** forcibly disrupts this linear approach:

* **The Script:** Inputs `pass1` -> Denied -> Tries `pass2` -> Denied. Even if `pass1` was correct, it fails because it wasn't **immediately repeated**.
* **The Human:** Inputs `pass` -> Receives `Permission denied` -> **Retries the exact same** `pass` -> Authentication successful, forwarded to the real backend.

---

## ✨ Key Features

* **Repetition Verification:** Mandates  consecutive identical password entries to unlock access.
* **Transparent Forwarding:** Automatically connects to the real SSH backend using the verified credentials upon success.
* **Static Fingerprinting:** Default Server Version disguised as `OpenSSH_9.6p1 Ubuntu-3ubuntu13`.
* **Credential Harvesting:** Use `-savefailinfo` to log attacker IPs, usernames, and their password dictionaries in real-time.
* **Ultra-Lightweight:** A single binary with zero external dependencies and minimal memory footprint.

---

## 🚀 Quick Start

### Run

```bash
# Listen on 2222, forward to local 22, require 2 identical password attempts
./parrotssh -listen :2222 -real 127.0.0.1:22 -attempts 2

```

### Flags

| Flag | Description | Default |
| --- | --- | --- |
| `-listen` | Listening address (e.g., `:2222`) | (Required) |
| `-real` | Real backend SSH address | (Required) |
| `-attempts` | Number of consecutive identical passwords required | `2` |
| `-keyfile` | Path to store the host key | `ssh_host_key` |
| `-savefailinfo` | File path to log failed attempts | (Disabled) |

---

## ⚠️ Limitations

* **No Public Key Support:** Public key auth is a single-step process and cannot fulfill the "repetition" logic.
* **IP Binding:** Verification state is tied to the client's remote IP address.

---

## 💡 Pro Tip

If you run the following command:

```bash
./parrotssh -listen :22 -real 127.0.0.1:22 -savefailinfo faillog

```

If you point -real back to your publicly accessible -listen address (e.g., -listen :22 -real 127.0.0.1:22), ParrotSSH acts as a high-efficiency trap. Since bots will never "repeat" their passwords, they will continuously feed their login attempts into your faillog. Because there is no real SSH backend and it just loops back to itself, it functions as a loopback recorder—giving you a real-time SSH password dictionary.

**Result:** You will automatically generate a real-time, high-quality **SSH Password Dictionary** based on actual global attack trends.


---
