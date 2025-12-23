# ParrotSSH

**ParrotSSH** is a transparent SSH authentication proxy built with Go. Its core philosophy is simple: **If you don't repeat yourself, you don't get in.**

---

## 🛡️ The Defense Logic

In automated network attacks, scripts typically try passwords sequentially from a dictionary. **ParrotSSH** forcibly disrupts this linear approach:

* **The Script:** Inputs `pass1` → Denied → Tries `pass2` → Denied. Even if `pass1` was correct, it fails because it wasn't **immediately repeated**.
* **The Human:** Inputs `pass` → Receives `Permission denied` → **Retries the exact same** `pass` → Authentication successful, forwarded to the real backend.

---

## ✨ Key Features

* **Repetition Verification:** Mandates consecutive identical password entries to unlock access.
* **Transparent Forwarding:** Automatically connects to the real SSH backend using the verified credentials upon success.
* **Static Fingerprinting:** Default Server Version disguised as `OpenSSH_9.6p1 Ubuntu-3ubuntu13`.
* **Credential Harvesting:** Use `-savefailinfo` to log attacker IPs, usernames, and their password dictionaries in real-time.
* **Ultra-Lightweight:** A single binary with zero external dependencies and minimal memory footprint.
* **Optional Port Knocking Gate:** Completely hide the SSH service unless a correct knock sequence is performed.

---

## 🚪 Port Knocking (Optional)

ParrotSSH supports **Port Knocking** as a pre-authentication access gate.

When enabled, the SSH service is **invisible** unless the client performs the correct TCP knock sequence.

### How It Works

1. The client connects to a predefined sequence of TCP ports in the correct order
2. After the final knock, SSH access is granted for a limited time window
3. Authorization is tracked per client IP and expires automatically
4. Any incorrect order or timeout resets progress immediately

Bots and scanners will never reach the SSH authentication stage without prior knowledge of the sequence.

### Enable Port Knocking

```bash
./parrotssh -listen :2222 -real 127.0.0.1:22 -attempts 2 -knock-seq 7000,8000,9000 -knock-open 30 -knock-timeout 10
````

### Knock Flags

| Flag             | Description                             | Default  |
| ---------------- | --------------------------------------- | -------- |
| `-knock-seq`     | Comma-separated TCP port knock sequence | Disabled |
| `-knock-open`    | Seconds SSH remains open after success  | `30`     |
| `-knock-timeout` | Maximum seconds between knock steps     | `10`     |

**Notes:**

* Each knock port is listened independently
* Knock state is tracked per client IP
* `127.0.0.1` / `::1` are always allowed
* If port knocking is not configured, ParrotSSH behaves exactly like the original version

---

## 🚀 Quick Start

### Run

```bash
./parrotssh -listen :2222 -real 127.0.0.1:22 -attempts 2
```

---

### Flags

| Flag             | Description                                        | Default        |
| ---------------- | -------------------------------------------------- | -------------- |
| `-listen`        | Listening address (e.g., `:2222`)                  | (Required)     |
| `-real`          | Real backend SSH address                           | (Required)     |
| `-attempts`      | Number of consecutive identical passwords required | `2`            |
| `-keyfile`       | Path to store the host key                         | `ssh_host_key` |
| `-savefailinfo`  | File path to log failed attempts                   | (Disabled)     |
| `-knock-seq`     | Port knocking sequence                             | (Disabled)     |
| `-knock-open`    | SSH open window after knock (seconds)              | `30`           |
| `-knock-timeout` | Knock sequence timeout (seconds)                   | `10`           |

---

## ⚠️ Limitations

* **No Public Key Support:** Public key authentication is a single-step process and cannot satisfy repetition-based verification.
* **IP Binding:** Verification and knock state are bound to the client’s remote IP address.
* **Not a Firewall Replacement:** Port knocking reduces exposure but does not replace proper network-level controls.

---

## 💡 Pro Tip: Loopback Trap Mode

```bash
./parrotssh -listen :22 -real 127.0.0.1:22 -savefailinfo faillog
```

If you point `-real` back to your publicly accessible `-listen` address, ParrotSSH acts as a **high-efficiency SSH trap**.

Since bots will never repeat passwords:

* They will never authenticate
* They will continuously feed password dictionaries
* No real SSH backend is ever reached

Because the proxy loops back to itself, it becomes a **loopback recorder**.

**Result:** You automatically generate a real-time, high-quality **SSH Password Dictionary** based on live global attack traffic.

Also adding port knocking on top of this setup further ensures that SSH remains invisible to generic scanners, dramatically reducing noise.
