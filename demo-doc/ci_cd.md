## ✅ Demo Ready!

You now have:
- OIDC login flow implemented with Keycloak
- Secrets encryption and retrieval managed by Vault
- IP-based regional access control



Next step: deploy to Kubernetes or integrate GitHub Actions for CI/CD automation.

---

## 🧩 Step 5: GPG and SOPS-Based Secrets Encryption

### 📦 Install Tools (macOS)

```bash
brew uninstall gnupg sops

brew install gnupg sops
```

### 🔐 Generate a GPG Key

#### Option 1: Interactive (terminal must be large enough)

```bash
gpg --full-generate-key
gpg --list-secret-keys --keyid-format LONG
```

#### Option 2: Non-Interactive (CI-friendly)

```bash
cat <<EOF > gpg-batch.conf
%no-protection
Key-Type: RSA
Key-Length: 3072
Subkey-Type: RSA
Subkey-Length: 3072
Name-Real: Xihai (cst8922 test)
Name-Email: renxihai@gmail.com
Expire-Date: 1y
%commit
EOF

gpg --batch --generate-key gpg-batch.conf
gpg --list-secret-keys --keyid-format LONG



---------
sec   rsa3072/6C05E464B71A4382 2025-07-21 [SCEAR] [expires: 2026-07-21]
      F065EED3811189037F3C632A6C05E464B71A4382
uid                 [ultimate] Xihai (cst8922 test) <renxihai@gmail.com>
ssb   rsa3072/17DB048CA8F39D48 2025-07-21 [SEA] [expires: 2026-07-21]
```



### 📤 Export Private Key for CI

```bash
gpg --export-secret-keys --armor YOUR_KEY_FP > private-key.asc
base64 -i private-key.asc -o private-key.base64

gpg --export-secret-keys --armor F065EED3811189037F3C632A6C05E464B71A4382 > private-key.asc
base64 -i private-key.asc -o private-key.base64
```

Replace `YOUR_KEY_FP` with your GPG key fingerprint.

### 🧪 Simulate CI Environment Setup

```bash
export GPG_PRIVATE_KEY_QA=$(cat private-key.base64)
export GPG_PASSPHRASE_QA="your-password"

# GPG config
export GPG_TTY=$(tty)
export GPG_EXECUTABLE=gpg
export SOPS_GPG_EXEC=gpg
export GPG_AGENT_INFO=
export GPG_OPTS="--pinentry-mode loopback"
export SOPS_DEBUG=true
export TERM=xterm-256color

mkdir -p ~/.gnupg
chmod 700 ~/.gnupg
echo "allow-loopback-pinentry" >> ~/.gnupg/gpg-agent.conf
echo "pinentry-mode loopback" >> ~/.gnupg/gpg.conf
gpgconf --kill gpg-agent

```

### 🔏 Encrypt `.env` File with SOPS

```env
PORT=3000
SECRET_KEY=super-secret
```

```bash
sops --input-type dotenv --output-type dotenv --encrypt --pgp YOUR_KEY_FP .env > .env.enc

sops --input-type dotenv --output-type dotenv --encrypt --pgp F065EED3811189037F3C632A6C05E464B71A4382 .env > .env.enc

```

### 🔓 Decrypt `.env.enc` File

```bash
sops --input-type dotenv --output-type dotenv --decrypt .env.enc > .env.decrypted
```

### ✅ Summary

- GPG keys can be created and used locally or in CI.
- SOPS supports field-level encryption with GPG.
- Key trust and loopback pinentry are required for non-interactive use.


```bash

docker pull xihairen/app-demo:latest
docker run --rm -p 3000:3000 xihairen/app-demo:latest

docker run --pull always --rm -p 3000:3000 xihairen/app-demo:latest
```