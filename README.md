# Cloud-Agnostic Encryption Demo Development Guide

This guide walks you through implementing the code components of the demo, including identity authentication, encryption, and region-based access control.

---

## 🧩 Step 1: Start Identity Server (Keycloak)

1. Start Keycloak container using Docker:
   ```bash
   docker run -d \
  -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:latest \
  start-dev
   ```

2. Open http://localhost:8080 to access the admin console, login credentials are both `admin`.

3. Create Realm: `security-demo` or import realm (don't foget to user the new credential)

4. Create Client:
   - Name: `demo-client`
   - Type: `confidential`
   - Redirect URI: `http://localhost:3000/callback`
   - Enable `Standard Flow` and `Direct Access Grant`

5. creating roles in client `demo-client` and control client token content using `Client scopes`
---


## 🧩 Step 2: Configure Vault to Manage Encrypted Secrets

1. Start Vault using Docker:
   ```bash
   docker run -d --cap-add=IPC_LOCK -e VAULT_DEV_ROOT_TOKEN_ID=myroot -p 8200:8200 hashicorp/vault
   ```

2. Enable KV storage:
   ```bash
   export VAULT_ADDR=http://localhost:8200
   vault login myroot
   vault secrets enable -path=secret kv
   vault kv put secret/demo password=123456


3. authentication with oidc
vault auth enable oidc
vault auth enable -path=keycloak oidc


  vault write auth/oidc/config \
  oidc_discovery_url="http://192.168.12.6:8080/realms/security-demo" \
  oidc_client_id="vault" \
  oidc_client_secret="3VHHw4BlZscO6ba6qkgdpLEnZoW5TkVh" \
  default_role="default"


  vault write auth/oidc/role/admin \
    bound_audiences="vault" \
    allowed_redirect_uris="http://192.168.12.6:3000/callback" \
    user_claim="preferred_username" \
    role_type="oidc" \
    groups_claim="roles" \
    policies="admin-policy"
   ```


---

Vault directory design
```
secret/
├── data/
│   ├── users/
│   │   ├── adminuser        # password, apiKey
│   │   ├── normaluser       # password, apiKey
│   ├── config               # system-wide config: smtpHost, smtpPass
│   └── feature_flags        # flags like "demoBanner", "maintenanceMode"


```

```bash

vault kv put secret/users/adminuser password=admin123 apiKey=admin-api-key
vault kv put secret/users/normaluser password=user123 apiKey=user-api-key

vault kv put secret/config smtpHost=smtp.example.com smtpPass=smtp1234
vault kv put secret/feature_flags demoBanner=true maintenanceMode=false


```


3. Access Vault in Node.js:
   ```bash
   npm install node-vault
   ```

   ```js
   import vault from 'node-vault';
   const client = vault({ endpoint: 'http://localhost:8200', token: 'myroot' });
   const secret = await client.read('secret/demo');
   console.log(secret.data.password);
   ```

---

## 🧩 Step 3: Implement User Login Flow (Node.js Example)


```bash
   cd app

   npm run dev

```

1. Install dependencies:
   ```bash
   npm install express passport openid-client express-session
   ```

2. Initialize OIDC client and configure Passport strategy:

   ```js
   // app.js
   import express from 'express';
   import session from 'express-session';
   import { Issuer, Strategy } from 'openid-client';
   import passport from 'passport';

   const app = express();
   app.use(session({ secret: 'demo', resave: false, saveUninitialized: true }));
   app.use(passport.initialize());
   app.use(passport.session());

   const keycloakIssuer = await Issuer.discover('http://localhost:8080/realms/security-demo');
   const client = new keycloakIssuer.Client({
     client_id: 'demo-client',
     client_secret: 'your client secret',
     redirect_uris: ['http://localhost:3000/callback'],
     response_types: ['code'],
   });

   passport.use('oidc', new Strategy({ client }, (tokenSet, userinfo, done) => {
     return done(null, userinfo);
   }));

   passport.serializeUser((user, done) => done(null, user));
   passport.deserializeUser((obj, done) => done(null, obj));

   app.get('/login', passport.authenticate('oidc'));
   app.get('/callback', passport.authenticate('oidc', {
     successRedirect: '/',
     failureRedirect: '/error',
   }));

   app.get('/', (req, res) => res.send(`Hello ${req.user?.preferred_username || 'Guest'}`));

   app.listen(3000, () => console.log('Server started at http://localhost:3000'));
   ```

---

## 🧩 Step 3: Configure Vault to Manage Encrypted Secrets

1. Start Vault using Docker:
   ```bash
   docker run -d --cap-add=IPC_LOCK -e VAULT_DEV_ROOT_TOKEN_ID=myroot -p 8200:8200 hashicorp/vault
   ```

2. Enable KV storage:
   ```bash
   export VAULT_ADDR=http://localhost:8200
   vault login myroot
   vault secrets enable -path=secret kv
   vault kv put secret/demo password=123456

   # windows

   $env:VAULT_ADDR = "http://localhost:8200"

   ```

3. Access Vault in Node.js:
   ```bash
   npm install node-vault
   ```

   ```js
   import vault from 'node-vault';
   const client = vault({ endpoint: 'http://localhost:8200', token: 'myroot' });
   const secret = await client.read('secret/demo');
   console.log(secret.data.password);
   ```


## 🧩 Step 4: Implement Region-Based Access Control (Example: Restrict Non-Canada IPs)

1. Use `express-ip` to get client IP:
   ```bash
   npm install express-ip
   ```

2. Add middleware to check region:
   ```js
   import ip from 'express-ip';

   app.use(ip().getIpInfoMiddleware);
   app.use((req, res, next) => {
     const country = req.ipInfo?.country;
     if (country !== 'CA') {
       return res.status(403).send('Access restricted to Canada only');
     }
     next();
   });
   ```

---

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
