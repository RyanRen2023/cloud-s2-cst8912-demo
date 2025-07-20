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
   docker run --cap-add=IPC_LOCK -e VAULT_DEV_ROOT_TOKEN_ID=myroot -p 8200:8200 hashicorp/vault
   ```

2. Enable KV storage:
   ```bash
   export VAULT_ADDR=http://localhost:8200
   vault login myroot
   vault secrets enable -path=secret kv
   vault kv put secret/demo password=123456
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