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

3. Create Realm: `security-demo` (or import an existing realm). If importing, remember to update the credentials.

4. Create Clients:
   - **Client 1 (for app login)**:
     - Client ID: `demo-client`
     - Type: `confidential`
     - Redirect URI: `http://localhost:3000/callback`
     - Enable `Standard Flow` and `Direct Access Grant`
     - Add Client Scopes: `roles`, `region`
     - Add Audience: `vault`
   - **Client 2 (for Vault OIDC login)**:
     - Client ID: `vault`
     - Type: `confidential`
     - Redirect URI: `http://localhost:8250/oidc/callback`
     - Enable `Standard Flow` and `Direct Access Grant`
     - Add Client Scopes: `roles`, `region`
     - Add Audience: `vault`

5. Create roles in the `demo-client`, such as `admin` and `user`.

6. Use `Client scopes` to control token content:
   - Add a **roles** mapper:
     - Name: `roles`
     - Mapper Type: `User Realm Role`
     - Token Claim Name: `roles`
     - Claim JSON Type: `String Array`
     - ✅ Add to ID Token, Access Token, and UserInfo
   - Add a **region** mapper:
     - Name: `region`
     - Mapper Type: `User Attribute`
     - User Attribute: `region`
     - Token Claim Name: `region`
     - Claim JSON Type: `String`
     - ✅ Add to ID Token, Access Token, and UserInfo
  
