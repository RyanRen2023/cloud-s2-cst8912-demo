# Security Demo App

This is a secure demonstration application using Keycloak for identity authentication.

## Environment Variable Configuration

### 1. Copy Environment Variable Template

```bash
cp .env.example .env
```

### 2. Configure Environment Variables

Edit the `.env` file and set the following configurations:

#### Server Configuration
- `PORT`: Application port (default: 3000)
- `NODE_ENV`: Runtime environment (development/production)

#### Keycloak Configuration
- `KEYCLOAK_URL`: Keycloak server address
- `KEYCLOAK_REALM`: Keycloak realm name
- `APP_CLIENT_ID`: Client ID
- `APP_CLIENT_SECRET`: Client secret

#### Application URL
- `APP_BASE_URL`: Application base URL
- `APP_CALLBACK_URL`: Authentication callback URL

#### Vault Configuration
- `VAULT_URL`: HashiCorp Vault server address
- `VAULT_TOKEN`: Vault access token

#### Session Configuration
- `SESSION_SECRET`: Session secret key
- `SESSION_MAX_AGE`: Session maximum lifetime (milliseconds)

#### Security Configuration
- `ALLOWED_ROLES`: Allowed roles (comma-separated)

## Running the Application

```bash
npm install
npm start
```

## Test Users

- `adminuser` / `password` - Administrator role
- `normaluser` / `password` - User role
- `otheruser` / `password` - No role

## Feature Pages

- `/` - Home page
- `/admin` - Administrator page (requires admin role)
- `/user` - User page (requires user or admin role)
- `/secrets` - System secrets page (requires admin role)
- `/logout` - Logout

## Security Features

- OpenID Connect authentication
- Role-based access control
- Zero trust security model
- Session management
- Vault integration 